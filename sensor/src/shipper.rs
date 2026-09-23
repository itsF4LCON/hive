use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::event::{now_secs, Event};
use crate::stats::Stats;

/// Recent events waiting to be shown in the live feed. Everything is counted in `Stats` on arrival;
/// this queue only holds candidates for the feed, so it can stay small.
const MAX_QUEUED: usize = 50;
/// Feed events sent per flush. With one flush a minute this keeps the Worker at roughly
/// 1 snapshot + 10 inserts + 10 pruned rows per minute, whatever the attack volume.
const FEED_PER_FLUSH: usize = 10;
const FLUSH_EVERY: Duration = Duration::from_secs(60);
/// Stay well under the Worker's 256 KB body limit.
const MAX_BODY_BYTES: usize = 128 * 1024;

/// Counts every event, then ships a stats snapshot plus the newest events to the Worker in one
/// signed request per minute.
pub struct Shipper {
    stats: Mutex<Stats>,
    stats_path: PathBuf,
    queue: Mutex<VecDeque<Event>>,
    dirty: AtomicBool,
}

enum SendError {
    /// Network trouble or a 5xx/429: keep the data and try again next minute.
    Retry(String),
    /// The Worker rejected the request itself (bad secret, clock, payload): retrying can't help.
    Reject(String),
}

impl Shipper {
    pub fn new(stats_path: PathBuf) -> Self {
        Shipper {
            stats: Mutex::new(Stats::load(&stats_path)),
            stats_path,
            queue: Mutex::new(VecDeque::new()),
            // Send a snapshot on the first tick even if nothing new arrives.
            dirty: AtomicBool::new(true),
        }
    }

    pub fn save(&self) {
        if let Err(e) = self.stats.lock().unwrap().save(&self.stats_path) {
            eprintln!("stats: could not save {}: {e}", self.stats_path.display());
        }
    }

    pub fn push(&self, e: Event) {
        self.stats.lock().unwrap().record(&e);
        let mut q = self.queue.lock().unwrap();
        if q.len() >= MAX_QUEUED {
            q.pop_front();
        }
        q.push_back(e);
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// The newest events for the feed, oldest first so the Worker inserts them in time order.
    fn take_feed(&self) -> Vec<Event> {
        let mut q = self.queue.lock().unwrap();
        let skip = q.len().saturating_sub(FEED_PER_FLUSH);
        q.drain(..).skip(skip).collect()
    }

    fn requeue(&self, events: Vec<Event>) {
        let mut q = self.queue.lock().unwrap();
        for e in events.into_iter().rev() {
            q.push_front(e);
        }
        while q.len() > MAX_QUEUED {
            q.pop_front();
        }
    }

    fn body(&self, events: &[Event]) -> Vec<u8> {
        let now = now_secs();
        let snapshot = self.stats.lock().unwrap().snapshot(now);
        let mut events = events;
        loop {
            let body = serde_json::to_vec(&serde_json::json!({
                "sent_at": now,
                "events": events,
                "stats": snapshot,
            }))
            .expect("events serialize");
            // Each event is capped at a few hundred bytes, so this only trims in odd cases.
            if body.len() <= MAX_BODY_BYTES || events.is_empty() {
                return body;
            }
            events = &events[1..];
        }
    }

    pub async fn run(&self, ingest_url: String, secret: String) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("http client");
        let mut tick = tokio::time::interval(FLUSH_EVERY);
        loop {
            tick.tick().await;
            if !self.dirty.swap(false, Ordering::Relaxed) {
                continue;
            }
            self.save();

            let feed = self.take_feed();
            let body = self.body(&feed);
            match send(&client, &ingest_url, &secret, body).await {
                Ok(()) => {}
                Err(SendError::Retry(e)) => {
                    eprintln!("shipper: {e}; retrying next minute");
                    self.requeue(feed);
                    self.dirty.store(true, Ordering::Relaxed);
                }
                Err(SendError::Reject(e)) => {
                    eprintln!("shipper: ingest rejected the batch ({e}); dropping it. Check HIVE_SECRET and the clock.");
                }
            }
        }
    }
}

pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

async fn send(client: &reqwest::Client, url: &str, secret: &str, body: Vec<u8>) -> Result<(), SendError> {
    let res = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Hive-Signature", sign(secret, &body))
        .body(body)
        .send()
        .await
        .map_err(|e| SendError::Retry(e.to_string()))?;
    let status = res.status();
    if status.is_success() {
        Ok(())
    } else if status.is_server_error() || status.as_u16() == 429 {
        Err(SendError::Retry(format!("ingest returned {status}")))
    } else {
        Err(SendError::Reject(format!("ingest returned {status}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::clip;
    use crate::geo::Location;

    fn shipper() -> Shipper {
        Shipper::new(std::env::temp_dir().join(format!("hive-test-missing-{}.json", std::process::id())))
    }

    fn http_event(i: usize) -> Event {
        let mut e = Event::new("http", "198.51.100.1".parse().unwrap(), Location::default());
        e.method = Some("GET".into());
        e.path = clip(&format!("/{i}/{}", "\"<>".repeat(200)), 256);
        e.ua = clip(&"\"\\".repeat(200), 256);
        e
    }

    #[test]
    fn signature_matches_openssl_hmac() {
        // printf 'hello' | openssl dgst -sha256 -hmac key
        assert_eq!(sign("key", b"hello"), "9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b");
    }

    #[test]
    fn counts_everything_but_only_ships_the_newest_few() {
        let s = shipper();
        for i in 0..500 {
            s.push(http_event(i));
        }
        assert_eq!(s.stats.lock().unwrap().snapshot(now_secs()).total_24h, 500);
        assert_eq!(s.queue.lock().unwrap().len(), MAX_QUEUED);
        let feed = s.take_feed();
        assert_eq!(feed.len(), FEED_PER_FLUSH);
        assert!(feed.last().unwrap().path.as_deref().unwrap().starts_with("/499/"), "newest last");
        assert!(s.queue.lock().unwrap().is_empty());
    }

    #[test]
    fn worst_case_body_fits_the_worker_limit() {
        let s = shipper();
        for i in 0..MAX_QUEUED {
            s.push(http_event(i));
        }
        let feed = s.take_feed();
        let body = s.body(&feed);
        assert!(body.len() <= MAX_BODY_BYTES, "{} bytes", body.len());
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["events"].as_array().unwrap().len(), FEED_PER_FLUSH);
        assert_eq!(parsed["stats"]["total_24h"], MAX_QUEUED as u64);
    }

    #[test]
    fn requeue_keeps_the_queue_bounded() {
        let s = shipper();
        for i in 0..MAX_QUEUED {
            s.push(http_event(i));
        }
        s.requeue((0..20).map(http_event).collect());
        assert_eq!(s.queue.lock().unwrap().len(), MAX_QUEUED);
    }
}

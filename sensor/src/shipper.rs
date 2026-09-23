use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use crate::event::{now_secs, Event};

const MAX_QUEUED: usize = 10_000;
const MAX_BATCH: usize = 500;
const FLUSH_EVERY: Duration = Duration::from_secs(10);

/// Buffers events and ships them to the Worker in signed batches.
/// The queue is bounded and drops the oldest events when full, so a flood can't exhaust memory.
pub struct Shipper {
    queue: Mutex<VecDeque<Event>>,
    dropped: Mutex<u64>,
}

impl Shipper {
    pub fn new() -> Self {
        Shipper { queue: Mutex::new(VecDeque::new()), dropped: Mutex::new(0) }
    }

    pub fn push(&self, e: Event) {
        let mut q = self.queue.lock().unwrap();
        if q.len() >= MAX_QUEUED {
            q.pop_front();
            *self.dropped.lock().unwrap() += 1;
        }
        q.push_back(e);
    }

    fn take_batch(&self) -> Vec<Event> {
        let mut q = self.queue.lock().unwrap();
        let n = q.len().min(MAX_BATCH);
        q.drain(..n).collect()
    }

    /// Put a failed batch back at the front, still respecting the cap.
    fn requeue(&self, batch: Vec<Event>) {
        let mut q = self.queue.lock().unwrap();
        for e in batch.into_iter().rev() {
            q.push_front(e);
        }
        while q.len() > MAX_QUEUED {
            q.pop_front();
            *self.dropped.lock().unwrap() += 1;
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
            loop {
                let batch = self.take_batch();
                if batch.is_empty() {
                    break;
                }
                let n = batch.len();
                match send(&client, &ingest_url, &secret, &batch).await {
                    Ok(()) => {
                        if n < MAX_BATCH {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("shipper: {e}; will retry {n} events");
                        self.requeue(batch);
                        break;
                    }
                }
            }
            let dropped = std::mem::take(&mut *self.dropped.lock().unwrap());
            if dropped > 0 {
                eprintln!("shipper: queue full, dropped {dropped} oldest events");
            }
        }
    }
}

pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

async fn send(client: &reqwest::Client, url: &str, secret: &str, events: &[Event]) -> Result<(), String> {
    let body = serde_json::to_vec(&serde_json::json!({ "sent_at": now_secs(), "events": events }))
        .map_err(|e| e.to_string())?;
    let res = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Hive-Signature", sign(secret, &body))
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("ingest returned {}", res.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::Location;

    fn ev() -> Event {
        Event::new("ssh", "198.51.100.1".parse().unwrap(), Location::default())
    }

    #[test]
    fn signature_matches_openssl_hmac() {
        // printf 'hello' | openssl dgst -sha256 -hmac key
        assert_eq!(sign("key", b"hello"), "9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b");
    }

    #[test]
    fn queue_is_bounded_and_drops_oldest() {
        let s = Shipper::new();
        for _ in 0..MAX_QUEUED + 5 {
            s.push(ev());
        }
        assert_eq!(s.queue.lock().unwrap().len(), MAX_QUEUED);
        assert_eq!(*s.dropped.lock().unwrap(), 5);
        let b = s.take_batch();
        assert_eq!(b.len(), MAX_BATCH);
        s.requeue(b);
        assert_eq!(s.queue.lock().unwrap().len(), MAX_QUEUED);
    }
}

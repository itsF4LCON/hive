use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::event::Event;

const HOUR: i64 = 3600;
const KEEP_HOURS: i64 = 7 * 24;
const MAP_CAP: usize = 300;
const SOURCE_CAP: usize = 5000;
const TOP_N: usize = 5;
const MAX_POINTS: usize = 500;

#[derive(Serialize, Deserialize, Default)]
struct Bucket {
    total: u64,
    services: HashMap<String, u64>,
    usernames: HashMap<String, u64>,
    passwords: HashMap<String, u64>,
    paths: HashMap<String, u64>,
    countries: HashMap<String, u64>,
    user_agents: HashMap<String, u64>,
    points: HashMap<String, u64>,
    sources: HashSet<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Stats {
    buckets: BTreeMap<i64, Bucket>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Top {
    pub k: String,
    pub n: u64,
}

#[derive(Serialize, Debug)]
pub struct Point {
    pub lat: f64,
    pub lon: f64,
    pub n: u64,
}

#[derive(Serialize, Debug)]
pub struct Snapshot {
    pub generated_at: f64,
    pub total_24h: u64,
    pub total_7d: u64,
    pub unique_sources_24h: u64,
    pub by_service_24h: Vec<Top>,
    pub top_usernames: Vec<Top>,
    pub top_passwords: Vec<Top>,
    pub top_paths: Vec<Top>,
    pub top_countries: Vec<Top>,
    pub top_user_agents: Vec<Top>,
    pub points_24h: Vec<Point>,
}

fn bump(map: &mut HashMap<String, u64>, key: Option<&str>) {
    let Some(key) = key else { return };
    if let Some(n) = map.get_mut(key) {
        *n += 1;
    } else if map.len() < MAP_CAP {
        map.insert(key.to_owned(), 1);
    }
}

fn merge<'a>(maps: impl Iterator<Item = &'a HashMap<String, u64>>) -> HashMap<&'a str, u64> {
    let mut out: HashMap<&str, u64> = HashMap::new();
    for m in maps {
        for (k, n) in m {
            *out.entry(k.as_str()).or_insert(0) += n;
        }
    }
    out
}

fn top(merged: HashMap<&str, u64>, n: usize) -> Vec<Top> {
    let mut v: Vec<Top> = merged.into_iter().map(|(k, n)| Top { k: k.to_owned(), n }).collect();
    v.sort_by(|a, b| b.n.cmp(&a.n).then_with(|| a.k.cmp(&b.k)));
    v.truncate(n);
    v
}

impl Stats {
    pub fn record(&mut self, e: &Event) {
        let hour = (e.ts as i64).div_euclid(HOUR) * HOUR;
        let b = self.buckets.entry(hour).or_default();
        b.total += 1;
        bump(&mut b.services, Some(e.service));
        bump(&mut b.usernames, e.username.as_deref());
        bump(&mut b.passwords, e.password.as_deref());
        bump(&mut b.paths, e.path.as_deref().filter(|p| *p != "/"));
        bump(&mut b.countries, e.country.as_deref());
        bump(&mut b.user_agents, e.ua.as_deref());
        if let (Some(lat), Some(lon)) = (e.lat, e.lon) {
            bump(&mut b.points, Some(&format!("{lat:.1},{lon:.1}")));
        }
        if b.sources.len() < SOURCE_CAP {
            b.sources.insert(e.ip.clone());
        }
        self.prune(hour);
    }

    fn prune(&mut self, current_hour: i64) {
        let oldest = current_hour - (KEEP_HOURS - 1) * HOUR;
        self.buckets = self.buckets.split_off(&oldest);
    }

    pub fn snapshot(&self, now: f64) -> Snapshot {
        let hour = (now as i64).div_euclid(HOUR) * HOUR;
        let day: Vec<&Bucket> = self.buckets.range(hour - 23 * HOUR..).map(|(_, b)| b).collect();
        let week: Vec<&Bucket> = self.buckets.range(hour - (KEEP_HOURS - 1) * HOUR..).map(|(_, b)| b).collect();

        let sources: HashSet<&String> = day.iter().flat_map(|b| b.sources.iter()).collect();
        let mut points: Vec<Point> = merge(day.iter().map(|b| &b.points))
            .into_iter()
            .filter_map(|(k, n)| {
                let (lat, lon) = k.split_once(',')?;
                Some(Point { lat: lat.parse().ok()?, lon: lon.parse().ok()?, n })
            })
            .collect();
        points.sort_by_key(|p| std::cmp::Reverse(p.n));
        points.truncate(MAX_POINTS);

        Snapshot {
            generated_at: now.floor(),
            total_24h: day.iter().map(|b| b.total).sum(),
            total_7d: week.iter().map(|b| b.total).sum(),
            unique_sources_24h: sources.len() as u64,
            by_service_24h: top(merge(day.iter().map(|b| &b.services)), TOP_N),
            top_usernames: top(merge(week.iter().map(|b| &b.usernames)), TOP_N),
            top_passwords: top(merge(week.iter().map(|b| &b.passwords)), TOP_N),
            top_paths: top(merge(week.iter().map(|b| &b.paths)), TOP_N),
            top_countries: top(merge(week.iter().map(|b| &b.countries)), TOP_N),
            top_user_agents: top(merge(week.iter().map(|b| &b.user_agents)), TOP_N),
            points_24h: points,
        }
    }

    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                eprintln!("stats: ignoring unreadable {}: {e}", path.display());
                Stats::default()
            }),
            Err(_) => Stats::default(),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::Location;

    fn ssh(ts: f64, ip: &str, user: &str, pass: &str) -> Event {
        let loc = Location { country: Some("NL".into()), city: None, lat: Some(52.37), lon: Some(4.89) };
        let mut e = Event::new("ssh", ip.parse().unwrap(), loc);
        e.ts = ts;
        e.username = Some(user.into());
        e.password = Some(pass.into());
        e
    }

    const NOW: f64 = 1_800_000_000.0;

    #[test]
    fn windows_and_top_lists() {
        let mut s = Stats::default();
        s.record(&ssh(NOW - 60.0, "198.51.100.1", "root", "123456"));
        s.record(&ssh(NOW - 120.0, "198.51.100.2", "root", "123456"));
        s.record(&ssh(NOW - 3.0 * 86400.0, "203.0.113.9", "admin", "admin"));
        let snap = s.snapshot(NOW);
        assert_eq!(snap.total_24h, 2);
        assert_eq!(snap.total_7d, 3);
        assert_eq!(snap.unique_sources_24h, 1, "both 24h hits are in 198.51.100.x");
        assert_eq!(snap.top_passwords[0], Top { k: "123456".into(), n: 2 });
        assert_eq!(snap.top_usernames.len(), 2);
        assert_eq!(snap.points_24h.len(), 1);
        assert_eq!(snap.points_24h[0].n, 2);
    }

    #[test]
    fn drops_buckets_older_than_a_week() {
        let mut s = Stats::default();
        s.record(&ssh(NOW - 8.0 * 86400.0, "198.51.100.1", "old", "old"));
        s.record(&ssh(NOW, "198.51.100.1", "new", "new"));
        assert_eq!(s.buckets.len(), 1);
        assert_eq!(s.snapshot(NOW).total_7d, 1);
    }

    #[test]
    fn distinct_keys_are_capped_per_hour_but_known_keys_keep_counting() {
        let mut s = Stats::default();
        for i in 0..MAP_CAP + 50 {
            s.record(&ssh(NOW, "198.51.100.1", "root", &format!("pw{i}")));
        }
        s.record(&ssh(NOW, "198.51.100.1", "root", "pw0"));
        let b = s.buckets.values().next().unwrap();
        assert_eq!(b.passwords.len(), MAP_CAP);
        assert_eq!(b.passwords["pw0"], 2);
        assert_eq!(b.total, (MAP_CAP + 51) as u64, "totals still count every event");
    }

    #[test]
    fn survives_a_save_and_load() {
        let dir = std::env::temp_dir().join(format!("hive-stats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("stats.json");
        let mut s = Stats::default();
        s.record(&ssh(NOW, "198.51.100.1", "root", "toor"));
        s.save(&path).unwrap();
        let loaded = Stats::load(&path);
        assert_eq!(loaded.snapshot(NOW).total_24h, 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

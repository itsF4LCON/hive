use serde::Serialize;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::geo::Location;

/// One thing an attacker did. `ip` is already masked; the full address never leaves this process.
#[derive(Serialize, Clone, Debug)]
pub struct Event {
    pub ts: f64,
    pub service: &'static str,
    pub ip: String,
    pub country: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub ua: Option<String>,
}

impl Event {
    pub fn new(service: &'static str, ip: IpAddr, loc: Location) -> Self {
        Event {
            ts: now_secs(),
            service,
            ip: mask_ip(ip),
            country: loc.country,
            city: loc.city,
            lat: loc.lat,
            lon: loc.lon,
            username: None,
            password: None,
            method: None,
            path: None,
            ua: None,
        }
    }
}

pub fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 203.0.113.57 -> 203.0.113.x, 2001:db8:1:2::5 -> 2001:db8:1::x
pub fn mask_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.x", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::x", s[0], s[1], s[2])
        }
    }
}

/// Attacker-controlled strings: drop control characters and cap the length.
pub fn clip(s: &str, max_chars: usize) -> Option<String> {
    let v: String = s.chars().filter(|c| !c.is_control()).take(max_chars).collect();
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_v4_and_v6() {
        assert_eq!(mask_ip("203.0.113.57".parse().unwrap()), "203.0.113.x");
        assert_eq!(mask_ip("2001:db8:1:2::5".parse().unwrap()), "2001:db8:1::x");
    }

    #[test]
    fn clip_strips_control_chars_and_caps_length() {
        assert_eq!(clip("ro\x1b[31mot\n", 64).as_deref(), Some("ro[31mot"));
        assert_eq!(clip(&"a".repeat(100), 64).unwrap().len(), 64);
        assert_eq!(clip("\n\t", 64), None);
    }
}

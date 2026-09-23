use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Policy {
    pub min_hits: u64,
    pub ignore: Vec<Cidr>,
}

impl Policy {
    pub fn allows(&self, ip: IpAddr) -> bool {
        is_public(ip) && !self.ignore.iter().any(|c| c.contains(ip))
    }
}

pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((a, p)) => (a.parse::<IpAddr>().ok()?, Some(p.parse::<u8>().ok()?)),
            None => (s.trim().parse::<IpAddr>().ok()?, None),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Cidr { net: addr.to_canonical(), prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(a)) => same_prefix(u32::from(n) as u128, u32::from(a) as u128, 32, self.prefix),
            (IpAddr::V6(n), IpAddr::V6(a)) => same_prefix(u128::from(n), u128::from(a), 128, self.prefix),
            _ => false,
        }
    }
}

fn same_prefix(a: u128, b: u128, bits: u8, prefix: u8) -> bool {
    prefix == 0 || (a ^ b) >> (bits - prefix) == 0
}

pub fn parse_ignore(list: &str) -> Vec<Cidr> {
    list.split(',')
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| {
            let c = Cidr::parse(s);
            if c.is_none() {
                eprintln!("HIVE_IGNORE_IPS: ignoring invalid entry {s:?}");
            }
            c
        })
        .collect()
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] == 0x2001 && s[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_public_addresses_count() {
        for s in ["1.2.3.4", "45.10.20.30", "2a01:4f8::1", "::ffff:1.2.3.4"] {
            assert!(is_public(ip(s)), "{s}");
        }
        for s in [
            "10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1",
            "198.18.0.1", "203.0.113.5", "0.0.0.0", "255.255.255.255", "240.0.0.1", "224.0.0.1",
            "::1", "fe80::1", "fd00::1", "2001:db8::1", "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(ip(s)), "{s}");
        }
    }

    #[test]
    fn cidr_matching() {
        let c = Cidr::parse("1.2.3.0/24").unwrap();
        assert!(c.contains(ip("1.2.3.200")));
        assert!(!c.contains(ip("1.2.4.1")));
        assert!(Cidr::parse("1.2.3.4").unwrap().contains(ip("::ffff:1.2.3.4")));
        assert!(Cidr::parse("2a01:4f8::/32").unwrap().contains(ip("2a01:4f8:1::9")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("9.9.9.9")));
        assert!(Cidr::parse("1.2.3.0/33").is_none());
        assert!(Cidr::parse("nope").is_none());
    }

    #[test]
    fn policy_ignores_listed_ranges() {
        let p = Policy { min_hits: 1, ignore: parse_ignore(" 1.2.3.0/24, bad,, 5.6.7.8") };
        assert_eq!(p.ignore.len(), 2);
        assert!(!p.allows(ip("1.2.3.9")));
        assert!(!p.allows(ip("5.6.7.8")));
        assert!(!p.allows(ip("10.1.1.1")));
        assert!(p.allows(ip("5.6.7.9")));
    }
}

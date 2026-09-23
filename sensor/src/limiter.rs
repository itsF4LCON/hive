use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Caps open connections overall and per source IP, shared by every service.
pub struct Limiter {
    global: Arc<Semaphore>,
    per_ip: Mutex<HashMap<IpAddr, u32>>,
    max_per_ip: u32,
}

pub struct Permit {
    _global: OwnedSemaphorePermit,
    limiter: Arc<Limiter>,
    ip: IpAddr,
}

impl Limiter {
    pub fn new(max_total: usize, max_per_ip: u32) -> Arc<Self> {
        Arc::new(Limiter {
            global: Arc::new(Semaphore::new(max_total)),
            per_ip: Mutex::new(HashMap::new()),
            max_per_ip,
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<Permit> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        let mut per_ip = self.per_ip.lock().unwrap();
        let n = per_ip.entry(ip).or_insert(0);
        if *n >= self.max_per_ip {
            return None;
        }
        *n += 1;
        Some(Permit { _global: global, limiter: self.clone(), ip })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut per_ip = self.limiter.per_ip.lock().unwrap();
        if let Some(n) = per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                per_ip.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_per_ip_and_global_caps() {
        let l = Limiter::new(3, 2);
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        let p1 = l.try_acquire(a).unwrap();
        let _p2 = l.try_acquire(a).unwrap();
        assert!(l.try_acquire(a).is_none(), "third from same IP");
        let _p3 = l.try_acquire(b).unwrap();
        assert!(l.try_acquire(b).is_none(), "global cap of 3");
        drop(p1);
        assert!(l.try_acquire(a).is_some(), "slot freed on drop");
    }
}

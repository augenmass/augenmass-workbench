use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateBucket {
    TunnelCreate,
    WalletForward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RateKey {
    ip: IpAddr,
    bucket: RateBucket,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    started_at: Instant,
    count: usize,
}

pub struct RateLimiter {
    window: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<RateKey, Window>>,
}

impl RateLimiter {
    pub fn new(window: Duration, max_entries: usize) -> Self {
        Self {
            window: window.max(Duration::from_secs(1)),
            max_entries: max_entries.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub async fn allow(&self, ip: IpAddr, bucket: RateBucket, limit: usize) -> bool {
        if limit == 0 {
            return false;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_, window| now.duration_since(window.started_at) < self.window);

        let key = RateKey { ip, bucket };
        let window = entries.entry(key).or_insert(Window {
            started_at: now,
            count: 0,
        });
        if now.duration_since(window.started_at) >= self.window {
            *window = Window {
                started_at: now,
                count: 0,
            };
        }
        if window.count >= limit {
            return false;
        }
        window.count += 1;

        if entries.len() > self.max_entries {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, window)| window.started_at)
                .map(|(key, _)| *key)
            {
                if oldest != key {
                    entries.remove(&oldest);
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enforces_limit_by_ip_and_bucket() {
        let limiter = RateLimiter::new(Duration::from_secs(1), 16);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.allow(ip, RateBucket::TunnelCreate, 2).await);
        assert!(limiter.allow(ip, RateBucket::TunnelCreate, 2).await);
        assert!(!limiter.allow(ip, RateBucket::TunnelCreate, 2).await);
        assert!(limiter.allow(ip, RateBucket::WalletForward, 2).await);
    }

    #[tokio::test]
    async fn zero_limit_denies() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 16);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!limiter.allow(ip, RateBucket::TunnelCreate, 0).await);
    }
}

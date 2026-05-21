//! Thread-local DNS cache with TTL-based expiry.
//!
//! One cache per worker thread (no cross-thread sync needed — thread-per-core).
//! Uses tokio::net::lookup_host (OS resolver via getaddrinfo) — zero extra dependencies.
//! The OS resolver reads /etc/resolv.conf for nameserver configuration.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::server::ServerConfig;

/// A single cached DNS result.
struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

/// Thread-local DNS cache. One per worker — no Arc/Mutex needed.
pub struct DnsCache {
    cache: HashMap<String, CacheEntry>,
    ttl: Duration,
    ipv4_first: bool,
}

impl DnsCache {
    pub fn new(config: &ServerConfig) -> Self {
        Self {
            cache: HashMap::new(),
            ttl: Duration::from_secs(config.dns_ttl),
            ipv4_first: config.dns_result_order == "ipv4first",
        }
    }

    /// Whether IPv4 results should be sorted first.
    #[inline]
    pub fn ipv4_first(&self) -> bool {
        self.ipv4_first
    }

    /// Check cache for a hostname (sync, no async). Returns first IP if cached and not expired.
    pub fn get_cached(&self, hostname: &str) -> Option<IpAddr> {
        let now = Instant::now();
        if let Some(entry) = self.cache.get(hostname) {
            if now < entry.expires_at {
                return Some(entry.addrs[0]);
            }
        }
        None
    }

    /// Insert a resolved result into the cache. Returns the first IP.
    pub fn insert_resolved(&mut self, hostname: &str, addrs: Vec<IpAddr>) -> IpAddr {
        let first = addrs[0];
        self.cache.insert(
            hostname.to_string(),
            CacheEntry {
                addrs,
                expires_at: Instant::now() + self.ttl,
            },
        );
        first
    }

    /// Periodic cache cleanup — remove expired entries.
    #[allow(dead_code)]
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| now < entry.expires_at);
    }
}

/// DNS resolution errors.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS resolution failed: {0}")]
    ResolveFailed(String),
    #[error("No addresses returned for {0}")]
    NoAddresses(String),
}

//! Security helpers: IP blocking, real IP parsing, egress policy.
//!
//! All checks happen at CONNECT time — ZERO overhead on the DATA hot path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::server::ServerConfig;

// ============================================================================
// IP address classification
// ============================================================================

/// Check if an IP is a loopback address.
/// Covers 127.0.0.0/8, ::1, and IPv4-mapped ::ffff:127.x.x.x.
#[inline]
pub fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Check if an IP is a private/RFC1918 address.
/// Covers 10/8, 172.16/12, 192.168/16, fc00::/7, and IPv4-mapped equivalents.
#[inline]
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => {
            // fc00::/7 — IPv6 unique-local
            is_ipv6_unique_local(v6)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_private())
        }
    }
}

/// Check if an IP is an unspecified address (0.0.0.0 or ::).
#[inline]
pub fn is_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_unspecified())
        }
    }
}

/// Check if an IP is a link-local address.
/// Covers 169.254/16, fe80::/10, and IPv4-mapped equivalents.
#[inline]
pub fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            is_ipv6_link_local(v6)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_link_local())
        }
    }
}

/// Check fe80::/10 - IPv6 link-local.
#[inline]
fn is_ipv6_link_local(v6: &Ipv6Addr) -> bool {
    let seg = v6.segments();
    seg[0] & 0xffc0 == 0xfe80
}

/// Check fc00::/7 - IPv6 unique-local.
#[inline]
fn is_ipv6_unique_local(v6: &Ipv6Addr) -> bool {
    let seg = v6.segments();
    seg[0] & 0xfe00 == 0xfc00
}

/// Check if an IP address should be blocked based on the three separate flags.
/// This replaces the old monolithic `is_blocked_ip()`.
#[inline]
pub fn is_ip_blocked(ip: &IpAddr, config: &ServerConfig) -> bool {
    // Unspecified is always blocked (0.0.0.0, ::) — connecting to these makes no sense
    if is_unspecified(ip) {
        return true;
    }

    // Check loopback (127.0.0.0/8, ::1)
    if !config.allow_loopback && is_loopback(ip) {
        return true;
    }

    // Check private ranges (RFC1918, unique-local)
    if !config.allow_private_ips && is_private(ip) {
        return true;
    }

    // Link-local is always blocked when private IPs are blocked
    if !config.allow_private_ips && is_link_local(ip) {
        return true;
    }

    false
}

/// Check if a hostname string looks like a raw IP address (not a DNS name).
#[inline]
pub fn is_raw_ip(hostname: &str) -> bool {
    hostname.parse::<Ipv4Addr>().is_ok() || hostname.parse::<Ipv6Addr>().is_ok()
}

/// Pre-resolution hostname check for obviously private/loopback hostnames.
/// This catches literal IP strings and well-known local names before DNS resolution.
/// The post-resolution `is_ip_blocked()` is the real guard.
#[inline]
pub fn is_hostname_blocked_pre_resolution(hostname: &str, config: &ServerConfig) -> bool {
    // Raw IP address check
    if !config.allow_direct_ip && is_raw_ip(hostname) {
        return true;
    }

    // Well-known local hostnames (pre-resolution fast-reject)
    if !config.allow_loopback
        && (hostname == "localhost"
            || hostname == "127.0.0.1"
            || hostname == "::1"
            || hostname == "0.0.0.0"
            || hostname == "::")
    {
        return true;
    }

    // Pre-resolution private IP string checks (the post-resolution check is authoritative)
    if !config.allow_private_ips {
        if hostname.starts_with("10.")
            || hostname.starts_with("192.168.")
            || hostname.starts_with("169.254.")
            || hostname_is_private_172(hostname)
        {
            return true;
        }
    }

    // Loopback IP string check
    if !config.allow_loopback && hostname.starts_with("127.") {
        return true;
    }

    false
}

/// Check if a hostname string starts with a 172.16-31.x.x private range.
#[inline]
fn hostname_is_private_172(hostname: &str) -> bool {
    if let Some(rest) = hostname.strip_prefix("172.") {
        if let Some(dot_pos) = rest.find('.') {
            if let Ok(second_octet) = rest[..dot_pos].parse::<u8>() {
                return (16..=31).contains(&second_octet);
            }
        }
    }
    false
}

// ============================================================================
// Real IP parsing
// ============================================================================

/// Parse trusted proxy CIDRs from config strings into ipnet::IpNet values.
pub fn parse_trusted_proxies(proxy_strs: &[String]) -> Vec<ipnet::IpNet> {
    let mut nets = Vec::with_capacity(proxy_strs.len());
    for s in proxy_strs {
        match s.parse::<ipnet::IpNet>() {
            Ok(net) => nets.push(net),
            Err(e) => {
                // Try as bare IP (add /32 or /128)
                if let Ok(ip) = s.parse::<IpAddr>() {
                    let prefix = match ip {
                        IpAddr::V4(_) => 32,
                        IpAddr::V6(_) => 128,
                    };
                    if let Ok(net) = ipnet::IpNet::new(ip, prefix) {
                        nets.push(net);
                    }
                } else {
                    tracing::warn!(cidr = %s, error = %e, "Invalid trusted proxy CIDR — skipping");
                }
            }
        }
    }
    nets
}

/// Check if a peer address is from a trusted proxy.
pub fn is_trusted_proxy(peer_ip: &IpAddr, trusted_proxies: &[ipnet::IpNet]) -> bool {
    if trusted_proxies.is_empty() {
        return false;
    }
    trusted_proxies.iter().any(|net| net.contains(peer_ip))
}

/// Extract real client IP from request headers.
/// Only called when real_ip is enabled AND the peer is a trusted proxy.
///
/// Checks headers in configured priority order (e.g., CF-Connecting-IP first,
/// then X-Forwarded-For). Returns the first valid IP found.
pub fn extract_real_ip(
    headers: &[(String, String)],
    config_headers: &[String],
) -> Option<IpAddr> {
    for target_header in config_headers {
        let target_lower = target_header.to_ascii_lowercase();
        for (name, value) in headers {
            if name.to_ascii_lowercase() == target_lower {
                // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
                // Take the leftmost (original client)
                let ip_str = value.split(',').next().unwrap_or(value).trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_loopback() {
        assert!(is_loopback(&"127.0.0.1".parse().unwrap()));
        assert!(is_loopback(&"127.0.0.2".parse().unwrap()));
        assert!(is_loopback(&"::1".parse().unwrap()));
        assert!(!is_loopback(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_is_private() {
        assert!(is_private(&"10.0.0.1".parse().unwrap()));
        assert!(is_private(&"172.16.0.1".parse().unwrap()));
        assert!(is_private(&"192.168.1.1".parse().unwrap()));
        assert!(!is_private(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_is_raw_ip() {
        assert!(is_raw_ip("127.0.0.1"));
        assert!(is_raw_ip("::1"));
        assert!(is_raw_ip("10.0.0.1"));
        assert!(!is_raw_ip("example.com"));
        assert!(!is_raw_ip("localhost"));
    }

    #[test]
    fn test_extract_real_ip() {
        let headers = vec![
            ("X-Forwarded-For".to_string(), "1.2.3.4, 5.6.7.8".to_string()),
            ("CF-Connecting-IP".to_string(), "9.10.11.12".to_string()),
        ];

        // CF-Connecting-IP has priority
        let config_headers = vec![
            "CF-Connecting-IP".to_string(),
            "X-Forwarded-For".to_string(),
        ];
        assert_eq!(
            extract_real_ip(&headers, &config_headers),
            Some("9.10.11.12".parse().unwrap())
        );

        // X-Forwarded-For takes leftmost IP
        let config_headers = vec!["X-Forwarded-For".to_string()];
        assert_eq!(
            extract_real_ip(&headers, &config_headers),
            Some("1.2.3.4".parse().unwrap())
        );
    }
}

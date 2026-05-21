//! Server configuration with JSON file support.
//!
//! Supports loading from a JSON config file (`--config <path>`) with CLI overrides.
//! All security checks happen at CONNECT time — zero overhead on the DATA hot path.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

// ============================================================================
// JSON config schema (matches mrrowisp structure where sensible)
// ============================================================================

/// Top-level JSON config file format.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct JsonConfig {
    pub bind: Option<String>,
    pub workers: Option<usize>,
    pub buffer_size: Option<u32>,
    pub tcp_no_delay: Option<bool>,
    pub allow_loopback: Option<bool>,
    pub allow_direct_ip: Option<bool>,
    pub allow_private_ips: Option<bool>,
    pub max_streams: Option<usize>,
    pub max_frame_size: Option<usize>,
    pub prod: Option<bool>,
    pub blacklist: Option<JsonFilterList>,
    pub whitelist: Option<JsonFilterList>,
    pub auth: Option<JsonAuth>,
    pub dns: Option<JsonDns>,
    pub real_ip: Option<JsonRealIp>,
    pub log_level: Option<String>,
    pub log_format: Option<String>,
    pub max_connections: Option<usize>,
    pub idle_timeout_secs: Option<u64>,
    pub max_connections_per_ip: Option<usize>,
    pub connection_window_secs: Option<u64>,
    pub ws_ping_interval_secs: Option<u64>,
    pub ws_pong_timeout_secs: Option<u64>,
    pub tcp_keepalive_secs: Option<u64>,
}

/// Hostname + port filter list (blacklist or whitelist).
/// Ports can be individual numbers or [start, end] ranges.
#[derive(Debug, Deserialize, Default)]
pub struct JsonFilterList {
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub ports: Vec<PortEntry>,
}

/// A port entry: either a single port or a [start, end] range.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PortEntry {
    Single(u16),
    Range([u16; 2]),
}

/// Auth configuration.
#[derive(Debug, Deserialize, Default)]
pub struct JsonAuth {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub users: HashMap<String, String>,
}

/// DNS cache configuration.
#[derive(Debug, Deserialize, Default)]
pub struct JsonDns {
    #[serde(default)]
    pub servers: Vec<String>,
    pub ttl: Option<u64>,
    pub result_order: Option<String>,
}

/// Real IP parsing configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct JsonRealIp {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub headers: Vec<String>,
}

// ============================================================================
// Runtime config (used by server after merging JSON + CLI)
// ============================================================================

/// Runtime configuration for the Wisp server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Per-stream buffer size in packets (initial CONTINUE credits).
    /// Must be the same for every stream on a connection per spec.
    pub buffer_size: u32,

    /// Enable TCP_NODELAY on proxied TCP sockets.
    pub tcp_nodelay: bool,

    /// Allow connections to loopback addresses (127.0.0.0/8, ::1).
    pub allow_loopback: bool,

    /// Allow connections to raw IP addresses (not hostnames).
    pub allow_direct_ip: bool,

    /// Allow connections to private/RFC1918 IP addresses.
    pub allow_private_ips: bool,

    /// Maximum streams per connection (0 = unlimited).
    pub max_streams: usize,

    /// Maximum WebSocket frame size in bytes (0 = unlimited).
    pub max_frame_size: usize,

    /// Legacy single-password auth (--password flag shorthand).
    /// When set, creates a single user "default" with this password.
    pub auth_password: Option<String>,

    /// Multi-user auth map: username -> password/bcrypt hash.
    /// Takes priority over auth_password when non-empty.
    pub auth_users: HashMap<String, String>,

    /// Whether auth is required (derived from auth config).
    pub auth_required: bool,

    /// Production mode: enables SO_ZEROCOPY for real NIC deployments.
    pub prod_mode: bool,

    // ── Blacklist/whitelist ──

    /// Blacklisted hostnames (case-insensitive, stored lowercase).
    pub blacklist_hostnames: HashSet<String>,

    /// Blacklisted ports (ranges expanded at load time).
    pub blacklist_ports: HashSet<u16>,

    /// Whitelisted hostnames (case-insensitive, stored lowercase).
    /// When non-empty, ONLY whitelisted hostnames are allowed.
    pub whitelist_hostnames: HashSet<String>,

    /// Whitelisted ports (ranges expanded at load time).
    /// When non-empty, ONLY whitelisted ports are allowed.
    pub whitelist_ports: HashSet<u16>,

    // ── DNS ──

    /// Custom DNS server addresses.
    pub dns_servers: Vec<String>,

    /// DNS cache TTL in seconds.
    pub dns_ttl: u64,

    /// DNS result ordering: "ipv4first", "ipv6first", or "verbatim".
    pub dns_result_order: String,

    // ── Real IP ──

    /// Whether to parse real client IP from headers.
    pub real_ip_enabled: bool,

    /// Trusted proxy CIDRs (only trust headers from these sources).
    pub real_ip_trusted_proxies: Vec<String>,

    /// Headers to check for real IP, in priority order.
    pub real_ip_headers: Vec<String>,

    /// Log level override from config.
    pub log_level: String,

    /// Log format: "text" (default) or "json".
    pub log_format: String,

    // ── Production QoL ──

    /// Maximum total connections per worker (0 = unlimited).
    pub max_connections: usize,

    /// Idle WebSocket timeout in seconds (0 = disabled).
    pub idle_timeout_secs: u64,

    /// Maximum connections per IP within the window (0 = unlimited).
    pub max_connections_per_ip: usize,

    /// Window in seconds for per-IP connection rate limiting.
    pub connection_window_secs: u64,

    /// WebSocket ping interval in seconds (0 = disabled).
    pub ws_ping_interval_secs: u64,

    /// WebSocket pong timeout in seconds after a ping is sent.
    pub ws_pong_timeout_secs: u64,

    /// TCP keepalive on backend sockets in seconds (0 = disabled).
    pub tcp_keepalive_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            buffer_size: 65535,
            tcp_nodelay: true,
            allow_loopback: true,
            allow_direct_ip: true,
            allow_private_ips: true,
            max_streams: 0,
            max_frame_size: 0,
            auth_password: None,
            auth_users: HashMap::new(),
            auth_required: false,
            prod_mode: false,
            blacklist_hostnames: HashSet::new(),
            blacklist_ports: HashSet::new(),
            whitelist_hostnames: HashSet::new(),
            whitelist_ports: HashSet::new(),
            dns_servers: Vec::new(),
            dns_ttl: 120,
            dns_result_order: "ipv4first".to_string(),
            real_ip_enabled: false,
            real_ip_trusted_proxies: Vec::new(),
            real_ip_headers: Vec::new(),
            log_level: "info".to_string(),
            log_format: "text".to_string(),
            max_connections: 0,
            idle_timeout_secs: 0,
            max_connections_per_ip: 0,
            connection_window_secs: 60,
            ws_ping_interval_secs: 0,
            ws_pong_timeout_secs: 10,
            tcp_keepalive_secs: 0,
        }
    }
}

impl ServerConfig {
    /// CONTINUE threshold: send CONTINUE at 90% consumed (per GAMEPLAN adaptive strategy).
    /// This keeps the pipeline full and avoids 1-RTT stalls.
    #[inline]
    pub fn continue_threshold(&self) -> u32 {
        // 90% of buffer_size consumed -> u64 intermediate prevents overflow for large buffer_size
        ((self.buffer_size as u64 * 9) / 10).max(1) as u32
    }

    /// Whether auth is effectively required (either auth_required flag or users/password set).
    #[inline]
    pub fn is_auth_required(&self) -> bool {
        self.auth_required || !self.auth_users.is_empty() || self.auth_password.is_some()
    }

    /// Apply --prod defaults. Called BEFORE config file merge so that
    /// config file values override these, and CLI flags override everything.
    pub fn apply_prod_defaults(&mut self) {
        // buffer_size: default 65535 is already optimal for all scenarios.
        // No override needed — max CONTINUE credits minimizes flow control overhead.
        if self.max_connections == 0 {
            self.max_connections = 8192;
        }
        if self.idle_timeout_secs == 0 {
            self.idle_timeout_secs = 300;
        }
        if self.max_connections_per_ip == 0 {
            self.max_connections_per_ip = 64;
        }
        if self.connection_window_secs == 60 {
            // only override if still at struct default
            self.connection_window_secs = 60;
        }
        if self.ws_ping_interval_secs == 0 {
            self.ws_ping_interval_secs = 30;
        }
        if self.ws_pong_timeout_secs == 10 {
            self.ws_pong_timeout_secs = 10;
        }
        if self.tcp_keepalive_secs == 0 {
            self.tcp_keepalive_secs = 60;
        }
    }

    /// Whether hostname/port filtering is active.
    #[inline]
    pub fn has_filters(&self) -> bool {
        !self.blacklist_hostnames.is_empty()
            || !self.blacklist_ports.is_empty()
            || !self.whitelist_hostnames.is_empty()
            || !self.whitelist_ports.is_empty()
    }

    /// Check if a hostname is allowed by blacklist/whitelist rules.
    /// Returns true if the connection should be BLOCKED.
    #[inline]
    pub fn is_hostname_blocked(&self, hostname: &str) -> bool {
        let hostname_lower = hostname.to_ascii_lowercase();

        // Whitelist takes priority: if whitelist exists, hostname must be in it
        if !self.whitelist_hostnames.is_empty() {
            return !self.whitelist_hostnames.contains(&hostname_lower);
        }

        // Blacklist: hostname must NOT be in it
        if !self.blacklist_hostnames.is_empty() {
            return self.blacklist_hostnames.contains(&hostname_lower);
        }

        false
    }

    /// Check if a port is allowed by blacklist/whitelist rules.
    /// Returns true if the connection should be BLOCKED.
    #[inline]
    pub fn is_port_blocked(&self, port: u16) -> bool {
        // Whitelist takes priority
        if !self.whitelist_ports.is_empty() {
            return !self.whitelist_ports.contains(&port);
        }

        if !self.blacklist_ports.is_empty() {
            return self.blacklist_ports.contains(&port);
        }

        false
    }
}

// ============================================================================
// Config loading
// ============================================================================

/// Expand a list of PortEntry into a flat HashSet of individual ports.
fn expand_ports(entries: &[PortEntry]) -> HashSet<u16> {
    let mut set = HashSet::new();
    for entry in entries {
        match entry {
            PortEntry::Single(p) => {
                set.insert(*p);
            }
            PortEntry::Range([start, end]) => {
                let (lo, hi) = if start <= end {
                    (*start, *end)
                } else {
                    (*end, *start)
                };
                for p in lo..=hi {
                    set.insert(p);
                }
            }
        }
    }
    set
}

/// Load a JSON config file and return the parsed structure.
pub fn load_json_config(path: &Path) -> Result<JsonConfig, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
    serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse config file {}: {}", path.display(), e))
}

/// Merge a JSON config into a ServerConfig, applying defaults for missing fields.
/// CLI overrides are applied separately in main.rs after this call.
pub fn merge_json_config(json: &JsonConfig) -> ServerConfig {
    let mut config = ServerConfig::default();

    if let Some(bs) = json.buffer_size {
        config.buffer_size = bs;
    }
    if let Some(tnd) = json.tcp_no_delay {
        config.tcp_nodelay = tnd;
    }
    if let Some(al) = json.allow_loopback {
        config.allow_loopback = al;
    }
    if let Some(adi) = json.allow_direct_ip {
        config.allow_direct_ip = adi;
    }
    if let Some(api) = json.allow_private_ips {
        config.allow_private_ips = api;
    }
    if let Some(ms) = json.max_streams {
        config.max_streams = ms;
    }
    if let Some(mfs) = json.max_frame_size {
        config.max_frame_size = mfs;
    }
    if let Some(p) = json.prod {
        config.prod_mode = p;
    }
    if let Some(ref ll) = json.log_level {
        config.log_level = ll.clone();
    }

    if let Some(ref lf) = json.log_format {
        config.log_format = lf.clone();
    }
    if let Some(mc) = json.max_connections {
        config.max_connections = mc;
    }
    if let Some(it) = json.idle_timeout_secs {
        config.idle_timeout_secs = it;
    }
    if let Some(mcpi) = json.max_connections_per_ip {
        config.max_connections_per_ip = mcpi;
    }
    if let Some(cw) = json.connection_window_secs {
        config.connection_window_secs = cw;
    }
    if let Some(wpi) = json.ws_ping_interval_secs {
        config.ws_ping_interval_secs = wpi;
    }
    if let Some(wpt) = json.ws_pong_timeout_secs {
        config.ws_pong_timeout_secs = wpt;
    }
    if let Some(tka) = json.tcp_keepalive_secs {
        config.tcp_keepalive_secs = tka;
    }

    // Blacklist/whitelist
    if let Some(ref bl) = json.blacklist {
        config.blacklist_hostnames = bl
            .hostnames
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        config.blacklist_ports = expand_ports(&bl.ports);
    }
    if let Some(ref wl) = json.whitelist {
        config.whitelist_hostnames = wl
            .hostnames
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        config.whitelist_ports = expand_ports(&wl.ports);
    }

    // Auth
    if let Some(ref auth) = json.auth {
        config.auth_required = auth.required;
        config.auth_users = auth.users.clone();

        // Warn about plaintext passwords at load time
        for (username, password) in &auth.users {
            if !password.starts_with("$2b$") && !password.starts_with("$2a$") {
                tracing::warn!(
                    username = %username,
                    "Plaintext password detected — use bcrypt hashes in production"
                );
            }
        }
    }

    // DNS
    if let Some(ref dns) = json.dns {
        config.dns_servers = dns.servers.clone();
        if let Some(ttl) = dns.ttl {
            config.dns_ttl = ttl;
        }
        if let Some(ref order) = dns.result_order {
            config.dns_result_order = order.clone();
        }
    }

    // Real IP
    if let Some(ref rip) = json.real_ip {
        config.real_ip_enabled = rip.enabled;
        config.real_ip_trusted_proxies = rip.trusted_proxies.clone();
        config.real_ip_headers = rip.headers.clone();
    }

    config
}

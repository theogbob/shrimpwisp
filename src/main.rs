
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod protocol;
mod proxy;
mod server;
mod ws;

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "shrimpwisp", about = "The fastest Wisp v2.1 server", version)]
struct Args {
    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0:4000")]
    bind: SocketAddr,

    /// Number of worker threads (0 = physical core count)
    #[arg(short = 'w', long, default_value = "0")]
    workers: usize,

    /// Per-stream buffer size in packets (CONTINUE credits)
    #[arg(long, default_value = "65535")]
    buffer_size: u32,

    /// Disable TCP_NODELAY on proxy sockets (enabled by default)
    #[arg(long)]
    no_tcp_nodelay: bool,

    /// Block connections to loopback addresses (allowed by default for benchmarking)
    #[arg(long)]
    block_loopback: bool,

    /// Block connections to raw IP addresses (not hostnames)
    #[arg(long)]
    block_direct_ip: bool,

    /// Block connections to private/RFC1918 IP addresses
    #[arg(long)]
    block_private_ips: bool,

    /// Max streams per connection (0 = unlimited)
    #[arg(long, default_value = "0")]
    max_streams: usize,

    /// Maximum WebSocket frame size in bytes (0 = unlimited)
    #[arg(long, default_value = "0")]
    max_frame_size: usize,

    /// Password for Wisp v2 auth (extension 0x02). Creates a "default" user.
    /// For multi-user auth, use a config file with the auth.users map.
    #[arg(long)]
    password: Option<String>,

    /// Production mode: enables SO_ZEROCOPY for real NIC deployments.
    /// Do NOT use for loopback benchmarks (hurts throughput on localhost).
    #[arg(long)]
    prod: bool,

    /// Path to JSON configuration file. CLI args override config file values.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,

    /// Log format: "text" (default) or "json"
    #[arg(long)]
    log_format: Option<String>,

    /// Max connections per worker (0 = unlimited)
    #[arg(long)]
    max_connections: Option<usize>,

    /// Idle WebSocket timeout in seconds (0 = disabled)
    #[arg(long)]
    idle_timeout_secs: Option<u64>,

    /// Max connections per IP within window (0 = unlimited)
    #[arg(long)]
    max_connections_per_ip: Option<usize>,

    /// Window in seconds for per-IP rate limiting
    #[arg(long)]
    connection_window_secs: Option<u64>,

    /// WebSocket ping interval in seconds (0 = disabled)
    #[arg(long)]
    ws_ping_interval_secs: Option<u64>,

    /// WebSocket pong timeout in seconds
    #[arg(long)]
    ws_pong_timeout_secs: Option<u64>,

    /// TCP keepalive on backend sockets in seconds (0 = disabled)
    #[arg(long)]
    tcp_keepalive_secs: Option<u64>,
}

fn main() {
    let args = Args::parse();

    // ── Load config: JSON file (if provided) with CLI overrides ──
    let mut config = if let Some(ref config_path) = args.config {
        match server::config::load_json_config(config_path) {
            Ok(json_config) => {
                let cfg = server::config::merge_json_config(&json_config);
                eprintln!("Loaded config from {}", config_path.display());
                cfg
            }
            Err(e) => {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        server::ServerConfig::default()
    };

    // ── Apply CLI overrides ──
    // CLI args always take priority over config file values.
    // For fields with explicit CLI defaults (buffer_size, max_streams, etc.),
    // we only override if the user actually specified them on the command line.
    // For boolean flags (block_loopback, prod, etc.), they override when set.

    // buffer_size: CLI default is 65535, but if config file set a different value,
    // only override if user explicitly passed --buffer-size
    if args.config.is_none() || std::env::args().any(|a| a.starts_with("--buffer-size") || a.starts_with("--buffer_size")) {
        config.buffer_size = args.buffer_size;
    }

    config.tcp_nodelay = if args.no_tcp_nodelay { false } else { config.tcp_nodelay };

    if args.block_loopback {
        config.allow_loopback = false;
    }
    if args.block_direct_ip {
        config.allow_direct_ip = false;
    }
    if args.block_private_ips {
        config.allow_private_ips = false;
    }

    if args.config.is_none() || std::env::args().any(|a| a.starts_with("--max-streams") || a.starts_with("--max_streams")) {
        config.max_streams = args.max_streams;
    }
    if args.config.is_none() || std::env::args().any(|a| a.starts_with("--max-frame-size") || a.starts_with("--max_frame_size")) {
        config.max_frame_size = args.max_frame_size;
    }

    // --password creates a single "default" user (shorthand for auth.users.default)
    if let Some(ref pw) = args.password {
        config.auth_password = Some(pw.clone());
    }

    if args.prod {
        config.prod_mode = true;
        // Apply --prod defaults BEFORE CLI overrides so CLI flags win
        config.apply_prod_defaults();
    }

    if let Some(ref ll) = args.log_level {
        config.log_level = ll.clone();
    }

    if let Some(ref lf) = args.log_format {
        config.log_format = lf.clone();
    }

    // CLI overrides for production QoL features
    if let Some(mc) = args.max_connections {
        config.max_connections = mc;
    }
    if let Some(it) = args.idle_timeout_secs {
        config.idle_timeout_secs = it;
    }
    if let Some(mcpi) = args.max_connections_per_ip {
        config.max_connections_per_ip = mcpi;
    }
    if let Some(cw) = args.connection_window_secs {
        config.connection_window_secs = cw;
    }
    if let Some(wpi) = args.ws_ping_interval_secs {
        config.ws_ping_interval_secs = wpi;
    }
    if let Some(wpt) = args.ws_pong_timeout_secs {
        config.ws_pong_timeout_secs = wpt;
    }
    if let Some(tka) = args.tcp_keepalive_secs {
        config.tcp_keepalive_secs = tka;
    }

    // Validate buffer_size
    if config.buffer_size == 0 {
        eprintln!("error: buffer_size must be >= 1");
        std::process::exit(1);
    }

    // ── Determine log level ──
    let log_level = if let Some(ref ll) = args.log_level {
        ll.clone()
    } else if args.config.is_some() {
        config.log_level.clone()
    } else {
        "info".to_string()
    };

    // Initialize tracing
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&log_level));

    if config.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .init();
    }

    // ── Determine bind address ──
    let bind_addr = if args.config.is_none() {
        args.bind
    } else if std::env::args().any(|a| a == "-b" || a.starts_with("--bind")) {
        args.bind // CLI override
    } else {
        // Try to parse from JSON config
        if let Some(ref config_path) = args.config {
            if let Ok(json) = server::config::load_json_config(config_path) {
                if let Some(ref bind_str) = json.bind {
                    match bind_str.parse::<SocketAddr>() {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("error: invalid bind address '{}' in config: {}", bind_str, e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    args.bind
                }
            } else {
                args.bind
            }
        } else {
            args.bind
        }
    };

    let workers = if args.config.is_none() || std::env::args().any(|a| a == "-w" || a.starts_with("--workers")) {
        if args.workers == 0 {
            num_physical_cores()
        } else {
            args.workers
        }
    } else if args.config.is_some() {
        if let Some(ref config_path) = args.config {
            if let Ok(json) = server::config::load_json_config(config_path) {
                let w = json.workers.unwrap_or(0);
                if w == 0 { num_physical_cores() } else { w }
            } else if args.workers == 0 {
                num_physical_cores()
            } else {
                args.workers
            }
        } else if args.workers == 0 {
            num_physical_cores()
        } else {
            args.workers
        }
    } else if args.workers == 0 {
        num_physical_cores()
    } else {
        args.workers
    };

    // Log security config
    if config.has_filters() {
        tracing::info!(
            blacklist_hosts = config.blacklist_hostnames.len(),
            blacklist_ports = config.blacklist_ports.len(),
            whitelist_hosts = config.whitelist_hostnames.len(),
            whitelist_ports = config.whitelist_ports.len(),
            "Hostname/port filtering active"
        );
    }
    if config.is_auth_required() {
        let user_count = config.auth_users.len() + if config.auth_password.is_some() { 1 } else { 0 };
        tracing::info!(users = user_count, "Authentication enabled");
    }
    if config.real_ip_enabled {
        tracing::info!(
            headers = ?config.real_ip_headers,
            proxies = config.real_ip_trusted_proxies.len(),
            "Real IP parsing enabled"
        );
    }

    if config.prod_mode {
        tracing::info!(
            max_connections = config.max_connections,
            idle_timeout_secs = config.idle_timeout_secs,
            max_connections_per_ip = config.max_connections_per_ip,
            ws_ping_interval_secs = config.ws_ping_interval_secs,
            tcp_keepalive_secs = config.tcp_keepalive_secs,
            "Production mode enabled"
        );
    }

    tracing::info!(
        bind = %bind_addr,
        workers = workers,
        buffer_size = config.buffer_size,
        tcp_nodelay = config.tcp_nodelay,
        allow_loopback = config.allow_loopback,
        allow_direct_ip = config.allow_direct_ip,
        allow_private_ips = config.allow_private_ips,
        dns_ttl = config.dns_ttl,
        "Starting shrimpwisp server"
    );

    // Phase 1: ThreadPerCore via N independent current_thread runtimes
    server::run_thread_per_core(bind_addr, workers, config);
}

/// Get schedulable core count (includes hyperthreads -- fine for I/O-bound workers).
fn num_physical_cores() -> usize {
    // Count physical cores from sysfs, excluding hyperthreads.
    // On a 4C/8T machine this returns 4, not 8 — avoids SO_REUSEPORT
    // imbalance where most workers sit idle with few connections.
    //
    // Uses (physical_package_id, core_id) to handle multi-socket systems
    // where core_id alone can collide across packages.
    // Intersects with core_affinity to respect cpuset/cgroup constraints.
    let schedulable = core_affinity::get_core_ids().unwrap_or_default();
    if schedulable.is_empty() {
        return 1;
    }
    let schedulable_set: std::collections::HashSet<usize> = schedulable.iter().map(|c| c.id).collect();

    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") {
        let mut physical_cores = std::collections::HashSet::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("cpu") && name[3..].chars().all(|c| c.is_ascii_digit()) {
                // Only count CPUs that are schedulable (respects cpuset/cgroup)
                if let Ok(cpu_num) = name[3..].parse::<usize>() {
                    if !schedulable_set.contains(&cpu_num) {
                        continue;
                    }
                }
                let base = entry.path().join("topology");
                let pkg = std::fs::read_to_string(base.join("physical_package_id"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(0);
                let core = std::fs::read_to_string(base.join("core_id"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok());
                if let Some(core_id) = core {
                    physical_cores.insert((pkg, core_id));
                }
            }
        }
        if !physical_cores.is_empty() {
            return physical_cores.len();
        }
    }
    // Fallback: all schedulable cores (includes hyperthreads)
    schedulable.len()
}

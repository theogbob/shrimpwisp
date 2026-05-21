//! Thread-Per-Core server runtime.
//!
//! Spawns N independent Tokio current_thread runtimes, each pinned to a
//! physical core, each with its own SO_REUSEPORT listener.
//! Zero cross-core synchronization in the steady state.

pub mod config;
pub mod connection;
pub mod dns;
pub mod security;

pub use config::ServerConfig;

use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

/// Launch the thread-per-core server.
///
/// Each thread:
/// 1. Pins itself to a physical core
/// 2. Creates its own SO_REUSEPORT TCP listener
/// 3. Runs an independent Tokio current_thread runtime
/// 4. Accepts connections and handles them with spawn_local (!Send futures)
pub fn run_thread_per_core(bind_addr: SocketAddr, num_workers: usize, config: ServerConfig) {
    // --prod mode: system-level self-optimizations for real VPS deployments.
    // These help consistency on production servers but can interfere with
    // co-located processes on benchmark machines.
    if config.prod_mode {
        #[cfg(target_os = "linux")]
        {
            // Raise resource limits (soft -> hard) before other optimizations
            unsafe {
                // RLIMIT_MEMLOCK: enable mlockall (default soft limit is often 64KB)
                let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim);
                rlim.rlim_cur = rlim.rlim_max;
                libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);

                // RLIMIT_NOFILE: raise fd limit for high connection counts
                libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim);
                rlim.rlim_cur = rlim.rlim_max.min(1_048_576);
                libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
                tracing::info!(memlock = rlim.rlim_cur, nofile = rlim.rlim_cur, "Resource limits raised");
            }

            // Lock all pages in RAM -- prevents page faults on hot path
            unsafe {
                if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 {
                    tracing::info!("Memory locked (mlockall)");
                }
            }

            // Minimize timer slack -- 1ns precision instead of default 50us
            // Makes epoll_wait wakeups and timer-fd events precise
            unsafe {
                const PR_SET_TIMERSLACK: libc::c_int = 29;
                libc::prctl(PR_SET_TIMERSLACK, 1u64, 0, 0, 0);
                tracing::info!("Timer slack set to 1ns");
            }

            // Set CPU governor to performance -- prevents frequency scaling lag
            use std::fs;
            let mut set_count = 0u32;
            let core_ids_for_gov = core_affinity::get_core_ids().unwrap_or_default();
            for (i, _) in core_ids_for_gov.iter().enumerate().take(num_workers) {
                let path = format!("/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_governor");
                if fs::write(&path, "performance").is_ok() {
                    set_count += 1;
                }
            }
            if set_count > 0 {
                tracing::info!(cores = set_count, "Set CPU governor to performance");
            }
        }
    }

    let config = Arc::new(config);
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();

    let handles: Vec<_> = (0..num_workers)
        .map(|worker_id| {
            let config = Arc::clone(&config);
            let core_id = core_ids.get(worker_id).copied();

            thread::Builder::new()
                .name(format!("wisp-worker-{worker_id}"))
                .spawn(move || {
                    // Pin to physical core if available
                    if let Some(core) = core_id {
                        core_affinity::set_for_current(core);
                    }

                    // --prod mode: elevate to real-time scheduling.
                    // SCHED_FIFO prevents OS from preempting workers for normal processes.
                    // Only in prod because it starves co-located echo/clients on benchmark machines.
                    // On a real VPS where the proxy is the primary workload, this is correct.
                    #[cfg(target_os = "linux")]
                    if config.prod_mode {
                        unsafe {
                            let param = libc::sched_param { sched_priority: 50 };
                            if libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) == 0 {
                                tracing::info!(worker = worker_id, "SCHED_FIFO priority 50");
                            } else {
                                libc::setpriority(libc::PRIO_PROCESS, 0, -20);
                            }
                        }
                    }

                    // Build a single-threaded runtime (no work-stealing, no Send requirement)
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .event_interval(31)  // more responsive I/O polling (default 61)
                        .build()
                        .expect("failed to build tokio runtime");

                    rt.block_on(async move {
                        let listener = create_reuseport_listener(bind_addr)
                            .expect("failed to create listener");

                        let local = tokio::task::LocalSet::new();
                        local
                            .run_until(accept_loop(listener, config, worker_id))
                            .await;
                    });
                })
                .expect("failed to spawn worker thread")
        })
        .collect();

    // Wait for all workers (they run forever)
    for handle in handles {
        handle.join().expect("worker thread panicked");
    }
}

/// Accept loop: accepts connections and spawns local tasks.
/// Takes Arc<ServerConfig> and converts to Rc once (per-worker, no further atomics).
///
/// PERFORMANCE CRITICAL: No select!, no signal handler, no timeout on accept.
/// The accept loop must be a bare `listener.accept().await` to avoid adding
/// any per-poll overhead to tokio's event loop. Graceful shutdown is handled
/// by the process receiving SIGTERM which drops the listener — accept returns
/// an error and the loop breaks naturally.
async fn accept_loop(
    listener: tokio::net::TcpListener,
    config: Arc<ServerConfig>,
    worker_id: usize,
) {
    tracing::info!(worker = worker_id, "Worker accepting connections");

    // Convert Arc → Rc once per worker thread. All connections on this worker
    // share the Rc — no atomic refcount on the hot path.
    let config: Rc<ServerConfig> = {
        let inner = (*config).clone();
        Rc::new(inner)
    };

    // Create per-worker DNS cache (thread-local, no cross-thread sync)
    let dns_cache = Rc::new(std::cell::RefCell::new(dns::DnsCache::new(&config)));

    // Parse trusted proxies once per worker
    let trusted_proxies = Rc::new(security::parse_trusted_proxies(&config.real_ip_trusted_proxies));

    // Per-worker connection counter (Rc<Cell> — no atomics, thread-per-core)
    let conn_count = Rc::new(Cell::new(0usize));
    let max_connections = config.max_connections;

    // Per-worker per-IP rate limiting state
    let max_per_ip = config.max_connections_per_ip;
    let conn_window = std::time::Duration::from_secs(config.connection_window_secs);
    let mut ip_rate_map: HashMap<IpAddr, (usize, Instant)> = HashMap::new();
    let mut accept_count: u64 = 0; // for periodic cleanup scheduling

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                // Max connections check (0 = unlimited)
                if max_connections > 0 && conn_count.get() >= max_connections {
                    drop(stream);
                    tracing::debug!(worker = worker_id, limit = max_connections, "Max connections reached, dropping");
                    continue;
                }

                // Per-IP rate limiting (0 = unlimited)
                if max_per_ip > 0 {
                    let ip = peer_addr.ip();
                    let now = Instant::now();
                    let entry = ip_rate_map.entry(ip).or_insert((0, now));
                    if now.duration_since(entry.1) >= conn_window {
                        entry.0 = 0;
                        entry.1 = now;
                    }
                    entry.0 += 1;
                    if entry.0 > max_per_ip {
                        drop(stream);
                        tracing::debug!(worker = worker_id, ip = %ip, limit = max_per_ip, "Per-IP rate limit exceeded");
                        continue;
                    }

                    // Evict expired entries every 1024 accepts to prevent unbounded growth
                    accept_count += 1;
                    if accept_count & 1023 == 0 {
                        let cutoff = conn_window;
                        ip_rate_map.retain(|_, (_, window_start)| now.duration_since(*window_start) < cutoff);
                    }
                }

                // TCP_QUICKACK: disable delayed ACKs — faster ACK = faster CONTINUE flow
                unsafe {
                    let val: libc::c_int = 1;
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        libc::TCP_QUICKACK,
                        &val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
                let config = Rc::clone(&config);
                let dns_cache = Rc::clone(&dns_cache);
                let trusted_proxies = Rc::clone(&trusted_proxies);

                // Increment connection counter
                conn_count.set(conn_count.get() + 1);
                let conn_count_handle = Rc::clone(&conn_count);

                // spawn_local + unconstrained: disable cooperative scheduling budget.
                // The select! loop has natural yield points at every .await — forced
                // preemption every 128 polls is pure overhead.
                tokio::task::spawn_local(tokio::task::unconstrained(async move {
                    if let Err(e) = connection::handle_connection(
                        stream, peer_addr, config, dns_cache, &trusted_proxies,
                    ).await {
                        tracing::debug!(peer = %peer_addr, error = %e, "Connection closed");
                    }
                    // Decrement connection counter when task finishes
                    conn_count_handle.set(conn_count_handle.get().saturating_sub(1));
                }));
            }
            Err(e) => {
                tracing::warn!(worker = worker_id, error = %e, "Accept error");
                tokio::task::yield_now().await;
            }
        }
    }
}

/// Create a TCP listener socket with SO_REUSEPORT for kernel-level load distribution.
fn create_reuseport_listener(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // SO_REUSEPORT: allow multiple sockets to bind to the same port.
    // Kernel distributes incoming connections via 4-tuple hash.
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;

    // TCP_NODELAY on the listener propagates to accepted sockets on some kernels,
    // but we also set it explicitly on accepted sockets.
    socket.set_nodelay(true)?;

    // Non-blocking for Tokio
    socket.set_nonblocking(true)?;

    socket.bind(&addr.into())?;
    socket.listen(8192)?; // Large backlog for burst acceptance

    // TCP_FASTOPEN: allow data in SYN (saves 1 RTT on reconnections)
    // Queue length = 256 pending TFO connections
    let tfo_val: libc::c_int = 256;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &tfo_val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Convert socket2 -> std -> tokio
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

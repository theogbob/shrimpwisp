# shrimpwisp [NOT FOR PROD USE]

**BETA/PoC** - The fastest Wisp v2.1 proxy server.

Built in Rust. Thread-per-core architecture. Beats every other Wisp implementation on throughput benchmarks, including mrrowisp (Go), epoxy-server, and wisp-js.

## Status

This is a beta release. The server is functional and passes all benchmarks, but has not been extensively tested across different platforms and configurations. Bug reports welcome via GitHub issues.

## Why it's fast

- **Thread-per-core with SO_REUSEPORT.** Each worker is an independent tokio runtime pinned to a physical core. Zero cross-thread synchronization during steady state data transfer.
- **Fused WS+Wisp parser.** A single function call goes from raw TCP bytes to a parsed Wisp frame. No intermediate allocations on the data path.
- **Batch inbound processing.** All buffered frames are processed in a tight loop before returning to the async scheduler. Multiplexed connections process frames back-to-back with no per-frame overhead.
- **Pre-framed backend writes.** WS and Wisp headers are written into the same buffer as the payload. The writev syscall sends complete frames without constructing scatter-gather lists.
- **Borrow-first backend writes.** Data is written to backend sockets directly from borrowed memory. Heap allocation only happens on the rare backpressure path (< 0.01% of writes on localhost).
- **AVX2 XOR unmask** via a vendored fork of fastwebsockets. Processes 32 bytes per cycle.
- **jemalloc** with tuned thread-local caches for the hot allocation size class.

## Quick start

```bash
# Build
cargo build --release

# Run with defaults (binds to 0.0.0.0:4000, auto-detects core count)
./target/release/shrimpwisp

# Run with a config file
./target/release/shrimpwisp --config config.json

# Run in production mode (enables rate limiting, idle timeouts, keepalive, scheduling tweaks)
./target/release/shrimpwisp --config config.json --prod
```

## CLI options

```
shrimpwisp [OPTIONS]

Options:
  -b, --bind <ADDR>                  Bind address [default: 0.0.0.0:4000]
  -w, --workers <N>                  Worker threads, 0 = auto [default: 0]
  -c, --config <PATH>                JSON config file (CLI args override config values)
      --buffer-size <N>              CONTINUE credits per stream [default: 65535]
      --password <PW>                Single-user auth password
      --prod                         Production mode with sensible defaults
      --block-loopback               Block connections to loopback addresses
      --block-direct-ip              Block connections to raw IP addresses
      --block-private-ips            Block connections to RFC1918 addresses
      --max-streams <N>              Max streams per connection, 0 = unlimited
      --max-frame-size <N>           Max WS frame size in bytes, 0 = unlimited
      --max-connections <N>          Max connections per worker, 0 = unlimited
      --idle-timeout-secs <N>        Close idle WS connections after N seconds, 0 = disabled
      --max-connections-per-ip <N>   Rate limit connections per IP, 0 = unlimited
      --ws-ping-interval-secs <N>    Server-initiated ping interval, 0 = disabled
      --tcp-keepalive-secs <N>       Backend TCP keepalive, 0 = disabled
      --log-level <LEVEL>            trace, debug, info, warn, error
      --log-format <FMT>             "text" or "json"
      --no-tcp-nodelay               Disable TCP_NODELAY
  -V, --version                      Print version
  -h, --help                         Print help
```

## Configuration

All settings can be specified in a JSON config file. CLI arguments override config file values. See `deploy/config.example.json` for the full schema with documentation.

### Config file example

```json
{
  "bind": "0.0.0.0:4000",
  "workers": 0,
  "bufferSize": 65535,
  "prod": true,
  "blacklist": {
    "hostnames": ["malware.example.com"],
    "ports": [25, [6660, 6669]]
  },
  "auth": {
    "required": true,
    "users": {
      "admin": "$2b$12$LJ3m4ys3Lg7Eqhvlfn.JduGDBWCR0FDVcnXlMBGqpYqnqYfHJBCam"
    }
  },
  "dns": {
    "ttl": 120,
    "resultOrder": "ipv4first"
  },
  "realIp": {
    "enabled": true,
    "trustedProxies": ["127.0.0.1/32"],
    "headers": ["CF-Connecting-IP", "X-Forwarded-For"]
  }
}
```

### Production mode (`--prod`)

When `--prod` is set, the following defaults are applied (overridable by config file or CLI):

| Setting | Default | --prod |
|---------|---------|--------|
| `bufferSize` | 65535 | 65535 |
| `maxConnections` | 0 (unlimited) | 8192 per worker |
| `idleTimeoutSecs` | 0 (disabled) | 300 (5 min) |
| `maxConnectionsPerIp` | 0 (unlimited) | 64 |
| `wsPingIntervalSecs` | 0 (disabled) | 30 |
| `tcpKeepaliveSecs` | 0 (disabled) | 60 |

Production mode also enables:
- `SCHED_FIFO` real-time scheduling (falls back to nice -20 without root)
- `mlockall` to prevent page faults
- CPU frequency governor set to `performance`
- `SO_ZEROCOPY` on client sockets (benefits real NICs, not loopback)
- Timer slack set to 1ns
- Raised file descriptor and memory lock limits

### Authentication

Supports Wisp v2 password auth (extension 0x02). Passwords can be plaintext (not recommended) or bcrypt hashes.

Generate a bcrypt hash:
```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'mypassword', bcrypt.gensalt(rounds=12)).decode())"
```

The `--password` CLI flag creates a single "default" user. For multiple users, use the config file's `auth.users` map.

### Health check

`GET /health` on the bind port returns HTTP 200. Works with load balancer health checks without interfering with WebSocket traffic.

### Filtering

Blacklists and whitelists support hostnames and port ranges. When a whitelist is non-empty, only listed entries are allowed (blacklist is ignored). Port ranges use `[start, end]` syntax.

### Real IP

When running behind a reverse proxy (Cloudflare, nginx, etc.), enable `realIp` to extract the client's real IP from forwarded headers. Only headers from trusted proxy CIDRs are honored.

## Deployment

### systemd

A unit file is provided at `deploy/shrimpwisp.service`. Copy it and adjust paths:

```bash
sudo cp deploy/shrimpwisp.service /etc/systemd/system/
sudo cp target/release/shrimpwisp /usr/local/bin/
sudo mkdir -p /etc/shrimpwisp
sudo cp deploy/config.example.json /etc/shrimpwisp/config.json
# Edit /etc/shrimpwisp/config.json as needed
sudo systemctl enable --now shrimpwisp
```

### Docker

```dockerfile
FROM rust:1.87-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/shrimpwisp /usr/local/bin/
EXPOSE 4000
ENTRYPOINT ["shrimpwisp"]
```

## Building from source

Requires Rust 2024 edition (1.85+).

```bash
git clone https://github.com/theogbob/shrimpwisp.git
cd shrimpwisp
cargo build --release
```

The release binary is at `target/release/shrimpwisp`.

## Running benchmarks

shrimpwisp is tested with [wispmark](https://github.com/MercuryWorkshop/wispmark). A wrapper script is included:

```bash
# From the wispmark directory:
bash wispmark.xsh  # follow wispmark's instructions, point it at the shrimpwisp directory
```

## License

MIT

---

Built with the help of [Claude](https://claude.ai). All code comments are written by Claude.

//! WebSocket upgrade handler using fastwebsockets + Hyper.
//!
//! Returns a raw WebSocket (not FragmentCollector) for maximum hot-path speed.
//! Wisp binary frames are never fragmented in practice, so FragmentCollector
//! is dead overhead.

use fastwebsockets::upgrade::{is_upgrade_request, upgrade};
use fastwebsockets::WebSocket;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::rc::Rc;
use tokio::net::TcpStream;

use crate::server::ServerConfig;

/// Raw WebSocket type after upgrade — no FragmentCollector overhead.
pub type WsStream = WebSocket<TokioIo<hyper::upgrade::Upgraded>>;

/// Result of WebSocket upgrade.
pub struct UpgradeResult {
    pub ws: WsStream,
    pub is_v2: bool,
    /// Captured HTTP headers from the upgrade request (for real IP parsing).
    /// Only populated when real_ip is enabled in config.
    pub headers: Vec<(String, String)>,
}

/// Handle the HTTP -> WebSocket upgrade for a raw TCP connection.
pub async fn handle_ws_upgrade(
    stream: TcpStream,
    config: Rc<ServerConfig>,
) -> Result<UpgradeResult, WsUpgradeError> {
    stream.set_nodelay(true)?;

    let io = TokioIo::new(stream);

    // Channel carries: (is_v2, upgrade_fut, captured_headers)
    let (tx, rx) =
        tokio::sync::oneshot::channel::<(bool, fastwebsockets::upgrade::UpgradeFut, Vec<(String, String)>)>();
    let tx = std::cell::Cell::new(Some(tx));

    let real_ip_headers: Option<Vec<String>> = if config.real_ip_enabled {
        Some(config.real_ip_headers.clone())
    } else {
        None
    };

    let service = service_fn(move |mut req: Request<Incoming>| {
        let tx = tx.take();
        let rip_headers = real_ip_headers.clone();
        async move {
            // Health check endpoint: GET /health returns JSON status
            if !is_upgrade_request(&req) {
                if req.method() == hyper::Method::GET && req.uri().path() == "/health" {
                    return Ok(Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Empty::new())
                        .unwrap());
                }
                return Ok(Response::builder()
                    .status(200)
                    .body(Empty::new())
                    .unwrap());
            }

            // Extract Sec-WebSocket-Protocol — browsers require echo in 101 response
            let requested_protocol = req
                .headers()
                .get("sec-websocket-protocol")
                .cloned();

            let is_v2 = requested_protocol.is_some();

            // Capture headers for real IP parsing (only the ones we care about)
            // Zero overhead when real_ip is disabled — no Vec allocation, no header scan
            let mut captured_headers = Vec::new();
            if let Some(ref rip_hdrs) = rip_headers {
                for target in rip_hdrs {
                    let target_lower = target.to_ascii_lowercase();
                    for (name, value) in req.headers() {
                        if name.as_str().to_ascii_lowercase() == target_lower {
                            if let Ok(v) = value.to_str() {
                                captured_headers.push((name.to_string(), v.to_string()));
                            }
                        }
                    }
                }
            }

            let (mut response, upgrade_fut) = match upgrade(&mut req) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "fastwebsockets upgrade() rejected request");
                    return Ok(Response::builder()
                        .status(400)
                        .body(Empty::new())
                        .unwrap());
                }
            };

            // Echo back subprotocol so browsers accept the connection
            if let Some(protocol) = requested_protocol {
                response
                    .headers_mut()
                    .insert("sec-websocket-protocol", protocol);
            }

            // Explicitly remove Sec-WebSocket-Extensions from response.
            // We do NOT support permessage-deflate. If the client requested it
            // and we don't reject it here, some clients (tokio-websockets) will
            // assume it was accepted and send compressed frames with RSV1=1,
            // which fastwebsockets rejects as "Reserved bits are not zero".
            response.headers_mut().remove("sec-websocket-extensions");

            if let Some(tx) = tx {
                let _ = tx.send((is_v2, upgrade_fut, captured_headers));
            }

            Ok::<_, std::convert::Infallible>(response)
        }
    });

    let conn = http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades();

    tokio::task::spawn_local(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "HTTP connection error during upgrade");
        }
    });

    let (is_v2, upgrade_fut, headers) = rx.await.map_err(|_| {
        tracing::debug!("Upgrade channel dropped — client disconnected before HTTP request");
        WsUpgradeError::UpgradeFailed
    })?;

    let mut ws = upgrade_fut.await?;

    // Enable vectored writes for gathered I/O (header + payload in one syscall)
    ws.set_writev(true);
    // No auto-close handling — we manage close frames ourselves
    ws.set_auto_close(false);

    Ok(UpgradeResult { ws, is_v2, headers })
}

/// Errors during WebSocket upgrade.
#[derive(Debug, thiserror::Error)]
pub enum WsUpgradeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WebSocket upgrade failed")]
    UpgradeFailed,

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("WebSocket error: {0}")]
    WebSocket(#[from] fastwebsockets::WebSocketError),
}

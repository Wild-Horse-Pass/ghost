//! HTTP wire transport for `SessionGossipEvent` between coordinators.
//!
//! Active coordinators install an `HttpGossipSink` so every session
//! state change publishes a JSON event to every peer in the
//! coordinator pool. Standby coordinators expose `POST /api/v1/internal/gossip`
//! and apply received events to their `LiteSessionRegistry`. Once the
//! Active dies and a Standby promotes itself, its registry already
//! mirrors the in-flight session set — no cold start, no lost rounds.
//!
//! ### Wire format
//!
//! `SessionGossipEvent` is `serde_json`-serialised verbatim — the
//! protocol crate is the source of truth for shape. The HTTP request
//! is `POST /api/v1/internal/gossip` with `Content-Type: application/json`
//! and the event JSON as the body. The receiver returns `200` on
//! successful apply, `404` if the event references an unknown session
//! (the standby missed `SessionCreated`; it'll reconcile on the next
//! snapshot), and `400` on malformed JSON.
//!
//! ### Authentication (deferred)
//!
//! v1 trusts peers on a private network (operator deploys all
//! coordinators in the pool together and firewalls the
//! `/api/v1/internal/` prefix to the pool's address range). A future
//! commit lands a shared-secret HMAC header so the route can be safely
//! exposed on a public address — the wire format anticipates this.
//!
//! ### Async layout
//!
//! `publish` is sync (the `GossipSink` trait is sync, so registry
//! mutations don't have to await). It pushes the event into an
//! `mpsc` channel and returns immediately; a background tokio task
//! drains the channel and POSTs to every peer in parallel. A slow
//! peer never blocks the coordinator's hot path.

use std::sync::Arc;

use reqwest::Client;
use tokio::sync::mpsc::{self, UnboundedSender};
use tracing::{debug, warn};
use wraith_protocol::{GossipSink, SessionGossipEvent};

use crate::gossip_auth;

/// Default per-request timeout. A peer that doesn't ack within this
/// window is logged and the event is dropped — we don't retry, since
/// every event is idempotent and the next event will catch the peer
/// up (or the next snapshot reconcile, when that path lands).
const PEER_REQUEST_TIMEOUT_SECS: u64 = 5;

/// Async HTTP gossip sink. Construct via [`HttpGossipSink::spawn`],
/// which kicks off the background drain task and returns a handle that
/// implements [`GossipSink`] for installation on `LiteSessionRegistry`.
pub struct HttpGossipSink {
    tx: UnboundedSender<SessionGossipEvent>,
}

impl HttpGossipSink {
    /// Build the sink + spawn the drain task.
    ///
    /// `peers` are the absolute base URLs of every other coordinator
    /// in the pool (e.g. `["http://10.0.0.2:9100", "http://10.0.0.3:9100"]`).
    /// Each event is POSTed to `{peer}/api/v1/internal/gossip`.
    ///
    /// `peer_secret` is the shared HMAC key for inter-coordinator
    /// authentication. When `Some`, every outbound POST carries
    /// `X-Ghost-Signature` + `X-Ghost-Timestamp` headers per
    /// `gossip_auth`. When `None`, requests are unsigned (operators
    /// must firewall the `/api/v1/internal/` prefix to the pool's
    /// address range).
    ///
    /// Caller-supplied `runtime_handle` keeps the drain task alive
    /// across the binary's tokio runtime — when the runtime tears
    /// down, the task exits cleanly because the receiver returns
    /// `None`.
    pub fn spawn(
        peers: Vec<String>,
        peer_secret: Option<String>,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<SessionGossipEvent>();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(PEER_REQUEST_TIMEOUT_SECS))
            .build()
            .expect("reqwest client builds with default settings");
        let peers = Arc::new(peers);
        let peer_secret = Arc::new(peer_secret);

        runtime_handle.spawn(async move {
            while let Some(event) = rx.recv().await {
                let peers = peers.clone();
                let client = client.clone();
                let peer_secret = peer_secret.clone();
                // Fire-and-forget per event. Slow peers don't queue
                // up behind one another because each event spawns
                // its own per-peer fan-out.
                tokio::spawn(async move {
                    let payload = match serde_json::to_string(&event) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(error = %e, "gossip: failed to serialize event; dropping");
                            return;
                        }
                    };
                    let timestamp = chrono::Utc::now().timestamp();
                    let signature = peer_secret
                        .as_deref()
                        .map(|s| gossip_auth::sign(s, timestamp, payload.as_bytes()));
                    let mut joins = Vec::with_capacity(peers.len());
                    for peer in peers.iter() {
                        let url = format!("{}/api/v1/internal/gossip", peer.trim_end_matches('/'));
                        let body = payload.clone();
                        let client = client.clone();
                        let peer_for_log = peer.clone();
                        let signature = signature.clone();
                        joins.push(tokio::spawn(async move {
                            let mut req = client
                                .post(&url)
                                .header("content-type", "application/json")
                                .header(gossip_auth::TIMESTAMP_HEADER, timestamp.to_string());
                            if let Some(sig) = signature.as_ref() {
                                req = req.header(gossip_auth::SIGNATURE_HEADER, sig);
                            }
                            match req.body(body).send().await {
                                Ok(resp) if resp.status().is_success() => {
                                    debug!(peer = %peer_for_log, "gossip: peer accepted event");
                                }
                                Ok(resp) => {
                                    warn!(
                                        peer = %peer_for_log,
                                        status = %resp.status(),
                                        "gossip: peer rejected event"
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        peer = %peer_for_log,
                                        error = %e,
                                        "gossip: peer unreachable; dropping event"
                                    );
                                }
                            }
                        }));
                    }
                    for j in joins {
                        let _ = j.await;
                    }
                });
            }
        });

        Self { tx }
    }
}

impl GossipSink for HttpGossipSink {
    fn publish(&self, event: SessionGossipEvent) {
        // Unbounded channel; only drops if the runtime has shut down
        // (receiver gone). At that point the coordinator is already
        // tearing down so dropping the event is fine.
        if self.tx.send(event).is_err() {
            warn!("gossip: drain task gone, dropping event");
        }
    }
}

//! Production `BondLedger` impl backed by a remote ghost-pay HTTP
//! endpoint.
//!
//! This is the client side of phase C. The matching server-side
//! endpoints live in `bins/ghost-pay/` and are added as a follow-on;
//! this module defines the wire contract so both sides can be
//! written and tested in parallel.
//!
//! ## Wire contract
//!
//! All endpoints sit under `<base_url>/api/v1/wraith/bond/`. JSON in,
//! JSON out. Authentication is HTTP Bearer (rotating token issued
//! by the coordinator's operator and stored in ghost-pay's auth
//! table). 4xx maps onto specific `BondError` variants; 5xx /
//! transport failures map onto `BondError::LedgerUnreachable`.
//!
//! ### POST /api/v1/wraith/bond/verify
//! ```text
//! request:  { ghost_id, session_id, expected_sats }
//! reply:    { bond_id }
//! errors:   404 "not_bonded"     → BondError::NotBonded
//!           409 "amount_mismatch" with { actual_sats } in detail
//!                                 → BondError::AmountMismatch
//!           503 "ledger_unreachable" → BondError::LedgerUnreachable
//! ```
//!
//! ### POST /api/v1/wraith/bond/resolve
//! ```text
//! request:  { bond_id, resolution }   // see BondResolution serde shape
//! reply:    { bond_id, ghost_id, session_id, amount_sats, status }
//!                                     // BondRecord serde shape
//! errors:   409 "already_resolved"    → BondError::AlreadyResolved
//!           404 "not_found"           → BondError::Other("...")
//! ```
//!
//! ### GET /api/v1/wraith/bond/{bond_id}
//! ```text
//! reply:    BondRecord JSON
//! errors:   404 "not_found"           → BondError::Other("...")
//! ```
//!
//! ## What this module is NOT
//!
//! - It is NOT a wraith-protocol-level concern. The protocol crate
//!   defines the `BondLedger` trait abstractly; this is one impl.
//!   Tests use `MockBondLedger`; production wires this; future
//!   variants (eg. threshold-signed bond proofs) drop in by
//!   implementing the same trait.
//!
//! - It does NOT itself talk to bitcoind. ghost-pay handles all the
//!   on-chain / L2 escrow accounting; this client just observes
//!   the result.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::debug;

use wraith_protocol::{BondError, BondId, BondLedger, BondRecord, BondResolution};

/// Ghost-pay HTTP-backed BondLedger.
///
/// HTTP transport is `ureq` — pure-sync with no internal tokio
/// runtime. `reqwest::blocking` would panic on Drop inside the
/// surrounding axum/tokio runtime.
pub struct GhostPayBondLedger {
    base_url: String,
    /// Bearer auth token; sent as `Authorization: Bearer <token>` on
    /// every call. Rotating these is the operator's job (config
    /// reload + restart).
    auth_header: String,
    agent: ureq::Agent,
}

impl GhostPayBondLedger {
    /// Construct from a base URL + bearer token. URL is normalised
    /// to lose any trailing slash so subsequent path concatenation
    /// is unambiguous.
    pub fn new(base_url: impl Into<String>, bearer_token: &str) -> Result<Self, BondError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(15))
            .build();
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth_header: format!("Bearer {bearer_token}"),
            agent,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    ghost_id: &'a str,
    session_id: &'a str,
    expected_sats: u64,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    bond_id: String,
}

#[derive(Debug, Serialize)]
struct ResolveRequest<'a> {
    bond_id: &'a str,
    resolution: &'a BondResolution,
}

/// Server-side error envelope. Matches the shape every other
/// endpoint in this codebase uses (`{ error, detail }`); ghost-pay
/// returns this on any non-2xx.
#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: String,
    #[serde(default)]
    detail: String,
}

impl BondLedger for GhostPayBondLedger {
    fn verify_bond(
        &self,
        ghost_id: &str,
        session_id: &str,
        expected_sats: u64,
    ) -> Result<BondId, BondError> {
        let req = VerifyRequest {
            ghost_id,
            session_id,
            expected_sats,
        };
        debug!(
            ghost_id, session_id, expected_sats,
            "ghost-pay /verify_bond"
        );
        let body = serde_json::to_value(&req)
            .map_err(|e| BondError::Other(format!("verify: encode {e}")))?;
        let resp = self
            .agent
            .post(&self.url("/api/v1/wraith/bond/verify"))
            .set("Authorization", &self.auth_header)
            .send_json(body);
        match resp {
            Ok(r) => {
                let parsed: VerifyResponse = r
                    .into_json()
                    .map_err(|e| BondError::Other(format!("verify: parse {e}")))?;
                Ok(BondId::new(parsed.bond_id))
            }
            Err(ureq::Error::Status(_, response)) => {
                Err(decode_error_body(response, |env| match env.error.as_str() {
                    "not_bonded" => BondError::NotBonded {
                        ghost_id: ghost_id.into(),
                        session_id: session_id.into(),
                    },
                    "amount_mismatch" => BondError::AmountMismatch {
                        bond_id: BondId::new("unknown"),
                        expected_sats,
                        actual_sats: 0,
                    },
                    "ledger_unreachable" => BondError::LedgerUnreachable(env.detail),
                    other => BondError::Other(format!("{other}: {}", env.detail)),
                }))
            }
            Err(ureq::Error::Transport(t)) => Err(BondError::LedgerUnreachable(format!(
                "{:?}: {t}",
                t.kind()
            ))),
        }
    }

    fn resolve_bond(
        &self,
        bond_id: &BondId,
        resolution: BondResolution,
    ) -> Result<BondRecord, BondError> {
        let req = ResolveRequest {
            bond_id: bond_id.as_str(),
            resolution: &resolution,
        };
        debug!(%bond_id, ?resolution, "ghost-pay /resolve_bond");
        let body = serde_json::to_value(&req)
            .map_err(|e| BondError::Other(format!("resolve: encode {e}")))?;
        let resp = self
            .agent
            .post(&self.url("/api/v1/wraith/bond/resolve"))
            .set("Authorization", &self.auth_header)
            .send_json(body);
        match resp {
            Ok(r) => r
                .into_json::<BondRecord>()
                .map_err(|e| BondError::Other(format!("resolve: parse {e}"))),
            Err(ureq::Error::Status(_, response)) => Err(decode_error_body(response, |env| {
                match env.error.as_str() {
                    "already_resolved" => BondError::AlreadyResolved {
                        bond_id: bond_id.clone(),
                    },
                    "not_found" => BondError::Other(format!("bond {bond_id} not found")),
                    "ledger_unreachable" => BondError::LedgerUnreachable(env.detail),
                    other => BondError::Other(format!("{other}: {}", env.detail)),
                }
            })),
            Err(ureq::Error::Transport(t)) => Err(BondError::LedgerUnreachable(format!(
                "{:?}: {t}",
                t.kind()
            ))),
        }
    }

    fn snapshot_bond(&self, bond_id: &BondId) -> Result<BondRecord, BondError> {
        debug!(%bond_id, "ghost-pay /snapshot_bond");
        let resp = self
            .agent
            .get(&self.url(&format!("/api/v1/wraith/bond/{bond_id}")))
            .set("Authorization", &self.auth_header)
            .call();
        match resp {
            Ok(r) => r
                .into_json::<BondRecord>()
                .map_err(|e| BondError::Other(format!("snapshot: parse {e}"))),
            Err(ureq::Error::Status(_, response)) => Err(decode_error_body(response, |env| {
                match env.error.as_str() {
                    "not_found" => BondError::Other(format!("bond {bond_id} not found")),
                    "ledger_unreachable" => BondError::LedgerUnreachable(env.detail),
                    other => BondError::Other(format!("{other}: {}", env.detail)),
                }
            })),
            Err(ureq::Error::Transport(t)) => Err(BondError::LedgerUnreachable(format!(
                "{:?}: {t}",
                t.kind()
            ))),
        }
    }
}

fn decode_error_body<F>(response: ureq::Response, f: F) -> BondError
where
    F: FnOnce(ErrorEnvelope) -> BondError,
{
    let status = response.status();
    match response.into_json::<ErrorEnvelope>() {
        Ok(env) => f(env),
        Err(e) => BondError::Other(format!(
            "{status}: response body did not match {{error,detail}}: {e}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;

    /// Tiny one-shot HTTP/1.1 server. Same pattern as the broadcaster
    /// tests — drops complexity for unblockedness.
    fn one_shot(reply_status: u16, reply_body: serde_json::Value) -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body = read_request(&stream);
            let body_str = reply_body.to_string();
            let resp = format!(
                "HTTP/1.1 {} OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                reply_status,
                body_str.len(),
                body_str
            );
            stream.write_all(resp.as_bytes()).unwrap();
            body
        });
        (url, handle)
    }

    fn read_request(stream: &TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut content_length: usize = 0;
        let mut method_path = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if method_path.is_empty() {
                method_path = line.trim().to_string();
            }
            let lower = line.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("content-length:") {
                content_length = rest.trim().parse().unwrap_or(0);
            }
        }
        if content_length == 0 {
            return method_path;
        }
        let mut body = vec![0u8; content_length];
        std::io::Read::read_exact(&mut reader, &mut body).unwrap();
        format!("{method_path} {}", String::from_utf8(body).unwrap())
    }

    #[test]
    fn verify_bond_returns_bond_id_on_success() {
        let (url, server) = one_shot(
            200,
            serde_json::json!({ "bond_id": "ghost-pay-bond-abc" }),
        );
        let ledger = GhostPayBondLedger::new(url, "tok").unwrap();
        let id = ledger
            .verify_bond("wallet-x", "session-y", 500)
            .expect("verify ok");
        assert_eq!(id.as_str(), "ghost-pay-bond-abc");
        let req = server.join().unwrap();
        assert!(req.contains("/api/v1/wraith/bond/verify"));
        assert!(req.contains("wallet-x"));
        assert!(req.contains("session-y"));
        assert!(req.contains("500"));
    }

    #[test]
    fn verify_bond_maps_404_not_bonded_to_NotBonded() {
        let (url, server) = one_shot(
            404,
            serde_json::json!({ "error": "not_bonded", "detail": "" }),
        );
        let ledger = GhostPayBondLedger::new(url, "tok").unwrap();
        let err = ledger.verify_bond("wx", "sy", 500).unwrap_err();
        match err {
            BondError::NotBonded { ghost_id, session_id } => {
                assert_eq!(ghost_id, "wx");
                assert_eq!(session_id, "sy");
            }
            other => panic!("expected NotBonded; got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn verify_bond_maps_409_amount_mismatch() {
        let (url, server) = one_shot(
            409,
            serde_json::json!({ "error": "amount_mismatch", "detail": "actual=499" }),
        );
        let ledger = GhostPayBondLedger::new(url, "tok").unwrap();
        let err = ledger.verify_bond("wx", "sy", 500).unwrap_err();
        match err {
            BondError::AmountMismatch { expected_sats, .. } => {
                assert_eq!(expected_sats, 500);
            }
            other => panic!("expected AmountMismatch; got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn verify_bond_maps_transport_error_to_LedgerUnreachable() {
        // 127.0.0.1:1 — reserved-low, refuses immediately.
        let ledger = GhostPayBondLedger::new("http://127.0.0.1:1", "tok").unwrap();
        let err = ledger.verify_bond("a", "b", 1).unwrap_err();
        match err {
            BondError::LedgerUnreachable(_) => {}
            other => panic!("expected LedgerUnreachable; got {other:?}"),
        }
    }
}

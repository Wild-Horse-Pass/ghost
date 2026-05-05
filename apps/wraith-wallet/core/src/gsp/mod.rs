//! GSP client (REST + WebSocket).
//!
//! Phase 1: WebSocket Ping/Pong probe + REST registration / session creation +
//! long-lived authenticated session task (`session` submodule).
//!
//! Reuses message types from `ghost-gsp-proto` so the wire format stays in sync with the server.

pub mod session;
pub use session::{spawn_session, BalanceSnapshot, SessionHandle, SessionPhase, SessionStatus};

use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use ghost_gsp_proto::{
    ClientMessage, RegisterRequest, RegisterResponse, ServerMessage, SessionRequest,
    SessionResponse, SessionToken, WalletId, WalletProof,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Debug, thiserror::Error)]
pub enum GspError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("server returned unexpected message: {0}")]
    Unexpected(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("server returned error: {0}")]
    Server(String),
    #[error("missing field in response: {0}")]
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResult {
    /// GSP server's wall-clock at response time (unix milliseconds).
    pub server_time: i64,
    /// Round-trip time in milliseconds, if the server echoed our timestamp.
    pub round_trip_ms: Option<i64>,
}

pub struct GspClient {
    ws_url: String,
    /// HTTP base URL derived from `ws_url`. e.g. `ws://host:port/ws/v1` → `http://host:port`.
    http_base: String,
    http: reqwest::Client,
}

impl GspClient {
    pub fn new(ws_url: impl Into<String>) -> Self {
        let ws = ws_url.into();
        let http_base = derive_http_base(&ws);
        Self {
            ws_url: ws,
            http_base,
            http: reqwest::Client::new(),
        }
    }

    /// Open a WebSocket, send `Ping`, wait for `Pong`, close. Single-shot.
    ///
    /// For plain `ws://` this works directly. For `wss://` against a real cert
    /// it works too. For `wss://` against a self-signed dev cert, run the GSP
    /// with `--insecure-http` so the wallet can use plain `ws://`.
    pub async fn ping(&self) -> Result<PingResult, GspError> {
        let (mut ws, _) = connect_async(&self.ws_url)
            .await
            .map_err(|e| GspError::Transport(e.to_string()))?;

        let sent_ts = now_unix_ms();
        let request = ClientMessage::Ping {
            timestamp: Some(sent_ts),
        };
        let payload = serde_json::to_string(&request)
            .map_err(|e| GspError::Encoding(e.to_string()))?;

        ws.send(Message::Text(payload.into()))
            .await
            .map_err(|e| GspError::Transport(e.to_string()))?;

        loop {
            let frame = ws
                .next()
                .await
                .ok_or_else(|| GspError::Transport("connection closed before Pong".into()))?
                .map_err(|e| GspError::Transport(e.to_string()))?;

            let text = match frame {
                Message::Text(t) => t,
                Message::Close(_) => {
                    return Err(GspError::Transport("server closed before Pong".into()));
                }
                _ => continue,
            };

            let parsed: ServerMessage = serde_json::from_str(text.as_ref())
                .map_err(|e| GspError::Encoding(e.to_string()))?;

            if let ServerMessage::Pong {
                timestamp: echoed,
                server_time,
            } = parsed
            {
                let _ = ws.close(None).await;
                let round_trip_ms = echoed.map(|_| (now_unix_ms() - sent_ts).max(0));
                return Ok(PingResult {
                    server_time,
                    round_trip_ms,
                });
            }

            return Err(GspError::Unexpected(format!("{parsed:?}")));
        }
    }

    /// `POST /api/v1/register` — register the wallet identified by the proof's pubkey.
    pub async fn register(
        &self,
        proof: WalletProof,
        display_name: Option<String>,
    ) -> Result<WalletId, GspError> {
        let url = format!("{}/api/v1/register", self.http_base);
        let body = RegisterRequest {
            proof,
            display_name,
        };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| GspError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GspError::Encoding(e.to_string()))?;
        if !status.is_success() {
            return Err(GspError::Server(extract_error(&text, status)));
        }
        let body: RegisterResponse = serde_json::from_str(&text)
            .map_err(|e| GspError::Encoding(e.to_string()))?;
        if !body.success {
            return Err(GspError::Server(body.error.unwrap_or_else(|| {
                format!("register failed with status {status}")
            })));
        }
        body.wallet_id.ok_or(GspError::MissingField("wallet_id"))
    }

    /// `POST /api/v1/session` — create a session, returning the JWT.
    pub async fn create_session(
        &self,
        proof: WalletProof,
        session_nonce: Option<String>,
    ) -> Result<SessionToken, GspError> {
        let url = format!("{}/api/v1/session", self.http_base);
        let body = SessionRequest {
            proof,
            session_nonce,
        };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| GspError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GspError::Encoding(e.to_string()))?;
        if !status.is_success() {
            return Err(GspError::Server(extract_error(&text, status)));
        }
        let body: SessionResponse = serde_json::from_str(&text)
            .map_err(|e| GspError::Encoding(e.to_string()))?;
        if !body.success {
            return Err(GspError::Server(body.error.unwrap_or_else(|| {
                format!("session failed with status {status}")
            })));
        }
        body.token.ok_or(GspError::MissingField("token"))
    }
}

/// Pull a useful message out of an error response. Handles both
/// the structured `{"error": {"code", "message"}, "success": false}` shape
/// the GSP returns on 4xx, and any unstructured plaintext fallback.
fn extract_error(text: &str, status: reqwest::StatusCode) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(msg) = v.pointer("/error/message").and_then(|m| m.as_str()) {
            return msg.to_string();
        }
        if let Some(code) = v.pointer("/error/code").and_then(|c| c.as_str()) {
            return code.to_string();
        }
        if let Some(s) = v.pointer("/error").and_then(|m| m.as_str()) {
            return s.to_string();
        }
    }
    if text.is_empty() {
        format!("status {status}")
    } else {
        format!("status {status}: {text}")
    }
}

fn derive_http_base(ws_url: &str) -> String {
    let (scheme, rest) = if let Some(r) = ws_url.strip_prefix("wss://") {
        ("https", r)
    } else if let Some(r) = ws_url.strip_prefix("ws://") {
        ("http", r)
    } else {
        // Already an http(s) URL? trim any trailing path.
        let r = ws_url.trim_start_matches("http://").trim_start_matches("https://");
        let s = if ws_url.starts_with("https://") { "https" } else { "http" };
        (s, r)
    };
    let host_and_port = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{host_and_port}")
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_http_base_strips_path() {
        assert_eq!(derive_http_base("ws://127.0.0.1:8900/ws/v1"), "http://127.0.0.1:8900");
        assert_eq!(derive_http_base("wss://gsp.example.com/ws/v1"), "https://gsp.example.com");
        assert_eq!(derive_http_base("ws://localhost:9000"), "http://localhost:9000");
    }
}

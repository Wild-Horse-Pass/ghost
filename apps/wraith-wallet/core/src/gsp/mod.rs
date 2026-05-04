//! GSP WebSocket client.
//!
//! Phase 1 first WS slice: connectivity probe via `Ping`/`Pong` round-trip.
//! Auth (`Authenticate` with JWT), subscriptions, and persistent sessions land in subsequent commits.
//!
//! Reuses message types from `ghost-gsp-proto` so the wire format stays in sync with the server.

use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use ghost_gsp_proto::{ClientMessage, ServerMessage};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Debug, thiserror::Error)]
pub enum GspError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("server returned unexpected message: {0}")]
    Unexpected(String),
    #[error("encoding error: {0}")]
    Encoding(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResult {
    /// GSP server's wall-clock at response time (unix milliseconds).
    pub server_time: i64,
    /// Round-trip time in milliseconds, if the server echoed our timestamp.
    pub round_trip_ms: Option<i64>,
}

pub struct GspClient {
    url: String,
}

impl GspClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Open a WebSocket, send `Ping`, wait for `Pong`, close. Single-shot.
    pub async fn ping(&self) -> Result<PingResult, GspError> {
        let (mut ws, _) = connect_async(&self.url)
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

        // Drain messages until we see a Pong. GSP may push unsolicited frames
        // (e.g. errors before auth) — ignore those and keep reading for the Pong.
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

            // Anything else (Error, AuthResult, push notifications) is unexpected
            // for an unauth'd ping flow — log via error and surface.
            return Err(GspError::Unexpected(format!("{parsed:?}")));
        }
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

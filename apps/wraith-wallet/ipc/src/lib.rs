//! Wraith Wallet — IPC types shared between `wraithd` and clients (CLI, GUI).
//!
//! Wire format: newline-delimited JSON-RPC 2.0. One request per line, one response per line.
//!
//! Methods are typed: each `Request::*` variant pairs with a `Response::*` variant of the same name.

use serde::{Deserialize, Serialize};

pub const JSONRPC_VERSION: &str = "2.0";

/// Default socket path discovery.
///
/// On Unix: `${XDG_RUNTIME_DIR:-/tmp}/wraithd-${UID}.sock`.
#[cfg(unix)]
pub fn default_socket_path() -> std::path::PathBuf {
    use std::path::PathBuf;
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let uid = unsafe { libc::getuid() };
    dir.join(format!("wraithd-{uid}.sock"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Health,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Health(HealthResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub daemon_version: String,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(flatten)]
    pub payload: T,
}

impl<T> Envelope<T> {
    pub fn new(id: u64, payload: T) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            payload,
        }
    }
}

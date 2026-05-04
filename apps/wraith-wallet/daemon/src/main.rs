//! `wraithd` — Wraith Wallet daemon.
//!
//! Long-running process that holds module state and exposes a local IPC surface
//! to the CLI and GUI. Phase 0: accepts JSON-RPC over a Unix socket and answers
//! `health` requests. Real lifecycle (keystore unlock, module tasks, ghost-pay
//! client) lands in subsequent phases.

#[cfg(not(unix))]
fn main() {
    eprintln!("wraithd: only Unix-like platforms are supported in phase 0");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(unix::serve())
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use wraith_wallet_ipc::{
        default_socket_path, Envelope, ErrorResponse, HealthResponse, Request, Response,
    };

    pub async fn serve() -> std::io::Result<()> {
        let socket_path = default_socket_path();
        let started = Instant::now();

        // Remove stale socket file if present.
        if socket_path.exists() {
            tracing::warn!(
                path = %socket_path.display(),
                "stale socket file present, removing"
            );
            fs::remove_file(&socket_path)?;
        }

        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        // Restrict socket to owner only.
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

        tracing::info!(path = %socket_path.display(), "wraithd listening");

        loop {
            let (stream, _) = listener.accept().await?;
            tokio::spawn(handle_connection(stream, started));
        }
    }

    async fn handle_connection(stream: UnixStream, started: Instant) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let response = dispatch(&line, started);
            let mut out = match serde_json::to_string(&response) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e, "failed to serialise response");
                    continue;
                }
            };
            out.push('\n');
            if let Err(e) = writer.write_all(out.as_bytes()).await {
                tracing::warn!(?e, "client write failed");
                return;
            }
        }
    }

    fn dispatch(line: &str, started: Instant) -> Envelope<Response> {
        let parsed: Result<Envelope<Request>, _> = serde_json::from_str(line);
        let (id, request) = match parsed {
            Ok(env) => (env.id, env.payload),
            Err(e) => {
                return Envelope::new(
                    0,
                    Response::Error(ErrorResponse {
                        message: format!("malformed request: {e}"),
                    }),
                );
            }
        };

        let response = match request {
            Request::Health => Response::Health(HealthResponse {
                daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: started.elapsed().as_secs(),
            }),
        };

        Envelope::new(id, response)
    }
}

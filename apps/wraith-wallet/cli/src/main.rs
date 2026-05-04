//! `wraith` — Wraith Wallet CLI.
//!
//! Thin client that speaks JSON-RPC to a running `wraithd` over a local Unix socket.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Wraith Wallet CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Round-trip a health request to wraithd.
    Health,
    /// Chain backend (ghost-pay) commands.
    Chain {
        #[command(subcommand)]
        sub: ChainCommand,
    },
}

#[derive(Subcommand)]
enum ChainCommand {
    /// Query ghost-pay's `/api/v1/status` via wraithd.
    Status,
}

#[cfg(not(unix))]
fn main() {
    eprintln!("wraith: only Unix-like platforms are supported in phase 0");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wraith: failed to start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(unix::run(cli.command))
}

#[cfg(unix)]
mod unix {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use wraith_wallet_ipc::{default_socket_path, Envelope, Request, Response};

    use crate::{ChainCommand, Command};

    pub async fn run(command: Command) -> std::process::ExitCode {
        let request = match command {
            Command::Health => Request::Health,
            Command::Chain { sub } => match sub {
                ChainCommand::Status => Request::ChainStatus,
            },
        };

        match call(request).await {
            Ok(Response::Health(h)) => {
                println!(
                    "wraithd ok — version {} — uptime {}s",
                    h.daemon_version, h.uptime_secs
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::ChainStatus(s)) => {
                println!("ghost-pay {} ({})", s.backend_version, s.network);
                println!(
                    "  keys: {}   locks: {}   active sessions: {}",
                    if s.has_keys { "yes" } else { "no" },
                    s.lock_count,
                    s.active_sessions,
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::Error(e)) => {
                eprintln!("wraithd error: {}", e.message);
                std::process::ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("wraith: {e}");
                std::process::ExitCode::FAILURE
            }
        }
    }

    async fn call(request: Request) -> Result<Response, String> {
        let socket = default_socket_path();
        let stream = UnixStream::connect(&socket).await.map_err(|e| {
            format!(
                "could not connect to wraithd at {}: {e} \
                 (is the daemon running?)",
                socket.display()
            )
        })?;
        let (reader, mut writer) = stream.into_split();
        let mut line = serde_json::to_string(&Envelope::new(1, request))
            .map_err(|e| format!("failed to serialise request: {e}"))?;
        line.push('\n');
        writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        writer
            .shutdown()
            .await
            .map_err(|e| format!("shutdown failed: {e}"))?;
        let mut response_line = String::new();
        BufReader::new(reader)
            .read_line(&mut response_line)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        let envelope: Envelope<Response> = serde_json::from_str(&response_line)
            .map_err(|e| format!("malformed response: {e}"))?;
        Ok(envelope.payload)
    }
}

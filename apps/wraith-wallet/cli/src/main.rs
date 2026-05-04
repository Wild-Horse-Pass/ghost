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
    /// GSP WebSocket commands.
    Gsp {
        #[command(subcommand)]
        sub: GspCommand,
    },
    /// Wallet (keystore) commands.
    Wallet {
        #[command(subcommand)]
        sub: WalletCommand,
    },
    /// Light wallet commands (on-chain address derivation, balance, send/receive).
    Light {
        #[command(subcommand)]
        sub: LightCommand,
    },
}

#[derive(Subcommand)]
enum ChainCommand {
    /// Query ghost-pay's `/api/v1/status` via wraithd.
    Status,
}

#[derive(Subcommand)]
enum GspCommand {
    /// Open a WebSocket to GSP, send Ping, wait for Pong.
    Ping,
}

#[derive(Subcommand)]
enum LightCommand {
    /// Derive a fresh BIP86 taproot receive address.
    Receive {
        /// Address index. Default: 0 (first receive address).
        #[arg(short, long, default_value_t = 0)]
        index: u32,
    },
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Create a fresh wallet (generates a new 24-word BIP39 mnemonic).
    Create,
    /// Unlock the wallet on disk by passphrase.
    Unlock,
    /// Drop the unlocked keystore from daemon memory.
    Lock,
    /// Show whether a wallet is unlocked and its on-disk path.
    Status,
    /// Derive a public key at a BIP32 path from the unlocked wallet.
    Derive {
        /// BIP32 derivation path, e.g. `m/86'/531'/0'/0/0`.
        path: String,
    },
    /// Show the GSP authentication identity (wallet_id + auth pubkey).
    AuthInfo,
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

    use crate::{ChainCommand, Command, GspCommand, LightCommand, WalletCommand};

    pub async fn run(command: Command) -> std::process::ExitCode {
        let request = match command {
            Command::Health => Request::Health,
            Command::Chain { sub } => match sub {
                ChainCommand::Status => Request::ChainStatus,
            },
            Command::Gsp { sub } => match sub {
                GspCommand::Ping => Request::GspPing,
            },
            Command::Wallet { sub } => match sub {
                WalletCommand::Create => match prompt_new_passphrase() {
                    Ok(pass) => Request::WalletCreate { passphrase: pass },
                    Err(e) => {
                        eprintln!("wraith: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                },
                WalletCommand::Unlock => match prompt_passphrase("passphrase: ") {
                    Ok(pass) => Request::WalletUnlock { passphrase: pass },
                    Err(e) => {
                        eprintln!("wraith: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                },
                WalletCommand::Lock => Request::WalletLock,
                WalletCommand::Status => Request::WalletStatus,
                WalletCommand::Derive { path } => Request::WalletDerive { path },
                WalletCommand::AuthInfo => Request::WalletAuthInfo,
            },
            Command::Light { sub } => match sub {
                LightCommand::Receive { index } => Request::LightReceive { index },
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
            Ok(Response::GspPing(p)) => {
                match p.round_trip_ms {
                    Some(rtt) => println!(
                        "gsp ok — server_time {} — round-trip {}ms",
                        p.server_time, rtt
                    ),
                    None => println!("gsp ok — server_time {}", p.server_time),
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletCreate(c)) => {
                println!("wallet created at {}", c.path);
                println!("\nWrite these 24 words down somewhere safe.");
                println!("They are the ONLY way to recover this wallet if the file is lost.\n");
                println!("{}\n", c.mnemonic);
                println!("Wallet is unlocked.");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletUnlocked) => {
                println!("wallet unlocked");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletLocked) => {
                println!("wallet locked");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletStatus(s)) => {
                println!("wallet path: {}", s.path);
                println!(
                    "  on disk:  {}",
                    if s.exists_on_disk { "yes" } else { "no" }
                );
                println!(
                    "  unlocked: {}",
                    if s.unlocked { "yes" } else { "no" }
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletDerive(d)) => {
                println!("path:       {}", d.path);
                println!("public_key: {}", d.public_key_hex);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletAuthInfo(a)) => {
                println!("wallet_id:      {}", a.wallet_id);
                println!("auth_public_key: {}", a.auth_public_key_hex);
                println!("derivation:      {}", a.derivation_path);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightReceive(r)) => {
                println!("{}", r.address);
                println!("  index:   {}", r.index);
                println!("  network: {}", r.network);
                println!("  path:    {}", r.derivation_path);
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

    fn prompt_passphrase(prompt: &str) -> std::io::Result<String> {
        use std::io::{BufRead, IsTerminal};
        if std::io::stdin().is_terminal() {
            rpassword::prompt_password(prompt)
        } else {
            // Non-interactive (piped) — read one line from stdin without echoing.
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            Ok(line.trim_end_matches('\n').trim_end_matches('\r').to_string())
        }
    }

    fn prompt_new_passphrase() -> std::io::Result<String> {
        let pass = prompt_passphrase("new passphrase: ")?;
        if pass.is_empty() {
            return Err(std::io::Error::other("passphrase must not be empty"));
        }
        // In interactive mode, confirm. In piped mode skip the confirm
        // (one line in = one passphrase) — typical for scripted use.
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            let again = prompt_passphrase("repeat passphrase: ")?;
            if pass != again {
                return Err(std::io::Error::other("passphrases do not match"));
            }
        }
        Ok(pass)
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

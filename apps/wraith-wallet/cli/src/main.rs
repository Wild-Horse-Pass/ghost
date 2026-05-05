//! `wraith` — Wraith Wallet CLI.
//!
//! Thin client that speaks JSON-RPC to a running `wraithd` over a local Unix socket.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Wraith Wallet CLI", long_about = None)]
struct Cli {
    /// Print the response as JSON instead of human-readable output.
    /// Errors are printed as JSON too (`{"error": {"message": "..."}}`).
    #[arg(long, global = true)]
    json: bool,

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
    /// Ghost Locks (custody primitive) commands.
    Locks {
        #[command(subcommand)]
        sub: LocksCommand,
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
    /// Register the active wallet with GSP (idempotent) and create a session.
    Auth,
    /// Show the daemon's stored GSP session token.
    SessionStatus,
}

#[derive(Subcommand)]
enum LightCommand {
    /// Derive a fresh BIP86 taproot receive address from the active wallet.
    Receive {
        #[arg(short, long, default_value_t = 0)]
        index: u32,
    },
    /// Show the active wallet's last-known on-chain balance.
    Balance,
    /// List the active wallet's UTXOs.
    Utxos {
        /// Minimum number of confirmations. Default 1.
        #[arg(short = 'c', long, default_value_t = 1)]
        min_confirmations: u32,
    },
    /// Show the active wallet's transaction history.
    History {
        /// Maximum number of transactions to return.
        #[arg(short, long, default_value_t = 50)]
        limit: u32,
        /// Pagination offset.
        #[arg(short, long, default_value_t = 0)]
        offset: u32,
    },
}

#[derive(Subcommand)]
enum LocksCommand {
    /// List all Ghost Locks for the active wallet.
    List,
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Create a fresh wallet under the given name (generates a new BIP39 mnemonic).
    Create { name: String },
    /// Unlock the named wallet (becomes active).
    Unlock { name: String },
    /// Lock a wallet by name, or the active one if no name is given.
    Lock { name: Option<String> },
    /// List all on-disk wallets with unlocked / active status.
    List,
    /// Set the active wallet (must already be unlocked).
    Select { name: String },
    /// Show the active wallet's path and unlocked state.
    Status,
    /// Derive a public key at a BIP32 path from the active wallet.
    Derive { path: String },
    /// Show the GSP authentication identity (wallet_id + auth pubkey) of the active wallet.
    AuthInfo,
    /// Re-display the BIP39 mnemonic for a named wallet.
    ShowMnemonic { name: String },
}

#[cfg(not(unix))]
fn main() {
    eprintln!("wraith: only Unix-like platforms are supported in phase 0");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    // Restore default SIGPIPE so `wraith ... | head -1` exits cleanly instead of
    // panicking when the consumer closes the pipe early.
    // Safety: setting SIG_DFL is always sound; we do it before spawning threads.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wraith: failed to start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(unix::run(cli.command, cli.json))
}

#[cfg(unix)]
mod unix {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use wraith_wallet_ipc::{default_socket_path, Envelope, Request, Response};

    use crate::{
        ChainCommand, Command, GspCommand, LightCommand, LocksCommand, WalletCommand,
    };

    pub async fn run(command: Command, json: bool) -> std::process::ExitCode {
        let request = match command {
            Command::Health => Request::Health,
            Command::Chain { sub } => match sub {
                ChainCommand::Status => Request::ChainStatus,
            },
            Command::Gsp { sub } => match sub {
                GspCommand::Ping => Request::GspPing,
                GspCommand::Auth => Request::GspAuth,
                GspCommand::SessionStatus => Request::GspSessionStatus,
            },
            Command::Light { sub } => match sub {
                LightCommand::Receive { index } => Request::LightReceive { index },
                LightCommand::Balance => Request::LightBalance,
                LightCommand::Utxos { min_confirmations } => Request::LightUtxos {
                    min_confirmations,
                },
                LightCommand::History { limit, offset } => {
                    Request::LightHistory { limit, offset }
                }
            },
            Command::Locks { sub } => match sub {
                LocksCommand::List => Request::LocksList,
            },
            Command::Wallet { sub } => match sub {
                WalletCommand::Create { name } => match prompt_new_passphrase() {
                    Ok(pass) => Request::WalletCreate {
                        name,
                        passphrase: pass,
                    },
                    Err(e) => return io_err(e),
                },
                WalletCommand::Unlock { name } => match prompt_passphrase("passphrase: ") {
                    Ok(pass) => Request::WalletUnlock {
                        name,
                        passphrase: pass,
                    },
                    Err(e) => return io_err(e),
                },
                WalletCommand::Lock { name } => Request::WalletLock { name },
                WalletCommand::List => Request::WalletList,
                WalletCommand::Select { name } => Request::WalletSelect { name },
                WalletCommand::Status => Request::WalletStatus,
                WalletCommand::Derive { path } => Request::WalletDerive { path },
                WalletCommand::AuthInfo => Request::WalletAuthInfo,
                WalletCommand::ShowMnemonic { name } => match prompt_passphrase("passphrase: ") {
                    Ok(pass) => Request::WalletShowMnemonic {
                        name,
                        passphrase: pass,
                    },
                    Err(e) => return io_err(e),
                },
            },
        };

        let result = call(request).await;

        // --json: emit the full Response (or a synthesized {"error": {...}} on
        // transport failure) and exit. SUCCESS for any non-Error variant,
        // FAILURE for Error / transport problems.
        if json {
            return print_json(&result);
        }

        match result {
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
            Ok(Response::GspAuth(a)) => {
                if a.already_registered {
                    println!("(already registered) — session created");
                } else {
                    println!("registered + session created");
                }
                println!("  wallet_id:    {}", a.wallet_id);
                println!("  token (prefix): {}...", a.token_prefix);
                println!("  expires_at:   {}", a.expires_at);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GspSessionStatus(s)) => {
                if !s.have_token {
                    println!("(no session — run `wraith gsp auth`)");
                } else {
                    println!("session active");
                    if let Some(n) = s.wallet_name {
                        println!("  wallet:        {n}");
                    }
                    if let Some(id) = s.wallet_id {
                        println!("  wallet_id:     {id}");
                    }
                    if let Some(p) = s.phase {
                        let cnt = s.connect_count.unwrap_or(0);
                        println!("  ws phase:      {p} (connects: {cnt})");
                    }
                    if let Some(err) = s.last_error {
                        println!("  last error:    {err}");
                    }
                    if let Some(rem) = s.remaining_secs {
                        let hours = rem / 3600;
                        let mins = (rem % 3600) / 60;
                        println!("  expires in:    {hours}h {mins}m ({rem}s)");
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightUtxos(u)) => {
                if u.utxos.is_empty() {
                    println!("(no utxos)");
                } else {
                    for x in &u.utxos {
                        let spendable = if x.spendable { " " } else { " *" };
                        println!(
                            "{}:{}  {} sats  ({} confs, {}){}",
                            x.txid, x.vout, x.amount_sats, x.confirmations, x.script_type,
                            spendable
                        );
                    }
                    println!("\ntotal: {} sats ({} utxos)", u.total_sats, u.utxos.len());
                    if u.utxos.iter().any(|x| !x.spendable) {
                        println!("  * = not currently spendable");
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightHistory(h)) => {
                if h.transactions.is_empty() {
                    println!("(no transactions)");
                } else {
                    for t in &h.transactions {
                        let dir = if t.amount_sats >= 0 { "+" } else { "" };
                        let height = t
                            .block_height
                            .map(|h| h.to_string())
                            .unwrap_or_else(|| "(mempool)".into());
                        let memo = t.memo.as_deref().unwrap_or("");
                        println!(
                            "{}  {dir}{}  {}  height {}  ({} confs){}",
                            t.txid,
                            t.amount_sats,
                            t.tx_type,
                            height,
                            t.confirmations,
                            if memo.is_empty() {
                                String::new()
                            } else {
                                format!("  — {memo}")
                            }
                        );
                    }
                    println!(
                        "\n{} of {} transactions",
                        h.transactions.len(),
                        h.total_count
                    );
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LocksList(r)) => {
                if r.locks.is_empty() {
                    println!("(no locks)");
                } else {
                    for l in &r.locks {
                        println!(
                            "{}  {}  {} / {} sats  ({})",
                            &l.lock_id[..16.min(l.lock_id.len())],
                            l.status,
                            l.balance_sats,
                            l.capacity_sats,
                            l.denomination,
                        );
                        println!("  funding: {}", l.funding_address);
                        if let (Some(txid), Some(vout)) = (&l.funding_txid, l.funding_vout) {
                            println!("  outpoint: {txid}:{vout}");
                        }
                    }
                    println!(
                        "\n{} locks  total: {} sats",
                        r.locks.len(),
                        r.total_locked_sats
                    );
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightBalance(b)) => {
                match b.confirmed_sats {
                    None => println!("(balance not yet known — session still authenticating?)"),
                    Some(c) => {
                        println!("confirmed:   {c} sats");
                        if let Some(u) = b.unconfirmed_sats {
                            println!("unconfirmed: {u} sats");
                        }
                        if let Some(l) = b.locked_sats {
                            println!("locked:      {l} sats");
                        }
                        if let Some(t) = b.received_at {
                            println!("as of:       unix {t}");
                        }
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletCreate(c)) => {
                println!("wallet '{}' created at {}", c.name, c.path);
                println!("\nWrite these 24 words down somewhere safe.");
                println!("They are the ONLY way to recover this wallet if the file is lost.\n");
                println!("{}\n", c.mnemonic);
                println!("Wallet '{}' is unlocked and active.", c.name);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletUnlocked) => {
                println!("wallet unlocked and selected as active");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletLocked { name }) => {
                println!("wallet '{name}' locked");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletList(l)) => {
                if l.wallets.is_empty() {
                    println!("(no wallets)");
                } else {
                    for w in l.wallets {
                        let mark = if w.active {
                            "*"
                        } else if w.unlocked {
                            "+"
                        } else {
                            " "
                        };
                        println!("{mark} {} ({})", w.name, w.path);
                    }
                    println!("\n  * = active   + = unlocked");
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletSelected { name }) => {
                println!("active wallet is now '{name}'");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletStatus(s)) => {
                match s.active {
                    Some(n) => {
                        println!("active: {n}");
                        if let Some(p) = s.path {
                            println!("  path:     {p}");
                        }
                        println!(
                            "  unlocked: {}",
                            if s.unlocked { "yes" } else { "no" }
                        );
                    }
                    None => println!("(no active wallet)"),
                }
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
            Ok(Response::WalletShowMnemonic(m)) => {
                println!("WARNING: anyone with these 24 words owns the wallet.\n");
                println!("{}\n", m.mnemonic);
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

    fn io_err(e: std::io::Error) -> std::process::ExitCode {
        eprintln!("wraith: {e}");
        std::process::ExitCode::FAILURE
    }

    fn print_json(result: &Result<Response, String>) -> std::process::ExitCode {
        match result {
            Ok(resp) => {
                let s = serde_json::to_string(resp).unwrap_or_else(|e| {
                    format!("{{\"error\":{{\"message\":\"serialise: {e}\"}}}}")
                });
                println!("{s}");
                if matches!(resp, Response::Error(_)) {
                    std::process::ExitCode::FAILURE
                } else {
                    std::process::ExitCode::SUCCESS
                }
            }
            Err(e) => {
                let body = serde_json::json!({ "error": { "message": e } });
                println!("{body}");
                std::process::ExitCode::FAILURE
            }
        }
    }

    fn prompt_passphrase(prompt: &str) -> std::io::Result<String> {
        use std::io::{BufRead, IsTerminal};
        if std::io::stdin().is_terminal() {
            rpassword::prompt_password(prompt)
        } else {
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

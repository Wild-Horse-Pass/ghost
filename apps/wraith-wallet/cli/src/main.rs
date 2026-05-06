//! `wraith` — Wraith Wallet CLI.
//!
//! Thin client that speaks JSON-RPC to a running `wraithd` over a local Unix socket.

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser)]
#[command(version, about = "Wraith Wallet CLI", long_about = None)]
struct Cli {
    /// Print the response as JSON instead of human-readable output.
    /// Errors are printed as JSON too (`{"error": {"message": "..."}}`).
    #[arg(long, global = true)]
    json: bool,

    /// Don't auto-spawn `wraithd` if it isn't running. Fail with a
    /// "daemon not running" error instead.
    #[arg(long, global = true)]
    no_spawn: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Round-trip a health request to wraithd.
    Health,
    /// One-shot summary of daemon + ghost-pay + ghost-gsp + active wallet + session.
    Doctor,
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
    /// Print a shell-completion script to stdout. Pipe into your shell's
    /// completion location, e.g.:
    ///   wraith completions bash > /etc/bash_completion.d/wraith
    ///   wraith completions zsh  > ~/.zfunc/_wraith    # add ~/.zfunc to fpath
    ///   wraith completions fish > ~/.config/fish/completions/wraith.fish
    Completions {
        /// Target shell.
        shell: Shell,
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
    /// Register the active wallet's BIP-352 scan public key with the GSP so the
    /// server can detect incoming silent payments on its behalf.
    RegisterScanKey,
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
    /// Show BIP-352 silent-payment matches detected by the persistent
    /// session's local scanner since `wraith gsp auth` ran.
    Detected,
    /// Stream BIP-352 detections live as they arrive. Holds the connection
    /// open and prints each detection on a new line. Ctrl-C to exit.
    Watch,
    /// Show the active wallet's transaction history.
    History {
        /// Maximum number of transactions to return.
        #[arg(short, long, default_value_t = 50)]
        limit: u32,
        /// Pagination offset.
        #[arg(short, long, default_value_t = 0)]
        offset: u32,
    },
    /// Send a payment. Mode is one of `ghostpay` (default), `wraith`, or `confidential`.
    Send {
        /// Recipient: a Bitcoin address or a Ghost ID.
        recipient: String,
        /// Amount in satoshis.
        amount_sats: u64,
        /// Payment mode.
        #[arg(long, default_value = "ghostpay")]
        mode: String,
        /// Optional memo, included with the payment metadata.
        #[arg(long)]
        memo: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocksCommand {
    /// List all Ghost Locks for the active wallet.
    List,
    /// Ask GSP to prepare a new ghost lock — returns a funding address.
    Prepare {
        /// Capacity of the lock in satoshis.
        capacity_sats: u64,
    },
    /// Confirm that a prepared lock has been funded on-chain.
    Confirm {
        lock_id: String,
        funding_txid: String,
    },
    /// Initiate a jump (key rotation) for an existing lock.
    Jump {
        lock_id: String,
        /// Target address for the new lock.
        target_address: String,
        /// Priority: normal (default), high, or urgent.
        #[arg(long, default_value = "normal")]
        priority: String,
    },
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Create a fresh wallet under the given name (generates a new BIP39 mnemonic).
    Create { name: String },
    /// Import a wallet from an existing BIP-39 mnemonic. Prompts for the words
    /// and a new passphrase. Refuses to overwrite an existing wallet of the
    /// same name.
    Import { name: String },
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
    /// Show the active wallet's BIP-352 Ghost ID (silent payment receive identity).
    GhostId,
    /// Re-display the BIP39 mnemonic for a named wallet.
    ShowMnemonic { name: String },
    /// Copy the encrypted keystore for `name` to a backup file.
    Export {
        name: String,
        /// Destination path for the backup. Refuses to overwrite existing files.
        to: String,
    },
    /// Install an encrypted keystore from a backup file as wallet `name`.
    Restore {
        name: String,
        /// Source path of the backup file.
        from: String,
    },
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

    // Short-circuit shell completions: don't spin up the runtime, don't try
    // to spawn or talk to wraithd. Just emit the script and exit.
    if let Command::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        // Hardcode "wraith" (the binary name we ship); clap defaults to the
        // package name (wraith-wallet-cli) which would generate completions
        // bound to the wrong word.
        clap_complete::generate(shell, &mut cmd, "wraith", &mut std::io::stdout());
        return std::process::ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wraith: failed to start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(unix::run(cli.command, cli.json, cli.no_spawn))
}

#[cfg(unix)]
mod unix {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use wraith_wallet_ipc::{default_socket_path, Envelope, Request, Response};

    use crate::{
        ChainCommand, Command, GspCommand, LightCommand, LocksCommand, WalletCommand,
    };

    pub async fn run(
        command: Command,
        json: bool,
        no_spawn: bool,
    ) -> std::process::ExitCode {
        // Make sure wraithd is up before constructing the request — the request
        // build for some subcommands (eg. wallet create) prompts for a passphrase,
        // and we want to fail fast on "no daemon" instead of after the user types it.
        if !no_spawn {
            if let Err(e) = ensure_daemon().await {
                if json {
                    let body = serde_json::json!({
                        "error": { "message": format!("auto-spawn: {e}") }
                    });
                    println!("{body}");
                } else {
                    eprintln!("wraith: auto-spawn failed: {e}");
                }
                return std::process::ExitCode::FAILURE;
            }
        }

        // Streaming subcommand: handed off to its own code path so we don't
        // try to render it as a single Response.
        if let Command::Light { sub: LightCommand::Watch } = &command {
            return run_watch(json).await;
        }

        let request = match command {
            Command::Health => Request::Health,
            Command::Doctor => Request::Doctor,
            Command::Chain { sub } => match sub {
                ChainCommand::Status => Request::ChainStatus,
            },
            Command::Gsp { sub } => match sub {
                GspCommand::Ping => Request::GspPing,
                GspCommand::Auth => Request::GspAuth,
                GspCommand::SessionStatus => Request::GspSessionStatus,
                GspCommand::RegisterScanKey => Request::GspRegisterScanKey,
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
                LightCommand::Detected => Request::LightDetected,
                LightCommand::Watch => unreachable!("Watch handled above"),
                LightCommand::Send {
                    recipient,
                    amount_sats,
                    mode,
                    memo,
                } => Request::LightSend {
                    recipient,
                    amount_sats,
                    mode,
                    memo,
                },
            },
            Command::Locks { sub } => match sub {
                LocksCommand::List => Request::LocksList,
                LocksCommand::Prepare { capacity_sats } => {
                    Request::LocksPrepare { capacity_sats }
                }
                LocksCommand::Confirm {
                    lock_id,
                    funding_txid,
                } => Request::LocksConfirm {
                    lock_id,
                    funding_txid,
                },
                LocksCommand::Jump {
                    lock_id,
                    target_address,
                    priority,
                } => Request::LocksJump {
                    lock_id,
                    target_address,
                    priority,
                },
            },
            Command::Wallet { sub } => match sub {
                WalletCommand::Create { name } => match prompt_new_passphrase() {
                    Ok(pass) => Request::WalletCreate {
                        name,
                        passphrase: pass,
                    },
                    Err(e) => return io_err(e),
                },
                WalletCommand::Import { name } => {
                    let mnemonic = match prompt_mnemonic() {
                        Ok(m) => m,
                        Err(e) => return io_err(e),
                    };
                    let pass = match prompt_new_passphrase() {
                        Ok(p) => p,
                        Err(e) => return io_err(e),
                    };
                    Request::WalletImport {
                        name,
                        mnemonic,
                        passphrase: pass,
                    }
                }
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
                WalletCommand::GhostId => Request::WalletGhostId,
                WalletCommand::ShowMnemonic { name } => match prompt_passphrase("passphrase: ") {
                    Ok(pass) => Request::WalletShowMnemonic {
                        name,
                        passphrase: pass,
                    },
                    Err(e) => return io_err(e),
                },
                WalletCommand::Export { name, to } => Request::WalletExport { name, to_path: to },
                WalletCommand::Restore { name, from } => {
                    Request::WalletRestore { name, from_path: from }
                }
            },
            // Handled in main() before we reach the runtime; the arm exists
            // here only so the match is exhaustive.
            Command::Completions { .. } => unreachable!("Completions handled in main"),
        };

        let result = call(request).await;

        // --json: emit the full Response (or a synthesized {"error": {...}} on
        // transport failure) and exit. SUCCESS for any non-Error variant,
        // FAILURE for Error / transport problems.
        if json {
            return print_json(&result);
        }

        match result {
            Ok(Response::Doctor(d)) => {
                for c in &d.checks {
                    let mark = match c.status.as_str() {
                        "pass" => "  ok ",
                        "fail" => "FAIL ",
                        "skip" => "skip ",
                        _ => "  ?  ",
                    };
                    println!("{mark} {:<14}  {}", c.name, c.detail);
                }
                println!();
                println!(
                    "{}",
                    if d.all_pass {
                        "all checks passed"
                    } else {
                        "one or more checks failed"
                    }
                );
                if d.all_pass {
                    std::process::ExitCode::SUCCESS
                } else {
                    std::process::ExitCode::FAILURE
                }
            }
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
            Ok(Response::GspScanKeyRegistered {
                wallet_id,
                scan_pubkey_hex,
            }) => {
                println!("scan key registered with GSP");
                println!("  wallet_id:   {wallet_id}");
                println!("  scan_pubkey: {scan_pubkey_hex}");
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
            Ok(Response::LightDetected(d)) => {
                if d.detections.is_empty() {
                    println!("(no detections — server scanner may not be wired yet,");
                    println!(" or no incoming silent payments since auth)");
                } else {
                    for det in &d.detections {
                        let amt = det
                            .amount_sats
                            .map(|a| format!("{a} sats"))
                            .unwrap_or_else(|| "?".into());
                        let height = det
                            .block_height
                            .map(|h| h.to_string())
                            .unwrap_or_else(|| "(mempool)".into());
                        println!(
                            "{}:{}  {amt}  k={}  height {height}",
                            det.txid, det.vout, det.k
                        );
                    }
                    println!("\n{} detection(s)", d.detections.len());
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
            Ok(Response::LightSent(s)) => {
                println!("payment submitted");
                println!("  payment_id: {}", s.payment_id);
                if let Some(tx) = &s.txid {
                    println!("  txid:       {tx}");
                } else {
                    println!("  txid:       (L2 — no on-chain txid)");
                }
                println!("  recipient:  {}", s.recipient);
                println!("  amount:     {} sats", s.amount_sats);
                println!("  fee:        {} sats", s.fee_sats);
                println!("  mode:       {}", s.mode);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LocksPrepared(r)) => {
                println!("lock prepared");
                println!("  lock_id:         {}", r.lock_id);
                println!("  funding address: {}", r.funding_address);
                println!("  required:        {} sats", r.required_sats);
                println!();
                println!("Send {} sats to the address above, then run:", r.required_sats);
                println!("  wraith locks confirm {} <funding_txid>", r.lock_id);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LocksConfirmed(r)) => {
                println!("lock confirmed");
                println!("  lock_id:      {}", r.lock_id);
                println!("  funding txid: {}", r.txid);
                println!("  block height: {}", r.block_height);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LocksJumped(r)) => {
                println!("jump initiated");
                println!("  lock_id:   {}", r.lock_id);
                match r.jump_txid {
                    Some(tx) => println!("  jump txid: {tx}"),
                    None => println!("  jump txid: (queued — not yet broadcast)"),
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
            Ok(Response::WalletImported { name, path }) => {
                println!("wallet '{name}' imported at {path}");
                println!("Wallet '{name}' is unlocked and active.");
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
            Ok(Response::WalletGhostId(g)) => {
                println!("{}", g.ghost_id);
                println!("  network: {}", g.network);
                println!("  scan_pubkey:  {}", g.scan_public_key_hex);
                println!("  spend_pubkey: {}", g.spend_public_key_hex);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletShowMnemonic(m)) => {
                println!("WARNING: anyone with these 24 words owns the wallet.\n");
                println!("{}\n", m.mnemonic);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletExported { name, path, bytes }) => {
                println!("exported wallet '{name}' → {path} ({bytes} bytes)");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletRestored { name, path, bytes }) => {
                println!("restored wallet '{name}' from backup → {path} ({bytes} bytes)");
                println!("run `wraith wallet unlock {name}` to use it");
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
            // Streaming variants are handled in run_watch() and never reach here.
            Ok(Response::Watching) | Ok(Response::PaymentDetected(_)) => {
                eprintln!("wraith: unexpected streaming variant on a one-shot request");
                std::process::ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("wraith: {e}");
                std::process::ExitCode::FAILURE
            }
        }
    }

    /// Connect to the wraithd socket; if absent, find `wraithd` next to ourselves
    /// and spawn it detached. Polls the socket up to ~3 s.
    async fn ensure_daemon() -> Result<(), String> {
        let socket = default_socket_path();

        // Fast path: already up.
        if UnixStream::connect(&socket).await.is_ok() {
            return Ok(());
        }

        // Find `wraithd` next to ourselves.
        let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let dir = me
            .parent()
            .ok_or_else(|| "current_exe has no parent dir".to_string())?;
        let daemon_bin = dir.join("wraithd");
        if !daemon_bin.is_file() {
            return Err(format!(
                "wraithd binary not found at {} (is it built?)",
                daemon_bin.display()
            ));
        }

        // Spawn detached. Stdin/out/err → /dev/null so the daemon doesn't keep our
        // terminal alive; environment is inherited so WRAITHD_* vars work.
        let mut cmd = std::process::Command::new(&daemon_bin);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        // Detach into a new session so SIGHUP from the controlling terminal
        // doesn't kill it when the user closes the shell.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        cmd.spawn()
            .map_err(|e| format!("spawn wraithd: {e}"))?;

        // Poll for the socket. ~3s budget at 60ms each.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            if UnixStream::connect(&socket).await.is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "wraithd did not bind {} within 3s",
            socket.display()
        ))
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

    /// Reads a BIP-39 mnemonic from stdin. We don't echo it (treat as secret),
    /// so it goes through rpassword on a TTY; on a pipe we just read a line.
    /// Whitespace is normalised to a single space so users can paste from any
    /// line wrapping.
    fn prompt_mnemonic() -> std::io::Result<String> {
        let raw = prompt_passphrase("mnemonic (12 or 24 words): ")?;
        let words: Vec<&str> = raw.split_whitespace().collect();
        if words.len() != 12 && words.len() != 24 {
            return Err(std::io::Error::other(format!(
                "expected 12 or 24 words, got {}",
                words.len()
            )));
        }
        Ok(words.join(" "))
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

    /// Streaming subscriber for `Request::WatchPayments`. Connects, sends the
    /// request, expects a `Response::Watching` ack, then prints each
    /// `Response::PaymentDetected` line until the daemon closes the stream
    /// (or the user hits Ctrl-C). With `--json`, every line is the raw
    /// envelope JSON exactly as the daemon emits it.
    pub(crate) async fn run_watch(json: bool) -> std::process::ExitCode {
        let socket = default_socket_path();
        let stream = match UnixStream::connect(&socket).await {
            Ok(s) => s,
            Err(e) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"error": {"message": format!("connect: {e}")}})
                    );
                } else {
                    eprintln!(
                        "wraith: could not connect to wraithd at {}: {e}",
                        socket.display()
                    );
                }
                return std::process::ExitCode::FAILURE;
            }
        };
        let (reader, mut writer) = stream.into_split();
        let req = Envelope::new(1, Request::WatchPayments);
        let mut line = match serde_json::to_string(&req) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("wraith: serialise: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        line.push('\n');
        if let Err(e) = writer.write_all(line.as_bytes()).await {
            eprintln!("wraith: write: {e}");
            return std::process::ExitCode::FAILURE;
        }
        let mut reader = BufReader::new(reader);
        if !json {
            eprintln!("wraith: watching for silent-payment detections (Ctrl-C to stop)");
        }
        loop {
            let mut buf = String::new();
            match reader.read_line(&mut buf).await {
                Ok(0) => return std::process::ExitCode::SUCCESS,
                Ok(_) => {
                    if json {
                        print!("{buf}");
                        continue;
                    }
                    let env: Envelope<Response> = match serde_json::from_str(&buf) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("wraith: malformed push: {e}; raw={buf}");
                            continue;
                        }
                    };
                    match env.payload {
                        Response::Watching => {} // ack — keep waiting
                        Response::PaymentDetected(d) => {
                            let height = d
                                .block_height
                                .map(|h| h.to_string())
                                .unwrap_or_else(|| "—".to_string());
                            let amt = d
                                .amount_sats
                                .map(|a| a.to_string())
                                .unwrap_or_else(|| "?".to_string());
                            println!(
                                "{} sat  height={}  vout={}  k={}  txid={}",
                                amt, height, d.vout, d.k, d.txid
                            );
                        }
                        Response::Error(e) => {
                            eprintln!("wraith: daemon error: {}", e.message);
                            return std::process::ExitCode::FAILURE;
                        }
                        other => {
                            eprintln!("wraith: unexpected push variant: {other:?}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("wraith: read: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            }
        }
    }
}

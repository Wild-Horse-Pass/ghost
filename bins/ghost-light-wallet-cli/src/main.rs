//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: bins/ghost-light-wallet-cli/main.rs                                                                            |
//|======================================================================================================================|

//! Ghost Light Wallet CLI
//!
//! A command-line interface for the Ghost Light Wallet.
//!
//! Features:
//! - Create and recover wallets from mnemonic
//! - Check balance and transaction history
//! - Send Ghost Pay and Wraith payments
//! - Manage Ghost Locks
//! - Connect to multiple GSPs
//!
//! Usage:
//! ```bash
//! # Create a new wallet
//! ghost-wallet init
//!
//! # Check balance
//! ghost-wallet balance
//!
//! # Send payment
//! ghost-wallet send <recipient> <amount>
//!
//! # Generate receive address
//! ghost-wallet receive
//!
//! # View transaction history
//! ghost-wallet history
//! ```

use std::path::{Path, PathBuf};

use anyhow::Result;
use bitcoin::Network;
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{Confirm, Input};
use indicatif::{ProgressBar, ProgressStyle};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use ghost_keys::LabelBackup;
use ghost_light_wallet::wraith::{WizardStep, WraithWizard};
use ghost_light_wallet::{LightWallet, WalletConfig};

/// Ghost Light Wallet CLI
#[derive(Parser, Debug)]
#[command(name = "ghost-wallet")]
#[command(author, version, about = "Ghost Light Wallet - Privacy-preserving Bitcoin wallet", long_about = None)]
struct Args {
    /// Data directory for wallet storage
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Network (mainnet, testnet, signet, regtest)
    #[arg(long, global = true, default_value = "regtest")]
    network: String,

    /// GSP URL to connect to
    #[arg(long, global = true)]
    gsp: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, global = true, default_value = "warn")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new wallet
    Init {
        /// Recover from existing mnemonic
        #[arg(long)]
        recover: bool,
    },

    /// Check wallet balance
    Balance {
        /// Force refresh from GSP
        #[arg(long)]
        refresh: bool,

        /// Maximum k value to scan for Silent Payment detection (default: 10)
        #[arg(long, default_value = "10")]
        max_k: u32,

        /// Enable recovery scanning (sets max_k to 1000)
        #[arg(long)]
        recovery: bool,
    },

    /// Send payment
    Send {
        /// Recipient address or Ghost ID
        recipient: String,

        /// Amount in satoshis
        amount: u64,

        /// Use Wraith protocol for mixing
        #[arg(long)]
        wraith: bool,

        /// Optional memo (max 59 chars, encrypted)
        #[arg(long)]
        memo: Option<String>,

        /// Label index for categorization
        #[arg(long)]
        label: Option<u32>,
    },

    /// Generate receive address
    Receive {
        /// Address type (ghost, silent, taproot)
        #[arg(long, default_value = "ghost")]
        address_type: String,

        /// Label for the address
        #[arg(long)]
        label: Option<String>,
    },

    /// View transaction history
    History {
        /// Number of transactions to show
        #[arg(long, default_value = "10")]
        limit: u32,
    },

    /// Manage Ghost Locks
    Lock {
        #[command(subcommand)]
        action: LockCommands,
    },

    /// Manage payment labels
    Label {
        #[command(subcommand)]
        action: LabelCommands,
    },

    /// Show wallet info
    Info,

    /// Unlock the wallet
    Unlock,

    /// Lock the wallet
    LockWallet,

    /// Export wallet backup
    Backup {
        /// Output file path
        output: PathBuf,
    },

    /// Interactive Wraith CoinJoin mixing wizard
    Wraith,
}

#[derive(Subcommand, Debug)]
enum LockCommands {
    /// Create a new Ghost Lock
    Create {
        /// Lock capacity in satoshis
        amount: u64,

        /// Label for the lock
        #[arg(long)]
        label: Option<String>,
    },

    /// List all Ghost Locks
    List,

    /// Request emergency jump from a lock
    Jump {
        /// Lock ID
        lock_id: String,

        /// Target address for the jump
        target: String,

        /// High priority (faster but higher fees)
        #[arg(long)]
        high_priority: bool,
    },
}

#[derive(Subcommand, Debug)]
enum LabelCommands {
    /// Create a new label
    Create {
        /// Label name
        name: String,
    },

    /// List all labels
    List,

    /// Rename a label
    Rename {
        /// Label index
        index: u32,
        /// New name
        name: String,
    },

    /// Delete a label
    Delete {
        /// Label index
        index: u32,
    },

    /// Export labels to file
    Export {
        /// Output file path
        output: PathBuf,
    },

    /// Import labels from file
    Import {
        /// Input file path
        input: PathBuf,
    },
}

fn get_default_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|p| p.join("ghost-wallet"))
        .unwrap_or_else(|| PathBuf::from("./ghost-wallet-data"))
}

fn parse_network(s: &str) -> Network {
    match s.to_lowercase().as_str() {
        "mainnet" | "main" | "bitcoin" => Network::Bitcoin,
        "testnet" | "test" => Network::Testnet,
        "signet" => Network::Signet,
        _ => Network::Regtest,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::WARN,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Parse configuration
    let data_dir = args.data_dir.unwrap_or_else(get_default_data_dir);
    let network = parse_network(&args.network);
    let gsp_urls = args
        .gsp
        .map(|url| vec![url])
        .unwrap_or_else(|| vec!["wss://localhost:8901/ws/v1".to_string()]);

    let config = WalletConfig {
        data_dir: data_dir.clone(),
        network,
        gsp_urls,
        auto_reconnect: true,
        reconnect_interval_secs: 5,
    };

    // Execute command
    match args.command {
        Commands::Init { recover } => {
            cmd_init(config, recover).await?;
        }
        Commands::Balance {
            refresh,
            max_k,
            recovery,
        } => {
            let effective_max_k = if recovery { 1000 } else { max_k };
            cmd_balance(config, refresh, effective_max_k).await?;
        }
        Commands::Send {
            recipient,
            amount,
            wraith,
            memo,
            label,
        } => {
            cmd_send(config, &recipient, amount, wraith, memo.as_deref(), label).await?;
        }
        Commands::Receive {
            address_type,
            label,
        } => {
            cmd_receive(config, &address_type, label.as_deref()).await?;
        }
        Commands::History { limit } => {
            cmd_history(config, limit).await?;
        }
        Commands::Lock { action } => {
            cmd_lock(config, action).await?;
        }
        Commands::Label { action } => {
            cmd_label(config, action).await?;
        }
        Commands::Info => {
            cmd_info(config).await?;
        }
        Commands::Unlock => {
            cmd_unlock(config).await?;
        }
        Commands::LockWallet => {
            cmd_lock_wallet(config).await?;
        }
        Commands::Backup { output } => {
            cmd_backup(config, &output).await?;
        }
        Commands::Wraith => {
            cmd_wraith(config).await?;
        }
    }

    Ok(())
}

// ============================================================================
// Command Implementations
// ============================================================================

async fn cmd_init(config: WalletConfig, recover: bool) -> Result<()> {
    println!("{}", style("Ghost Light Wallet Setup").bold().cyan());
    println!();

    // Check if wallet already exists
    let wallet_file = config.data_dir.join("wallet.db");
    if wallet_file.exists() {
        let overwrite = Confirm::new()
            .with_prompt("A wallet already exists. Overwrite?")
            .default(false)
            .interact()?;

        if !overwrite {
            println!("Aborted.");
            return Ok(());
        }

        std::fs::remove_file(&wallet_file)?;
    }

    let mnemonic = if recover {
        // Recover from mnemonic
        println!(
            "{}",
            style("Enter your 12 or 24 word recovery phrase:").bold()
        );
        let input: String = Input::new().with_prompt("Mnemonic").interact_text()?;
        input
    } else {
        // Generate new mnemonic
        println!("{}", style("Generating new wallet...").bold());
        let mnemonic = ghost_light_wallet::keys::MasterKey::generate_mnemonic()?;

        println!();
        println!(
            "{}",
            style("IMPORTANT: Write down these words and keep them safe!")
                .bold()
                .red()
        );
        println!("{}", style("This is your wallet recovery phrase:").yellow());
        println!();
        println!("  {}", style(mnemonic.to_string()).green());
        println!();

        // Confirm backup
        let confirmed = Confirm::new()
            .with_prompt("Have you written down your recovery phrase?")
            .default(false)
            .interact()?;

        if !confirmed {
            println!(
                "{}",
                style("Please write down your recovery phrase before continuing.").red()
            );
            return Ok(());
        }

        // Verify the user actually wrote it down by asking for 3 random words
        let mnemonic_str = mnemonic.to_string();
        let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
        let word_count = words.len();

        println!();
        println!(
            "{}",
            style("Verification: Enter the requested words from your recovery phrase.")
                .bold()
                .yellow()
        );
        println!();

        // Pick 3 unique random word positions using getrandom
        let verify_positions: Vec<usize> = {
            let mut rand_bytes = [0u8; 3];
            getrandom::getrandom(&mut rand_bytes).expect("failed to get random bytes");
            let mut positions = std::collections::BTreeSet::new();
            // Use modular arithmetic to pick unique positions
            positions.insert(rand_bytes[0] as usize % word_count);
            let mut idx = 1;
            while positions.len() < 3 {
                let pos = (rand_bytes[idx % 3] as usize + positions.len() * 7) % word_count;
                positions.insert(pos);
                idx += 1;
            }
            positions.into_iter().collect()
        };

        for &pos in &verify_positions {
            let prompt = format!("Word #{}", pos + 1);
            let input: String = Input::new().with_prompt(&prompt).interact_text()?;
            if input.trim() != words[pos] {
                println!();
                println!(
                    "{}",
                    style("Incorrect! Word does not match your recovery phrase.").red()
                );
                println!(
                    "{}",
                    style("Wallet creation aborted for your safety.").red()
                );
                return Ok(());
            }
        }

        println!();
        println!("{}", style("Verification passed!").bold().green());

        mnemonic_str
    };

    // Get password
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let password_confirm = rpassword::prompt_password("Confirm password: ")?;

    if password != password_confirm {
        println!("{}", style("Passwords do not match.").red());
        return Ok(());
    }

    if password.len() < 8 {
        println!("{}", style("Password must be at least 8 characters.").red());
        return Ok(());
    }

    // Create wallet with progress
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.set_message("Creating wallet...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let wallet = LightWallet::from_mnemonic(&mnemonic, &password, config)?;

    pb.finish_with_message("Wallet created!");

    println!();
    println!(
        "{}",
        style("Wallet initialized successfully!").bold().green()
    );
    println!();
    println!("Ghost ID: {}", style(wallet.ghost_id()?).cyan());
    println!("Network: {:?}", wallet.network());
    println!();
    println!(
        "Run {} to see your balance.",
        style("ghost-wallet balance").cyan()
    );

    Ok(())
}

async fn cmd_balance(config: WalletConfig, refresh: bool, max_k: u32) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;

    let wallet = LightWallet::open(&password, config)?;

    let balance = if refresh {
        // Connect to GSP and refresh
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
        if max_k > 10 {
            pb.set_message(format!(
                "Connecting to GSP (scanning with max_k={})...",
                max_k
            ));
        } else {
            pb.set_message("Connecting to GSP...");
        }
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        wallet.connect(&wallet.config().gsp_urls[0]).await?;
        // TODO: Pass max_k to wallet.refresh_balance() when API supports it
        let balance = wallet.refresh_balance().await?;

        pb.finish_and_clear();
        balance
    } else {
        // Use cached balance
        wallet.cached_balance().unwrap_or_default()
    };

    println!();
    println!("{}", style("Wallet Balance").bold().cyan());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "Confirmed:   {} sats",
        style(format!("{:>15}", balance.confirmed)).green()
    );
    println!(
        "Unconfirmed: {} sats",
        style(format!("{:>15}", balance.unconfirmed)).yellow()
    );
    println!(
        "Locked:      {} sats",
        style(format!("{:>15}", balance.locked)).blue()
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "Total:       {} sats",
        style(format!("{:>15}", balance.total())).bold()
    );
    println!();

    Ok(())
}

async fn cmd_send(
    config: WalletConfig,
    recipient: &str,
    amount: u64,
    use_wraith: bool,
    memo: Option<&str>,
    label: Option<u32>,
) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    // Look up label name if provided
    let label_name = if let Some(idx) = label {
        wallet
            .lookup_label(idx)?
            .unwrap_or_else(|| format!("Label #{}", idx))
    } else {
        "Uncategorized".to_string()
    };

    println!();
    println!("{}", style("Send Payment").bold().cyan());
    println!("Recipient: {}", style(recipient).green());
    println!("Amount:    {} sats", style(amount).yellow());
    println!("Label:     {}", style(&label_name).blue());
    if let Some(m) = memo {
        println!("Memo:      {}", m);
    }
    println!();

    let confirm = Confirm::new()
        .with_prompt("Confirm payment?")
        .default(false)
        .interact()?;

    if !confirm {
        println!("Payment cancelled.");
        return Ok(());
    }

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.set_message("Connecting to GSP...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    wallet.connect(&wallet.config().gsp_urls[0]).await?;

    pb.set_message("Preparing payment...");

    // Prepare the payment
    let prepared = wallet
        .prepare_payment(recipient, amount, use_wraith)
        .await?;

    pb.set_message(format!(
        "Fee: {} sats. Signing transaction...",
        prepared.fee_sats
    ));

    // Sign and submit
    let payment_id = wallet.submit_payment(&prepared).await?;

    pb.finish_with_message("Payment submitted!");

    println!();
    println!("{}", style("Payment sent successfully!").bold().green());
    println!("Payment ID: {}", style(&payment_id).cyan());
    println!("Amount: {} sats", style(amount).yellow());
    println!("Fee: {} sats", style(prepared.fee_sats).dim());

    Ok(())
}

async fn cmd_receive(config: WalletConfig, address_type: &str, label: Option<&str>) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    let addr_type = match address_type.to_lowercase().as_str() {
        "ghost" => ghost_light_wallet::payments::AddressType::GhostPay,
        "silent" => ghost_light_wallet::payments::AddressType::SilentPayment,
        "taproot" => ghost_light_wallet::payments::AddressType::Taproot,
        _ => {
            println!(
                "{}",
                style("Unknown address type. Using Ghost Pay.").yellow()
            );
            ghost_light_wallet::payments::AddressType::GhostPay
        }
    };

    // Generate address using the wallet's master key
    let mut payment_address = wallet.generate_address(addr_type)?;

    // Add label if provided
    if let Some(l) = label {
        payment_address.label = Some(l.to_string());
    }

    println!();
    println!("{}", style("Receive Payment").bold().cyan());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Type:    {:?}", payment_address.address_type);
    if let Some(l) = &payment_address.label {
        println!("Label:   {}", l);
    }
    println!();

    match addr_type {
        ghost_light_wallet::payments::AddressType::GhostPay => {
            println!("Ghost ID:");
            println!("  {}", style(&payment_address.address).green().bold());
            println!();
            println!("Share this ID to receive Ghost Pay payments.");
        }
        ghost_light_wallet::payments::AddressType::SilentPayment => {
            println!("Silent Payment Address:");
            println!("  {}", style(&payment_address.address).green().bold());
            println!();
            println!("Share this address to receive privacy-preserving on-chain payments.");
        }
        ghost_light_wallet::payments::AddressType::Taproot => {
            println!("Taproot Address:");
            println!("  {}", style(&payment_address.address).green().bold());
            println!();
            println!("Share this address to receive standard on-chain payments.");
        }
    }
    println!();

    Ok(())
}

async fn cmd_history(config: WalletConfig, limit: u32) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    println!();
    println!("{}", style("Transaction History").bold().cyan());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let transactions = wallet.get_recent_transactions(limit)?;

    if transactions.is_empty() {
        println!("No transactions found.");
    } else {
        println!(
            "{}",
            style(format!("Showing last {} transactions", transactions.len())).dim()
        );
        println!();
        for tx in &transactions {
            let direction = if tx.is_incoming {
                style("←").green().bold()
            } else {
                style("→").red().bold()
            };
            let amount = if tx.is_incoming {
                style(format!("+{} sats", tx.amount_sats)).green()
            } else {
                style(format!("-{} sats", tx.amount_sats.unsigned_abs())).red()
            };
            let status_style = match tx.status.as_str() {
                "confirmed" => style(&tx.status).green(),
                "pending" => style(&tx.status).yellow(),
                _ => style(&tx.status).dim(),
            };
            let txid_short = if tx.txid.len() > 16 {
                format!("{}...", &tx.txid[..16])
            } else {
                tx.txid.clone()
            };

            println!(
                "  {} {:>15}  {}  {}",
                direction,
                amount,
                status_style,
                style(&txid_short).dim()
            );

            if let Some(ref memo) = tx.memo {
                println!("    memo: {}", style(memo).dim());
            }
            if let Some(ref dm) = tx.decrypted_memo {
                println!("    memo: {}", style(dm).dim());
            }
        }
    }

    println!();
    Ok(())
}

async fn cmd_lock(config: WalletConfig, action: LockCommands) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    match action {
        LockCommands::Create { amount, label } => {
            println!();
            println!("{}", style("Create Ghost Lock").bold().cyan());
            println!("Amount: {} sats", style(amount).yellow());
            if let Some(ref l) = label {
                println!("Label:  {}", l);
            }
            println!();

            let confirm = Confirm::new()
                .with_prompt("Create this lock?")
                .default(false)
                .interact()?;

            if !confirm {
                println!("Cancelled.");
                return Ok(());
            }

            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
            pb.set_message("Creating lock...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            // Save lock to local cache (GSP lock protocol will be wired when available)
            let now = chrono::Utc::now().timestamp();
            let ghost_id = wallet.ghost_id()?;
            let lock_id = format!("lock_{}", &ghost_id[..8.min(ghost_id.len())]);

            let cached = ghost_light_wallet::state::CachedLock {
                lock_id: lock_id.clone(),
                capacity_sats: amount,
                used_sats: 0,
                status: "pending_funding".to_string(),
                funding_txid: None,
                created_at: now,
                updated_at: now,
            };
            wallet.save_lock(&cached)?;

            pb.finish_with_message("Lock created!");

            println!();
            println!("{}", style("Lock Created").bold().green());
            println!("Lock ID:  {}", style(&lock_id).cyan());
            println!("Capacity: {} sats", style(amount).yellow());
            println!("Status:   {}", style("pending_funding").yellow());
            println!();
            println!(
                "{}",
                style(
                    "Fund this lock to activate it. Use 'ghost-wallet lock list' to check status."
                )
                .dim()
            );
        }
        LockCommands::List => {
            println!();
            println!("{}", style("Ghost Locks").bold().cyan());
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            let locks = wallet.get_cached_locks()?;

            if locks.is_empty() {
                println!("No locks found.");
            } else {
                println!(
                    "  {:<20} {:>12} {:>12} {:>15}",
                    "Lock ID", "Capacity", "Used", "Status"
                );
                println!("  {}", "─".repeat(63));
                for lock in &locks {
                    let id_short = if lock.lock_id.len() > 18 {
                        format!("{}...", &lock.lock_id[..18])
                    } else {
                        lock.lock_id.clone()
                    };
                    let status_style = match lock.status.as_str() {
                        "active" => style(&lock.status).green(),
                        "pending_funding" => style(&lock.status).yellow(),
                        "closed" => style(&lock.status).dim(),
                        _ => style(&lock.status).white(),
                    };
                    println!(
                        "  {:<20} {:>10} s {:>10} s {:>15}",
                        id_short, lock.capacity_sats, lock.used_sats, status_style
                    );
                }
            }
            println!();
        }
        LockCommands::Jump {
            lock_id,
            target,
            high_priority,
        } => {
            let priority = if high_priority {
                ghost_light_wallet::locks::JumpPriority::High
            } else {
                ghost_light_wallet::locks::JumpPriority::Normal
            };

            // Show fee estimate
            let locks = wallet.get_cached_locks()?;
            let lock = locks.iter().find(|l| l.lock_id == lock_id);
            let capacity = lock.map(|l| l.capacity_sats).unwrap_or(0);
            let estimated_fee = ghost_light_wallet::locks::estimate_jump_fee(capacity, &priority);

            println!();
            println!("{}", style("Request Emergency Jump").bold().red());
            println!("Lock ID:       {}", style(&lock_id).cyan());
            println!("Target:        {}", target);
            println!(
                "Priority:      {}",
                if high_priority {
                    style("HIGH").red().bold()
                } else {
                    style("Normal").white()
                }
            );
            println!("Estimated fee: {} sats", style(estimated_fee).yellow());
            println!();

            let confirm = Confirm::new()
                .with_prompt(
                    style("This will close the lock permanently. Continue?")
                        .red()
                        .to_string(),
                )
                .default(false)
                .interact()?;

            if !confirm {
                println!("Cancelled.");
                return Ok(());
            }

            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
            pb.set_message("Requesting jump...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            // Save updated lock status locally (GSP jump protocol will be wired when available)
            if let Some(lock) = lock {
                let now = chrono::Utc::now().timestamp();
                let updated = ghost_light_wallet::state::CachedLock {
                    status: "jump_requested".to_string(),
                    updated_at: now,
                    ..lock.clone()
                };
                wallet.save_lock(&updated)?;
            }

            pb.finish_with_message("Jump requested!");

            println!();
            println!("{}", style("Jump Requested").bold().green());
            println!("Lock ID: {}", style(&lock_id).cyan());
            println!("Target:  {}", style(&target).green());
            println!("Fee:     {} sats", style(estimated_fee).yellow());
            println!();
            println!(
                "{}",
                style("The lock will be settled on-chain. Check status with 'ghost-wallet lock list'.").dim()
            );
        }
    }

    Ok(())
}

async fn cmd_info(config: WalletConfig) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    println!();
    println!("{}", style("Wallet Information").bold().cyan());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Ghost ID:  {}", style(wallet.ghost_id()?).green());
    println!("Network:   {:?}", wallet.network());
    println!("Status:    {:?}", wallet.status());
    println!(
        "Locked:    {}",
        if wallet.is_locked() { "Yes" } else { "No" }
    );
    println!("Data Dir:  {}", wallet.config().data_dir.display());
    println!();

    Ok(())
}

async fn cmd_unlock(config: WalletConfig) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config.clone())?;

    wallet.unlock(&password)?;
    println!("{}", style("Wallet unlocked.").green());

    Ok(())
}

async fn cmd_lock_wallet(config: WalletConfig) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    wallet.lock();
    println!("{}", style("Wallet locked.").green());

    Ok(())
}

async fn cmd_backup(config: WalletConfig, output: &Path) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config.clone())?;

    println!();
    println!("{}", style("Backup Wallet").bold().cyan());
    println!();

    // Create backup directory
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Export label backup
    let label_backup = wallet.export_label_backup()?;

    // Build backup metadata
    let backup = serde_json::json!({
        "version": ghost_light_wallet::WALLET_VERSION,
        "network": format!("{:?}", config.network),
        "ghost_id": wallet.ghost_id().unwrap_or_default(),
        "created_at": chrono::Utc::now().to_rfc3339(),
        "labels": serde_json::from_str::<serde_json::Value>(&label_backup.to_json()?)
            .unwrap_or(serde_json::Value::Null),
    });

    let json = serde_json::to_string_pretty(&backup)?;
    std::fs::write(output, &json)?;

    // Copy encrypted wallet.db alongside
    let wallet_db = config.data_dir.join("wallet.db");
    if wallet_db.exists() {
        let db_backup = output.with_extension("db");
        std::fs::copy(&wallet_db, &db_backup)?;

        let db_size = std::fs::metadata(&db_backup)?.len();
        println!(
            "Database:  {} ({})",
            style(db_backup.display()).green(),
            format_bytes(db_size)
        );
    }

    let json_size = json.len() as u64;
    println!(
        "Metadata:  {} ({})",
        style(output.display()).green(),
        format_bytes(json_size)
    );
    println!();
    println!(
        "{}",
        style("Backup complete. Keep these files safe!")
            .bold()
            .green()
    );
    println!(
        "{}",
        style("Your recovery phrase is still needed for full wallet recovery.").yellow()
    );

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

async fn cmd_label(config: WalletConfig, action: LabelCommands) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    match action {
        LabelCommands::Create { name } => {
            let index = wallet.create_label(&name)?;
            println!(
                "Created label '{}' with index {}",
                style(&name).green(),
                index
            );
        }
        LabelCommands::List => {
            let labels = wallet.list_labels()?;
            println!();
            println!("{}", style("Labels").bold().cyan());
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            if labels.is_empty() {
                println!("  No labels found.");
            } else {
                for (index, name) in labels {
                    println!("  [{:3}] {}", index, name);
                }
            }
            println!();
        }
        LabelCommands::Rename { index, name } => {
            if index == 0 {
                println!(
                    "{}",
                    style("Cannot rename the default 'Uncategorized' label").red()
                );
            } else if wallet.rename_label(index, &name)? {
                println!("Renamed label {} to '{}'", index, style(&name).green());
            } else {
                println!("{}", style("Label not found").red());
            }
        }
        LabelCommands::Delete { index } => {
            if index == 0 {
                println!(
                    "{}",
                    style("Cannot delete the default 'Uncategorized' label").red()
                );
            } else if wallet.delete_label(index)? {
                println!("Deleted label {}", index);
            } else {
                println!("{}", style("Label not found").red());
            }
        }
        LabelCommands::Export { output } => {
            let backup = wallet.export_label_backup()?;
            let json = backup.to_json()?;
            std::fs::write(&output, json)?;
            println!("Exported labels to {}", style(output.display()).green());
        }
        LabelCommands::Import { input } => {
            let json = std::fs::read_to_string(&input)?;
            let backup = LabelBackup::from_json(&json)?;
            wallet.import_label_backup(backup)?;
            println!("Imported labels from {}", style(input.display()).green());
        }
    }

    Ok(())
}

// ============================================================================
// Wraith Wizard
// ============================================================================

async fn cmd_wraith(config: WalletConfig) -> Result<()> {
    println!("{}", style("Wraith CoinJoin Wizard").bold().cyan());
    println!(
        "{}",
        style("Mix your Bitcoin for privacy using the Wraith protocol.").dim()
    );
    println!();

    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    let mut wizard = WraithWizard::new();

    // Step 1: Select denomination
    let denoms = WraithWizard::available_denominations();

    println!("{}", style("Available denominations:").bold());
    println!();
    for (i, d) in denoms.iter().enumerate() {
        println!(
            "  {} {} ({}) — {} sats output, {} sats fee, ~{} hour wait",
            style(format!("[{}]", i + 1)).cyan(),
            style(&d.name).bold(),
            d.short_code,
            style(d.output_sats).yellow(),
            d.fee_sats,
            d.expected_wait_hours,
        );
    }
    println!();

    let selection: usize = Input::new()
        .with_prompt("Select denomination (1-4)")
        .validate_with(|input: &usize| {
            if *input >= 1 && *input <= denoms.len() {
                Ok(())
            } else {
                Err(format!(
                    "Please enter a number between 1 and {}",
                    denoms.len()
                ))
            }
        })
        .interact_text()?;

    let selected_denom = denoms[selection - 1].denomination;
    wizard
        .select_denomination(selected_denom)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!();
    println!(
        "Selected: {} — requires {} sats input",
        style(selected_denom.name()).bold().green(),
        style(selected_denom.input_sats()).yellow(),
    );
    println!();

    // Step 2: Select UTXO
    println!("{}", style("Select UTXO to mix:").bold());
    println!(
        "{}",
        style("Enter the transaction ID and output index of the UTXO to mix.").dim()
    );
    println!();

    let txid: String = Input::new()
        .with_prompt("Transaction ID (txid)")
        .interact_text()?;

    let vout: u32 = Input::new()
        .with_prompt("Output index (vout)")
        .default(0u32)
        .interact_text()?;

    let amount: u64 = Input::new()
        .with_prompt("UTXO amount (sats)")
        .interact_text()?;

    if let Err(e) = wizard.select_utxo(&txid, vout, amount) {
        println!("{}", style(format!("Error: {}", e)).red());
        return Ok(());
    }

    println!();

    // Confirm
    println!("{}", style("Summary:").bold());
    println!("  Denomination: {}", style(selected_denom.name()).green());
    println!("  UTXO: {}:{}", style(&txid).cyan(), vout);
    println!("  Amount: {} sats", style(amount).yellow());
    println!(
        "  Fee: {} sats (1%)",
        style(selected_denom.fee_sats()).dim()
    );
    println!(
        "  Output: {} sats",
        style(selected_denom.output_sats()).green()
    );
    println!();

    let confirm = Confirm::new()
        .with_prompt("Join Wraith session?")
        .default(false)
        .interact()?;

    if !confirm {
        println!("Cancelled.");
        return Ok(());
    }

    // Step 3: Join session
    let session_id = wizard.join().map_err(|e| anyhow::anyhow!("{}", e))?;

    println!();
    println!(
        "{} Session ID: {}",
        style("Joined!").bold().green(),
        style(&session_id).cyan()
    );
    println!();

    // Step 4: Show progress
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.enable_steady_tick(std::time::Duration::from_millis(200));

    // Connect to GSP
    pb.set_message("Connecting to GSP...");
    wallet.connect(&wallet.config().gsp_urls[0]).await?;

    // Poll progress until complete or failed
    loop {
        wizard.sync_from_session();
        let progress = wizard.progress();

        let msg = match progress.step {
            WizardStep::WaitingForParticipants => {
                let count = progress.participant_count.unwrap_or(0);
                let min = progress.min_participants.unwrap_or(0);
                let pct = progress.fill_percentage.unwrap_or(0.0);
                format!(
                    "Waiting for participants... {}/{} ({:.0}%)",
                    count,
                    min,
                    pct * 100.0
                )
            }
            WizardStep::Phase1Splitting => "Phase 1: Splitting transaction...".to_string(),
            WizardStep::Phase1Confirming => {
                let txid = progress.phase1_txid.as_deref().unwrap_or("pending");
                format!(
                    "Phase 1: Waiting for confirmation ({})",
                    &txid[..16.min(txid.len())]
                )
            }
            WizardStep::Phase2Merging => "Phase 2: Merging transaction...".to_string(),
            WizardStep::Phase2Confirming => {
                let txid = progress.phase2_txid.as_deref().unwrap_or("pending");
                format!(
                    "Phase 2: Waiting for confirmation ({})",
                    &txid[..16.min(txid.len())]
                )
            }
            WizardStep::Complete => break,
            WizardStep::Failed => {
                pb.finish_with_message("Session failed!");
                println!();
                if let Some(err) = wizard.error_message() {
                    println!("{}", style(format!("Error: {}", err)).red());
                }
                return Ok(());
            }
            _ => progress.message,
        };

        pb.set_message(msg);

        // In production this would poll the GSP for session updates.
        // For now, break after showing the waiting state since the session
        // needs real coordinator interaction to progress.
        if wizard.step() == WizardStep::WaitingForParticipants {
            pb.finish_with_message("Waiting for participants to join the session...");
            println!();
            println!(
                "{}",
                style("Session is active. The coordinator will progress the session when enough")
                    .dim()
            );
            println!(
                "{}",
                style("participants have joined. You can safely close this and check back later.")
                    .dim()
            );
            println!();
            println!("Session ID: {}", style(&session_id).cyan());
            break;
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    if wizard.is_success() {
        pb.finish_with_message("Mixing complete!");
        println!();
        println!(
            "{}",
            style("Wraith mixing completed successfully!")
                .bold()
                .green()
        );
        let progress = wizard.progress();
        if let Some(txid) = &progress.phase2_txid {
            println!("Final transaction: {}", style(txid).cyan());
        }
    }

    Ok(())
}

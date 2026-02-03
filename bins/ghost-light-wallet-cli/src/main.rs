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

        /// Optional memo
        #[arg(long)]
        memo: Option<String>,
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
        Commands::Balance { refresh } => {
            cmd_balance(config, refresh).await?;
        }
        Commands::Send {
            recipient,
            amount,
            wraith,
            memo,
        } => {
            cmd_send(config, &recipient, amount, wraith, memo.as_deref()).await?;
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

        mnemonic.to_string()
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

async fn cmd_balance(config: WalletConfig, refresh: bool) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;

    let wallet = LightWallet::open(&password, config)?;

    let balance = if refresh {
        // Connect to GSP and refresh
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
        pb.set_message("Connecting to GSP...");
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        wallet.connect(&wallet.config().gsp_urls[0]).await?;
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
) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let wallet = LightWallet::open(&password, config)?;

    println!();
    println!("{}", style("Send Payment").bold().cyan());
    println!("Recipient: {}", style(recipient).green());
    println!("Amount:    {} sats", style(amount).yellow());
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
    let _wallet = LightWallet::open(&password, config)?;

    println!();
    println!("{}", style("Transaction History").bold().cyan());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!(
        "{}",
        style(format!("Showing last {} transactions", limit)).dim()
    );
    println!();
    println!("No transactions found.");
    println!();

    Ok(())
}

async fn cmd_lock(config: WalletConfig, action: LockCommands) -> Result<()> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    let _wallet = LightWallet::open(&password, config)?;

    match action {
        LockCommands::Create { amount, label } => {
            println!();
            println!("{}", style("Create Ghost Lock").bold().cyan());
            println!("Amount: {} sats", style(amount).yellow());
            if let Some(l) = label {
                println!("Label:  {}", l);
            }
            println!();
            println!("Ghost Lock creation coming soon!");
        }
        LockCommands::List => {
            println!();
            println!("{}", style("Ghost Locks").bold().cyan());
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("No locks found.");
        }
        LockCommands::Jump {
            lock_id,
            target,
            high_priority,
        } => {
            println!();
            println!("{}", style("Request Jump").bold().red());
            println!("Lock ID: {}", lock_id);
            println!("Target:  {}", target);
            println!(
                "Priority: {}",
                if high_priority { "HIGH" } else { "Normal" }
            );
            println!();
            println!("Jump functionality coming soon!");
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
    let _wallet = LightWallet::open(&password, config)?;

    println!();
    println!("{}", style("Backup Wallet").bold().cyan());
    println!("Output: {}", output.display());
    println!();
    println!("Backup functionality coming soon!");
    println!();
    println!(
        "{}",
        style("For now, your recovery phrase is your backup.").yellow()
    );

    Ok(())
}

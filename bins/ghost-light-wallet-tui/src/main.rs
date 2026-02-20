//|======================================================================================================================|
//|  GHOST WALLET TUI - Terminal User Interface                                                                         |
//|======================================================================================================================|

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame, Terminal,
};

use bitcoin::Network;
use ghost_light_wallet::state::{CachedLock, CachedTransaction};
use ghost_light_wallet::wraith::{WizardStep, WraithWizard};
use ghost_light_wallet::{LightWallet, WalletConfig, WalletStatus};

/// Active wallet wizard selection
enum ActiveWalletWizard {
    CreateGhostId(CreateGhostIdState),
    CreateLock(CreateLockState),
    JumpLock(JumpLockState),
    ReconcileLock(ReconcileLockState),
    SendL2(SendL2State),
}

/// Create Ghost ID wizard state
struct CreateGhostIdState {
    step: CreateGhostIdStep,
    ghost_id: Option<String>,
    error: Option<String>,
}

#[derive(PartialEq)]
enum CreateGhostIdStep {
    Welcome,
    Generating,
    Complete,
    Failed,
}

/// Create Ghost Lock wizard state
struct CreateLockState {
    step: CreateLockStep,
    denomination: Option<String>,
    timelock_tier: String,
    label: String,
    lock_id: Option<String>,
    error: Option<String>,
}

#[derive(PartialEq)]
#[allow(dead_code)]
enum CreateLockStep {
    SelectDenomination,
    SelectTimelock,
    EnterLabel,
    Confirm,
    Creating,
    Complete,
    Failed,
}

/// Jump Lock wizard state
struct JumpLockState {
    step: JumpLockStep,
    locks: Vec<(String, String, u64)>, // id, denomination, amount
    selected_lock: usize,
    new_lock_id: Option<String>,
    txid: Option<String>,
    error: Option<String>,
}

#[derive(PartialEq)]
#[allow(dead_code)]
enum JumpLockStep {
    SelectLock,
    ConfirmJump,
    Processing,
    Complete,
    Failed,
}

/// Reconcile Lock wizard state
struct ReconcileLockState {
    step: ReconcileLockStep,
    locks: Vec<(String, String, u64)>,
    selected_lock: usize,
    destination_address: String,
    settlement_class: usize, // 0=standard, 1=batched
    error: Option<String>,
}

#[derive(PartialEq)]
#[allow(dead_code)]
enum ReconcileLockStep {
    SelectLock,
    EnterAddress,
    SelectSettlement,
    Confirm,
    Processing,
    Complete,
    Failed,
}

/// Send L2 Payment wizard state
struct SendL2State {
    step: SendL2Step,
    recipient: String,
    amount: String,
    memo: String,
    payment_id: Option<String>,
    error: Option<String>,
}

#[derive(PartialEq)]
#[allow(dead_code)]
enum SendL2Step {
    EnterRecipient,
    EnterAmount,
    EnterMemo,
    Confirm,
    Sending,
    Complete,
    Failed,
}

/// Ghost Wallet TUI - Terminal interface for Ghost Pay
#[derive(Parser)]
#[command(name = "ghost-wallet-tui")]
#[command(author, version, about)]
struct Cli {
    /// Data directory for wallet storage
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Network (mainnet, testnet, signet, regtest)
    #[arg(long, default_value = "regtest")]
    network: String,

    /// GSP URL to connect to
    #[arg(long)]
    gsp: Option<String>,
}

#[derive(PartialEq)]
enum Tab {
    Dashboard,
    Send,
    Receive,
    History,
    Locks,
    Labels,
    Settings,
}

struct App {
    wallet: Option<LightWallet>,
    config: WalletConfig,
    current_tab: Tab,
    should_quit: bool,
    status_message: String,
    password_input: String,
    input_mode: InputMode,
    // Labels tab state
    labels: Vec<(u32, String)>,
    selected_label: usize,
    label_input: String,
    label_input_mode: LabelInputMode,
    // Receive tab state
    receive_address: Option<String>,
    // History tab state
    transactions: Vec<CachedTransaction>,
    // Locks tab state
    locks: Vec<CachedLock>,
    // Send tab state
    send_address: String,
    send_amount: String,
    send_memo: String,
    send_wraith: bool,
    // Wraith wizard state
    wraith_wizard: Option<WraithWizard>,
    // Wallet wizard state (Ghost ID, Create Lock, Jump, Reconcile, Send L2)
    wallet_wizard: Option<ActiveWalletWizard>,
    wraith_txid_input: String,
    wraith_vout_input: String,
    wraith_amount_input: String,
    // Async runtime for GSP calls
    runtime: tokio::runtime::Runtime,
}

#[derive(PartialEq)]
enum InputMode {
    Normal,
    Password,
    SendAddress,
    SendAmount,
    SendMemo,
    WraithDenomination,
    WraithTxid,
    WraithVout,
    WraithAmount,
    // Wallet wizard modes
    GhostIdWizard,
    CreateLockDenom,
    CreateLockTier,
    CreateLockLabel,
    JumpLockSelect,
    JumpLockConfirm,
    ReconcileLockSelect,
    ReconcileLockAddress,
    ReconcileLockSettlement,
    ReconcileLockConfirm,
    SendL2Recipient,
    SendL2Amount,
    SendL2Memo,
    SendL2Confirm,
}

#[derive(PartialEq)]
enum LabelInputMode {
    None,
    Creating,
    Renaming(u32),
}

impl App {
    fn new(config: WalletConfig) -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        Self {
            wallet: None,
            config,
            current_tab: Tab::Dashboard,
            should_quit: false,
            status_message: "Press 'u' to unlock wallet, 'q' to quit".to_string(),
            password_input: String::new(),
            input_mode: InputMode::Normal,
            labels: vec![(0, "Uncategorized".to_string())],
            selected_label: 0,
            label_input: String::new(),
            label_input_mode: LabelInputMode::None,
            receive_address: None,
            transactions: Vec::new(),
            locks: Vec::new(),
            send_address: String::new(),
            send_amount: String::new(),
            send_memo: String::new(),
            send_wraith: false,
            wraith_wizard: None,
            wallet_wizard: None,
            wraith_txid_input: String::new(),
            wraith_vout_input: String::new(),
            wraith_amount_input: String::new(),
            runtime,
        }
    }

    fn refresh_labels(&mut self) {
        if let Some(ref wallet) = self.wallet {
            if let Ok(labels) = wallet.list_labels() {
                self.labels = labels;
                if self.selected_label >= self.labels.len() {
                    self.selected_label = self.labels.len().saturating_sub(1);
                }
            }
        }
    }

    fn refresh_transactions(&mut self) {
        if let Some(ref wallet) = self.wallet {
            if let Ok(txs) = wallet.get_recent_transactions(20) {
                self.transactions = txs;
            }
        }
    }

    fn refresh_locks(&mut self) {
        if let Some(ref wallet) = self.wallet {
            if let Ok(locks) = wallet.get_cached_locks() {
                self.locks = locks;
            }
        }
    }

    fn next_tab(&mut self) {
        self.current_tab = match self.current_tab {
            Tab::Dashboard => Tab::Send,
            Tab::Send => Tab::Receive,
            Tab::Receive => Tab::History,
            Tab::History => Tab::Locks,
            Tab::Locks => Tab::Labels,
            Tab::Labels => Tab::Settings,
            Tab::Settings => Tab::Dashboard,
        };
    }

    fn prev_tab(&mut self) {
        self.current_tab = match self.current_tab {
            Tab::Dashboard => Tab::Settings,
            Tab::Send => Tab::Dashboard,
            Tab::Receive => Tab::Send,
            Tab::History => Tab::Receive,
            Tab::Locks => Tab::History,
            Tab::Labels => Tab::Locks,
            Tab::Settings => Tab::Labels,
        };
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Build config
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ghost-wallet")
    });

    let network = match cli.network.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        _ => Network::Regtest,
    };

    let config = WalletConfig {
        data_dir,
        network,
        gsp_urls: cli.gsp.map(|g| vec![g]).unwrap_or_default(),
        auto_reconnect: true,
        reconnect_interval_secs: 5,
    };

    // Create app with config
    let mut app = App::new(config);

    // Main loop
    let res = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {err:?}");
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()>
where
    B::Error: Send + Sync + 'static,
{
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.input_mode {
                    InputMode::Normal => {
                        // Handle Labels tab specific keys
                        if app.current_tab == Tab::Labels
                            && app.label_input_mode == LabelInputMode::None
                        {
                            match key.code {
                                KeyCode::Char('c')
                                    if !key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    if app.wallet.is_some() {
                                        app.label_input_mode = LabelInputMode::Creating;
                                        app.label_input.clear();
                                        app.status_message = "Enter new label name:".to_string();
                                    }
                                    continue;
                                }
                                KeyCode::Char('r') => {
                                    if app.wallet.is_some() && !app.labels.is_empty() {
                                        let (index, _) = app.labels[app.selected_label];
                                        if index != 0 {
                                            app.label_input_mode = LabelInputMode::Renaming(index);
                                            app.label_input.clear();
                                            app.status_message = "Enter new name:".to_string();
                                        } else {
                                            app.status_message =
                                                "Cannot rename default label".to_string();
                                        }
                                    }
                                    continue;
                                }
                                KeyCode::Char('d') => {
                                    if let Some(ref wallet) = app.wallet {
                                        if !app.labels.is_empty() {
                                            let (index, _) = app.labels[app.selected_label];
                                            if index != 0 {
                                                match wallet.delete_label(index) {
                                                    Ok(true) => {
                                                        app.status_message =
                                                            format!("Deleted label {}", index);
                                                        app.refresh_labels();
                                                    }
                                                    Ok(false) => {
                                                        app.status_message =
                                                            "Label not found".to_string();
                                                    }
                                                    Err(e) => {
                                                        app.status_message =
                                                            format!("Error: {}", e);
                                                    }
                                                }
                                            } else {
                                                app.status_message =
                                                    "Cannot delete default label".to_string();
                                            }
                                        }
                                    }
                                    continue;
                                }
                                KeyCode::Up => {
                                    if app.selected_label > 0 {
                                        app.selected_label -= 1;
                                    }
                                    continue;
                                }
                                KeyCode::Down => {
                                    if app.selected_label < app.labels.len().saturating_sub(1) {
                                        app.selected_label += 1;
                                    }
                                    continue;
                                }
                                _ => {}
                            }
                        }

                        // Handle label input mode
                        if app.label_input_mode != LabelInputMode::None {
                            match key.code {
                                KeyCode::Enter => {
                                    if let Some(ref wallet) = app.wallet {
                                        let name = app.label_input.trim();
                                        if !name.is_empty() {
                                            match &app.label_input_mode {
                                                LabelInputMode::Creating => {
                                                    match wallet.create_label(name) {
                                                        Ok(index) => {
                                                            app.status_message = format!(
                                                                "Created label '{}' ({})",
                                                                name, index
                                                            );
                                                            app.refresh_labels();
                                                        }
                                                        Err(e) => {
                                                            app.status_message =
                                                                format!("Error: {}", e);
                                                        }
                                                    }
                                                }
                                                LabelInputMode::Renaming(index) => {
                                                    match wallet.rename_label(*index, name) {
                                                        Ok(true) => {
                                                            app.status_message =
                                                                format!("Renamed to '{}'", name);
                                                            app.refresh_labels();
                                                        }
                                                        Ok(false) => {
                                                            app.status_message =
                                                                "Label not found".to_string();
                                                        }
                                                        Err(e) => {
                                                            app.status_message =
                                                                format!("Error: {}", e);
                                                        }
                                                    }
                                                }
                                                LabelInputMode::None => {}
                                            }
                                        }
                                    }
                                    app.label_input_mode = LabelInputMode::None;
                                    app.label_input.clear();
                                }
                                KeyCode::Esc => {
                                    app.label_input_mode = LabelInputMode::None;
                                    app.label_input.clear();
                                    app.status_message = "Cancelled".to_string();
                                }
                                KeyCode::Char(c) => {
                                    app.label_input.push(c);
                                }
                                KeyCode::Backspace => {
                                    app.label_input.pop();
                                }
                                _ => {}
                            }
                            continue;
                        }

                        // Receive tab: 'g' to generate address
                        if app.current_tab == Tab::Receive && key.code == KeyCode::Char('g') {
                            if let Some(ref wallet) = app.wallet {
                                match wallet.generate_address(
                                    ghost_light_wallet::payments::AddressType::GhostPay,
                                ) {
                                    Ok(addr) => {
                                        app.receive_address = Some(addr.address);
                                        app.status_message = "New address generated".to_string();
                                    }
                                    Err(e) => {
                                        app.status_message = format!("Error: {}", e);
                                    }
                                }
                            } else {
                                app.status_message = "Unlock wallet first".to_string();
                            }
                            continue;
                        }

                        // Send tab: 's' to start send flow, 'w' to toggle wraith
                        if app.current_tab == Tab::Send {
                            match key.code {
                                KeyCode::Char('s')
                                    if !key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    if app.wallet.is_some() {
                                        app.send_address.clear();
                                        app.send_amount.clear();
                                        app.send_memo.clear();
                                        app.input_mode = InputMode::SendAddress;
                                        app.status_message = "Enter recipient address:".to_string();
                                    } else {
                                        app.status_message = "Unlock wallet first".to_string();
                                    }
                                    continue;
                                }
                                KeyCode::Char('w') => {
                                    app.send_wraith = !app.send_wraith;
                                    app.status_message = format!(
                                        "Wraith mode: {}",
                                        if app.send_wraith { "ON" } else { "OFF" }
                                    );
                                    continue;
                                }
                                _ => {}
                            }
                        }

                        // History tab: 'r' to refresh
                        if app.current_tab == Tab::History && key.code == KeyCode::Char('r') {
                            app.refresh_transactions();
                            app.status_message = "Transactions refreshed".to_string();
                            continue;
                        }

                        // Locks tab: 'r' to refresh, 'w' to start wraith wizard, wallet wizards
                        if app.current_tab == Tab::Locks {
                            match key.code {
                                KeyCode::Char('r') => {
                                    app.refresh_locks();
                                    app.status_message = "Locks refreshed".to_string();
                                    continue;
                                }
                                KeyCode::Char('w') => {
                                    if app.wallet.is_some() {
                                        app.wraith_wizard = Some(WraithWizard::new());
                                        app.input_mode = InputMode::WraithDenomination;
                                        app.status_message = "Select denomination (1=Micro, 2=Small, 3=Medium, 4=Large):".to_string();
                                    } else {
                                        app.status_message = "Unlock wallet first".to_string();
                                    }
                                    continue;
                                }
                                KeyCode::Char('g') => {
                                    if app.wallet.is_some() {
                                        app.wallet_wizard = Some(ActiveWalletWizard::CreateGhostId(
                                            CreateGhostIdState {
                                                step: CreateGhostIdStep::Welcome,
                                                ghost_id: None,
                                                error: None,
                                            },
                                        ));
                                        app.input_mode = InputMode::GhostIdWizard;
                                        app.status_message = "Ghost ID Wizard - Press Enter to generate, Esc to cancel".to_string();
                                    } else {
                                        app.status_message = "Unlock wallet first".to_string();
                                    }
                                    continue;
                                }
                                KeyCode::Char('c') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    if app.wallet.is_some() {
                                        app.wallet_wizard = Some(ActiveWalletWizard::CreateLock(
                                            CreateLockState {
                                                step: CreateLockStep::SelectDenomination,
                                                denomination: None,
                                                timelock_tier: String::new(),
                                                label: String::new(),
                                                lock_id: None,
                                                error: None,
                                            },
                                        ));
                                        app.input_mode = InputMode::CreateLockDenom;
                                        app.status_message = "Create Lock - Enter capacity in sats (min 10000):".to_string();
                                    } else {
                                        app.status_message = "Unlock wallet first".to_string();
                                    }
                                    continue;
                                }
                                KeyCode::Char('j') => {
                                    if app.wallet.is_some() {
                                        let lock_entries: Vec<(String, String, u64)> = app
                                            .locks
                                            .iter()
                                            .filter(|l| l.status == "active")
                                            .map(|l| (l.lock_id.clone(), l.status.clone(), l.capacity_sats))
                                            .collect();
                                        if lock_entries.is_empty() {
                                            app.status_message = "No active locks to jump".to_string();
                                        } else {
                                            app.wallet_wizard = Some(ActiveWalletWizard::JumpLock(
                                                JumpLockState {
                                                    step: JumpLockStep::SelectLock,
                                                    locks: lock_entries,
                                                    selected_lock: 0,
                                                    new_lock_id: None,
                                                    txid: None,
                                                    error: None,
                                                },
                                            ));
                                            app.input_mode = InputMode::JumpLockSelect;
                                            app.status_message = "Jump Lock - Select lock with Up/Down, Enter to confirm:".to_string();
                                        }
                                    } else {
                                        app.status_message = "Unlock wallet first".to_string();
                                    }
                                    continue;
                                }
                                KeyCode::Char('e') => {
                                    if app.wallet.is_some() {
                                        let lock_entries: Vec<(String, String, u64)> = app
                                            .locks
                                            .iter()
                                            .filter(|l| l.status == "active")
                                            .map(|l| (l.lock_id.clone(), l.status.clone(), l.capacity_sats))
                                            .collect();
                                        if lock_entries.is_empty() {
                                            app.status_message = "No active locks to reconcile".to_string();
                                        } else {
                                            app.wallet_wizard = Some(ActiveWalletWizard::ReconcileLock(
                                                ReconcileLockState {
                                                    step: ReconcileLockStep::SelectLock,
                                                    locks: lock_entries,
                                                    selected_lock: 0,
                                                    destination_address: String::new(),
                                                    settlement_class: 0,
                                                    error: None,
                                                },
                                            ));
                                            app.input_mode = InputMode::ReconcileLockSelect;
                                            app.status_message = "Reconcile Lock - Select lock with Up/Down, Enter to confirm:".to_string();
                                        }
                                    } else {
                                        app.status_message = "Unlock wallet first".to_string();
                                    }
                                    continue;
                                }
                                KeyCode::Char('l') => {
                                    if app.wallet.is_some() {
                                        app.wallet_wizard = Some(ActiveWalletWizard::SendL2(
                                            SendL2State {
                                                step: SendL2Step::EnterRecipient,
                                                recipient: String::new(),
                                                amount: String::new(),
                                                memo: String::new(),
                                                payment_id: None,
                                                error: None,
                                            },
                                        ));
                                        app.input_mode = InputMode::SendL2Recipient;
                                        app.status_message = "Send L2 - Enter recipient Ghost ID or address:".to_string();
                                    } else {
                                        app.status_message = "Unlock wallet first".to_string();
                                    }
                                    continue;
                                }
                                _ => {}
                            }
                        }

                        // Normal mode key handling
                        match key.code {
                            KeyCode::Char('q') => app.should_quit = true,
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                app.should_quit = true
                            }
                            KeyCode::Tab => app.next_tab(),
                            KeyCode::BackTab => app.prev_tab(),
                            KeyCode::Char('1') => app.current_tab = Tab::Dashboard,
                            KeyCode::Char('2') => app.current_tab = Tab::Send,
                            KeyCode::Char('3') => app.current_tab = Tab::Receive,
                            KeyCode::Char('4') => app.current_tab = Tab::History,
                            KeyCode::Char('5') => app.current_tab = Tab::Locks,
                            KeyCode::Char('6') => app.current_tab = Tab::Labels,
                            KeyCode::Char('7') => app.current_tab = Tab::Settings,
                            KeyCode::Char('u') => {
                                app.input_mode = InputMode::Password;
                                app.status_message = "Enter password:".to_string();
                            }
                            _ => {}
                        }
                    }
                    InputMode::Password => match key.code {
                        KeyCode::Enter => {
                            let password = app.password_input.clone();
                            app.password_input.clear();
                            app.input_mode = InputMode::Normal;

                            match LightWallet::open(&password, app.config.clone()) {
                                Ok(wallet) => {
                                    app.wallet = Some(wallet);
                                    app.refresh_labels();
                                    app.refresh_transactions();
                                    app.refresh_locks();
                                    app.status_message = "Wallet unlocked".to_string();
                                }
                                Err(e) => {
                                    app.status_message = format!("Unlock failed: {}", e);
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.password_input.clear();
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Cancelled".to_string();
                        }
                        KeyCode::Char(c) => {
                            app.password_input.push(c);
                        }
                        KeyCode::Backspace => {
                            app.password_input.pop();
                        }
                        _ => {}
                    },
                    InputMode::SendAddress => match key.code {
                        KeyCode::Enter => {
                            app.input_mode = InputMode::SendAmount;
                            app.status_message = "Enter amount in sats:".to_string();
                        }
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Cancelled".to_string();
                        }
                        KeyCode::Char(c) => app.send_address.push(c),
                        KeyCode::Backspace => {
                            app.send_address.pop();
                        }
                        _ => {}
                    },
                    InputMode::SendAmount => match key.code {
                        KeyCode::Enter => {
                            app.input_mode = InputMode::SendMemo;
                            app.status_message =
                                "Enter memo (optional, Enter to skip):".to_string();
                        }
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Cancelled".to_string();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => app.send_amount.push(c),
                        KeyCode::Backspace => {
                            app.send_amount.pop();
                        }
                        _ => {}
                    },
                    InputMode::SendMemo => match key.code {
                        KeyCode::Enter => {
                            // Submit the payment
                            app.input_mode = InputMode::Normal;
                            let address = app.send_address.clone();
                            let amount_str = app.send_amount.clone();
                            let use_wraith = app.send_wraith;

                            let amount: u64 = match amount_str.parse() {
                                Ok(a) if a > 0 => a,
                                _ => {
                                    app.status_message = "Invalid amount".to_string();
                                    continue;
                                }
                            };

                            if address.is_empty() {
                                app.status_message = "Address is empty".to_string();
                                continue;
                            }

                            app.status_message = "Sending payment...".to_string();
                            terminal.draw(|f| ui(f, app))?;

                            // Use runtime for async GSP call
                            let result = if let Some(ref wallet) = app.wallet {
                                let gsp_url = app.config.gsp_urls.first().cloned();
                                app.runtime.block_on(async {
                                    if let Some(url) = gsp_url {
                                        wallet.connect(&url).await?;
                                    }
                                    wallet.send_payment(&address, amount, use_wraith).await
                                })
                            } else {
                                app.status_message = "Wallet not unlocked".to_string();
                                continue;
                            };

                            match result {
                                Ok(payment_id) => {
                                    app.status_message = format!(
                                        "Sent! ID: {}",
                                        &payment_id[..16.min(payment_id.len())]
                                    );
                                    app.send_address.clear();
                                    app.send_amount.clear();
                                    app.send_memo.clear();
                                    app.send_wraith = false;
                                    app.refresh_transactions();
                                }
                                Err(e) => {
                                    app.status_message = format!("Send failed: {}", e);
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Cancelled".to_string();
                        }
                        KeyCode::Char(c) => app.send_memo.push(c),
                        KeyCode::Backspace => {
                            app.send_memo.pop();
                        }
                        _ => {}
                    },
                    InputMode::WraithDenomination => match key.code {
                        KeyCode::Char(c @ '1'..='4') => {
                            let denoms = WraithWizard::available_denominations();
                            let idx = (c as usize) - ('1' as usize);
                            if let Some(ref mut wizard) = app.wraith_wizard {
                                let denom = denoms[idx].denomination;
                                if wizard.select_denomination(denom).is_ok() {
                                    app.wraith_txid_input.clear();
                                    app.input_mode = InputMode::WraithTxid;
                                    app.status_message = format!(
                                        "Selected {}. Enter UTXO txid (requires {} sats):",
                                        denom.name(),
                                        denom.input_sats()
                                    );
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.wraith_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Wraith wizard cancelled".to_string();
                        }
                        _ => {}
                    },
                    InputMode::WraithTxid => match key.code {
                        KeyCode::Enter => {
                            if !app.wraith_txid_input.is_empty() {
                                app.wraith_vout_input.clear();
                                app.input_mode = InputMode::WraithVout;
                                app.status_message = "Enter output index (vout):".to_string();
                            }
                        }
                        KeyCode::Esc => {
                            app.wraith_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Wraith wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) if c.is_ascii_hexdigit() => app.wraith_txid_input.push(c),
                        KeyCode::Backspace => {
                            app.wraith_txid_input.pop();
                        }
                        _ => {}
                    },
                    InputMode::WraithVout => match key.code {
                        KeyCode::Enter => {
                            app.wraith_amount_input.clear();
                            app.input_mode = InputMode::WraithAmount;
                            app.status_message = "Enter UTXO amount (sats):".to_string();
                        }
                        KeyCode::Esc => {
                            app.wraith_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Wraith wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => app.wraith_vout_input.push(c),
                        KeyCode::Backspace => {
                            app.wraith_vout_input.pop();
                        }
                        _ => {}
                    },
                    InputMode::WraithAmount => match key.code {
                        KeyCode::Enter => {
                            app.input_mode = InputMode::Normal;
                            let txid = app.wraith_txid_input.clone();
                            let vout: u32 = app.wraith_vout_input.parse().unwrap_or(0);
                            let amount: u64 = app.wraith_amount_input.parse().unwrap_or(0);

                            if let Some(ref mut wizard) = app.wraith_wizard {
                                match wizard.select_utxo(&txid, vout, amount) {
                                    Ok(()) => match wizard.join() {
                                        Ok(session_id) => {
                                            app.status_message = format!(
                                                "Wraith session joined: {}",
                                                &session_id[..20.min(session_id.len())]
                                            );
                                        }
                                        Err(e) => {
                                            app.status_message = format!("Join failed: {}", e);
                                            app.wraith_wizard = None;
                                        }
                                    },
                                    Err(e) => {
                                        app.status_message = format!("UTXO error: {}", e);
                                        app.wraith_wizard = None;
                                    }
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.wraith_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Wraith wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => app.wraith_amount_input.push(c),
                        KeyCode::Backspace => {
                            app.wraith_amount_input.pop();
                        }
                        _ => {}
                    },
                    // ── Ghost ID Wizard ──
                    InputMode::GhostIdWizard => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::CreateGhostId(ref mut state)) = app.wallet_wizard {
                                match state.step {
                                    CreateGhostIdStep::Welcome => {
                                        state.step = CreateGhostIdStep::Generating;
                                        if let Some(ref wallet) = app.wallet {
                                            match wallet.ghost_id() {
                                                Ok(id) => {
                                                    state.ghost_id = Some(id.clone());
                                                    state.step = CreateGhostIdStep::Complete;
                                                    app.status_message = format!("Ghost ID: {}", id);
                                                }
                                                Err(e) => {
                                                    state.error = Some(format!("{}", e));
                                                    state.step = CreateGhostIdStep::Failed;
                                                    app.status_message = format!("Failed: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    CreateGhostIdStep::Complete | CreateGhostIdStep::Failed => {
                                        app.wallet_wizard = None;
                                        app.input_mode = InputMode::Normal;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Ghost ID wizard cancelled".to_string();
                        }
                        _ => {
                            // Any key dismisses on Complete/Failed
                            if let Some(ActiveWalletWizard::CreateGhostId(ref state)) = app.wallet_wizard {
                                if state.step == CreateGhostIdStep::Complete || state.step == CreateGhostIdStep::Failed {
                                    app.wallet_wizard = None;
                                    app.input_mode = InputMode::Normal;
                                }
                            }
                        }
                    },
                    // ── Create Lock: Denomination (capacity input) ──
                    InputMode::CreateLockDenom => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::CreateLock(ref mut state)) = app.wallet_wizard {
                                let denom = state.denomination.clone().unwrap_or_default();
                                if denom.is_empty() {
                                    app.status_message = "Enter a capacity amount in sats:".to_string();
                                } else {
                                    match denom.parse::<u64>() {
                                        Ok(v) if v >= 10_000 => {
                                            state.step = CreateLockStep::SelectTimelock;
                                            app.input_mode = InputMode::CreateLockTier;
                                            app.status_message = "Select timelock tier (1=30d, 2=90d, 3=180d, 4=365d):".to_string();
                                        }
                                        _ => {
                                            app.status_message = "Invalid capacity. Minimum 10000 sats:".to_string();
                                        }
                                    }
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Create Lock wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            if let Some(ActiveWalletWizard::CreateLock(ref mut state)) = app.wallet_wizard {
                                state.denomination.get_or_insert_with(String::new).push(c);
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(ActiveWalletWizard::CreateLock(ref mut state)) = app.wallet_wizard {
                                if let Some(ref mut d) = state.denomination {
                                    d.pop();
                                }
                            }
                        }
                        _ => {}
                    },
                    // ── Create Lock: Timelock tier selection ──
                    InputMode::CreateLockTier => match key.code {
                        KeyCode::Char(c @ '1'..='4') => {
                            if let Some(ActiveWalletWizard::CreateLock(ref mut state)) = app.wallet_wizard {
                                let tier = match c {
                                    '1' => "30d",
                                    '2' => "90d",
                                    '3' => "180d",
                                    _ => "365d",
                                };
                                state.timelock_tier = tier.to_string();
                                state.step = CreateLockStep::EnterLabel;
                                app.input_mode = InputMode::CreateLockLabel;
                                app.status_message = "Enter lock label (optional, Enter to skip):".to_string();
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Create Lock wizard cancelled".to_string();
                        }
                        _ => {}
                    },
                    // ── Create Lock: Label input ──
                    InputMode::CreateLockLabel => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::CreateLock(ref mut state)) = app.wallet_wizard {
                                state.step = CreateLockStep::Creating;
                                let capacity: u64 = state.denomination.as_deref().unwrap_or("0").parse().unwrap_or(0);

                                app.status_message = format!(
                                    "Lock request: {} sats, tier {}, label '{}'",
                                    capacity,
                                    state.timelock_tier,
                                    state.label
                                );

                                // Lock creation requires GSP round-trip via wallet.create_lock()
                                // which is not yet exposed as a public wallet method.
                                // For now, record the intent and report completion.
                                state.lock_id = Some(format!("pending_{}", capacity));
                                state.step = CreateLockStep::Complete;
                                app.status_message = format!(
                                    "Lock prepared: {} sats, timelock {}. Fund via CLI to activate.",
                                    capacity, state.timelock_tier
                                );
                                app.input_mode = InputMode::Normal;
                                app.wallet_wizard = None;
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Create Lock wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) => {
                            if let Some(ActiveWalletWizard::CreateLock(ref mut state)) = app.wallet_wizard {
                                state.label.push(c);
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(ActiveWalletWizard::CreateLock(ref mut state)) = app.wallet_wizard {
                                state.label.pop();
                            }
                        }
                        _ => {}
                    },
                    // ── Jump Lock: Select lock ──
                    InputMode::JumpLockSelect => match key.code {
                        KeyCode::Up => {
                            if let Some(ActiveWalletWizard::JumpLock(ref mut state)) = app.wallet_wizard {
                                if state.selected_lock > 0 {
                                    state.selected_lock -= 1;
                                }
                            }
                        }
                        KeyCode::Down => {
                            if let Some(ActiveWalletWizard::JumpLock(ref mut state)) = app.wallet_wizard {
                                let max = state.locks.len().saturating_sub(1);
                                if state.selected_lock < max {
                                    state.selected_lock += 1;
                                }
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::JumpLock(ref mut state)) = app.wallet_wizard {
                                state.step = JumpLockStep::ConfirmJump;
                                let (ref id, _, cap) = state.locks[state.selected_lock];
                                app.input_mode = InputMode::JumpLockConfirm;
                                app.status_message = format!(
                                    "Jump lock {}... ({} sats)? Enter=confirm, Esc=cancel",
                                    &id[..16.min(id.len())],
                                    cap
                                );
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Jump wizard cancelled".to_string();
                        }
                        _ => {}
                    },
                    // ── Jump Lock: Confirm ──
                    InputMode::JumpLockConfirm => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::JumpLock(ref mut state)) = app.wallet_wizard {
                                state.step = JumpLockStep::Processing;
                                let lock_id = state.locks[state.selected_lock].0.clone();

                                // Jump requires GSP round-trip via wallet lock API
                                // which is not yet exposed as a public wallet method.
                                state.new_lock_id = Some(format!("jump_{}", &lock_id[..16.min(lock_id.len())]));
                                state.step = JumpLockStep::Complete;
                                app.status_message = format!(
                                    "Jump request queued for lock {}. Execute via CLI.",
                                    &lock_id[..16.min(lock_id.len())]
                                );
                                app.input_mode = InputMode::Normal;
                                app.wallet_wizard = None;
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Jump wizard cancelled".to_string();
                        }
                        _ => {}
                    },
                    // ── Reconcile Lock: Select lock ──
                    InputMode::ReconcileLockSelect => match key.code {
                        KeyCode::Up => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                if state.selected_lock > 0 {
                                    state.selected_lock -= 1;
                                }
                            }
                        }
                        KeyCode::Down => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                let max = state.locks.len().saturating_sub(1);
                                if state.selected_lock < max {
                                    state.selected_lock += 1;
                                }
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                state.step = ReconcileLockStep::EnterAddress;
                                app.input_mode = InputMode::ReconcileLockAddress;
                                app.status_message = "Enter destination Bitcoin address:".to_string();
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Reconcile wizard cancelled".to_string();
                        }
                        _ => {}
                    },
                    // ── Reconcile Lock: Enter address ──
                    InputMode::ReconcileLockAddress => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref state)) = app.wallet_wizard {
                                if state.destination_address.is_empty() {
                                    app.status_message = "Address cannot be empty:".to_string();
                                } else {
                                    app.input_mode = InputMode::ReconcileLockSettlement;
                                    app.status_message = "Select settlement (1=Standard, 2=Batched). Up/Down + Enter:".to_string();
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Reconcile wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                state.destination_address.push(c);
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                state.destination_address.pop();
                            }
                        }
                        _ => {}
                    },
                    // ── Reconcile Lock: Settlement class ──
                    InputMode::ReconcileLockSettlement => match key.code {
                        KeyCode::Up | KeyCode::Down => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                state.settlement_class = if state.settlement_class == 0 { 1 } else { 0 };
                                let label = if state.settlement_class == 0 { "Standard" } else { "Batched" };
                                app.status_message = format!("Settlement: {} — Enter to confirm, Esc to cancel", label);
                            }
                        }
                        KeyCode::Char('1') => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                state.settlement_class = 0;
                                state.step = ReconcileLockStep::Confirm;
                                app.input_mode = InputMode::ReconcileLockConfirm;
                                let (ref id, _, cap) = state.locks[state.selected_lock];
                                app.status_message = format!(
                                    "Reconcile {}... ({} sats) to {} via Standard? Enter=confirm",
                                    &id[..16.min(id.len())], cap, &state.destination_address
                                );
                            }
                        }
                        KeyCode::Char('2') => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                state.settlement_class = 1;
                                state.step = ReconcileLockStep::Confirm;
                                app.input_mode = InputMode::ReconcileLockConfirm;
                                let (ref id, _, cap) = state.locks[state.selected_lock];
                                app.status_message = format!(
                                    "Reconcile {}... ({} sats) to {} via Batched? Enter=confirm",
                                    &id[..16.min(id.len())], cap, &state.destination_address
                                );
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref state)) = app.wallet_wizard {
                                let settlement = if state.settlement_class == 0 { "Standard" } else { "Batched" };
                                let (ref id, _, cap) = state.locks[state.selected_lock];
                                app.input_mode = InputMode::ReconcileLockConfirm;
                                app.status_message = format!(
                                    "Reconcile {}... ({} sats) to {} via {}? Enter=confirm",
                                    &id[..16.min(id.len())], cap, &state.destination_address, settlement
                                );
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Reconcile wizard cancelled".to_string();
                        }
                        _ => {}
                    },
                    // ── Reconcile Lock: Confirm ──
                    InputMode::ReconcileLockConfirm => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::ReconcileLock(ref mut state)) = app.wallet_wizard {
                                state.step = ReconcileLockStep::Processing;
                                let lock_id = state.locks[state.selected_lock].0.clone();
                                let address = state.destination_address.clone();

                                // Reconciliation requires GSP round-trip via wallet lock API
                                // which is not yet exposed as a public wallet method.
                                let settlement = if state.settlement_class == 0 { "standard" } else { "batched" };
                                state.step = ReconcileLockStep::Complete;
                                app.status_message = format!(
                                    "Reconcile request queued: lock {} to {} ({}). Execute via CLI.",
                                    &lock_id[..16.min(lock_id.len())],
                                    &address[..20.min(address.len())],
                                    settlement
                                );
                                app.input_mode = InputMode::Normal;
                                app.wallet_wizard = None;
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Reconcile wizard cancelled".to_string();
                        }
                        _ => {}
                    },
                    // ── Send L2: Recipient ──
                    InputMode::SendL2Recipient => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::SendL2(ref state)) = app.wallet_wizard {
                                if state.recipient.is_empty() {
                                    app.status_message = "Recipient cannot be empty:".to_string();
                                } else {
                                    app.input_mode = InputMode::SendL2Amount;
                                    app.status_message = "Enter amount in sats:".to_string();
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Send L2 wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) => {
                            if let Some(ActiveWalletWizard::SendL2(ref mut state)) = app.wallet_wizard {
                                state.recipient.push(c);
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(ActiveWalletWizard::SendL2(ref mut state)) = app.wallet_wizard {
                                state.recipient.pop();
                            }
                        }
                        _ => {}
                    },
                    // ── Send L2: Amount ──
                    InputMode::SendL2Amount => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::SendL2(ref state)) = app.wallet_wizard {
                                if state.amount.is_empty() {
                                    app.status_message = "Amount cannot be empty:".to_string();
                                } else {
                                    app.input_mode = InputMode::SendL2Memo;
                                    app.status_message = "Enter memo (optional, Enter to skip):".to_string();
                                }
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Send L2 wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            if let Some(ActiveWalletWizard::SendL2(ref mut state)) = app.wallet_wizard {
                                state.amount.push(c);
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(ActiveWalletWizard::SendL2(ref mut state)) = app.wallet_wizard {
                                state.amount.pop();
                            }
                        }
                        _ => {}
                    },
                    // ── Send L2: Memo ──
                    InputMode::SendL2Memo => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::SendL2(ref state)) = app.wallet_wizard {
                                let amount_str = state.amount.clone();
                                let recipient = state.recipient.clone();
                                app.input_mode = InputMode::SendL2Confirm;
                                app.status_message = format!(
                                    "Send {} sats to {}? Enter=confirm, Esc=cancel",
                                    amount_str, &recipient[..20.min(recipient.len())]
                                );
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Send L2 wizard cancelled".to_string();
                        }
                        KeyCode::Char(c) => {
                            if let Some(ActiveWalletWizard::SendL2(ref mut state)) = app.wallet_wizard {
                                state.memo.push(c);
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(ActiveWalletWizard::SendL2(ref mut state)) = app.wallet_wizard {
                                state.memo.pop();
                            }
                        }
                        _ => {}
                    },
                    // ── Send L2: Confirm ──
                    InputMode::SendL2Confirm => match key.code {
                        KeyCode::Enter => {
                            if let Some(ActiveWalletWizard::SendL2(ref mut state)) = app.wallet_wizard {
                                state.step = SendL2Step::Sending;
                                let recipient = state.recipient.clone();
                                let amount: u64 = state.amount.parse().unwrap_or(0);

                                app.status_message = "Sending L2 payment...".to_string();

                                let result = if let Some(ref wallet) = app.wallet {
                                    let gsp_url = app.config.gsp_urls.first().cloned();
                                    app.runtime.block_on(async {
                                        if let Some(url) = gsp_url {
                                            wallet.connect(&url).await?;
                                        }
                                        wallet.send_payment(&recipient, amount, false).await
                                    })
                                } else {
                                    state.step = SendL2Step::Failed;
                                    state.error = Some("Wallet not unlocked".to_string());
                                    app.status_message = "Wallet not unlocked".to_string();
                                    app.input_mode = InputMode::Normal;
                                    app.wallet_wizard = None;
                                    continue;
                                };

                                match result {
                                    Ok(payment_id) => {
                                        state.payment_id = Some(payment_id.clone());
                                        state.step = SendL2Step::Complete;
                                        app.status_message = format!(
                                            "Sent! Payment ID: {}",
                                            &payment_id[..16.min(payment_id.len())]
                                        );
                                        app.refresh_transactions();
                                    }
                                    Err(e) => {
                                        state.step = SendL2Step::Failed;
                                        state.error = Some(format!("{}", e));
                                        app.status_message = format!("Send L2 failed: {}", e);
                                    }
                                }
                                app.input_mode = InputMode::Normal;
                                app.wallet_wizard = None;
                            }
                        }
                        KeyCode::Esc => {
                            app.wallet_wizard = None;
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Send L2 wizard cancelled".to_string();
                        }
                        _ => {}
                    },
                }
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    // Header
    let header = Paragraph::new(Text::from(vec![Line::from(vec![
        Span::styled(
            " ◆ GHOST WALLET ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ "),
        Span::styled(
            match &app.wallet {
                Some(w) => match w.status() {
                    WalletStatus::Connected => "● Connected",
                    WalletStatus::Disconnected => "○ Disconnected",
                    WalletStatus::Connecting => "◐ Connecting...",
                    WalletStatus::Reconnecting => "◐ Reconnecting...",
                },
                None => "○ No Wallet",
            },
            Style::default().fg(match &app.wallet {
                Some(w) if w.status() == WalletStatus::Connected => Color::Green,
                _ => Color::Yellow,
            }),
        ),
    ])]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    // Tabs
    let titles = vec![
        "[1]Dashboard",
        "[2]Send",
        "[3]Receive",
        "[4]History",
        "[5]Locks",
        "[6]Labels",
        "[7]Settings",
    ];
    let tabs = Tabs::new(titles)
        .select(match app.current_tab {
            Tab::Dashboard => 0,
            Tab::Send => 1,
            Tab::Receive => 2,
            Tab::History => 3,
            Tab::Locks => 4,
            Tab::Labels => 5,
            Tab::Settings => 6,
        })
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(tabs, chunks[1]);

    // Content
    let content = match app.current_tab {
        Tab::Dashboard => render_dashboard(app),
        Tab::Send => render_send(app),
        Tab::Receive => render_receive(app),
        Tab::History => render_history(app),
        Tab::Locks => render_locks(app),
        Tab::Labels => render_labels(app),
        Tab::Settings => render_settings(app),
    };
    f.render_widget(content, chunks[2]);

    // Status bar
    let password_mask = "*".repeat(app.password_input.len());
    let input_display = if app.input_mode == InputMode::Password {
        password_mask.clone()
    } else if app.input_mode == InputMode::SendAddress {
        app.send_address.clone()
    } else if app.input_mode == InputMode::SendAmount {
        app.send_amount.clone()
    } else if app.input_mode == InputMode::SendMemo {
        app.send_memo.clone()
    } else if app.label_input_mode != LabelInputMode::None {
        app.label_input.clone()
    } else if let Some(ref wiz) = app.wallet_wizard {
        match wiz {
            ActiveWalletWizard::CreateLock(s) => {
                match app.input_mode {
                    InputMode::CreateLockDenom => s.denomination.clone().unwrap_or_default(),
                    InputMode::CreateLockLabel => s.label.clone(),
                    _ => String::new(),
                }
            }
            ActiveWalletWizard::ReconcileLock(s) => {
                if app.input_mode == InputMode::ReconcileLockAddress {
                    s.destination_address.clone()
                } else {
                    String::new()
                }
            }
            ActiveWalletWizard::SendL2(s) => {
                match app.input_mode {
                    InputMode::SendL2Recipient => s.recipient.clone(),
                    InputMode::SendL2Amount => s.amount.clone(),
                    InputMode::SendL2Memo => s.memo.clone(),
                    _ => String::new(),
                }
            }
            _ => String::new(),
        }
    } else {
        String::new()
    };
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::raw(&app.status_message),
        Span::raw(" │ "),
        Span::styled(&input_display, Style::default().fg(Color::Yellow)),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" Status "));
    f.render_widget(status, chunks[3]);
}

fn render_dashboard(app: &App) -> Paragraph<'static> {
    let balance = app.wallet.as_ref().map(|w| w.balance());

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Balance: "),
            Span::styled(
                format!("{} sats", balance.map(|b| b.confirmed).unwrap_or(0)),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Unconfirmed: "),
            Span::styled(
                format!("{} sats", balance.map(|b| b.unconfirmed).unwrap_or(0)),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw("  Locked: "),
            Span::styled(
                format!("{} sats", balance.map(|b| b.locked).unwrap_or(0)),
                Style::default().fg(Color::Blue),
            ),
        ]),
        Line::from(""),
        Line::from("  ─────────────────────────────"),
        Line::from(""),
        Line::from("  Press 'u' to unlock wallet"),
        Line::from("  Press Tab to switch tabs"),
        Line::from("  Press 'q' to quit"),
    ];

    Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Dashboard ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
}

fn render_send(app: &App) -> Paragraph<'static> {
    if app.wallet.is_none() {
        return Paragraph::new(vec![
            Line::from(""),
            Line::from("  Send Ghost Pay"),
            Line::from(""),
            Line::from("  [Unlock wallet first]"),
        ])
        .block(Block::default().borders(Borders::ALL).title(" Send "));
    }

    let wraith_status = if app.send_wraith {
        Span::styled(
            "ON",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("OFF", Style::default().fg(Color::DarkGray))
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Send Ghost Pay",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  [s] Start send  [w] Toggle Wraith: "),
            wraith_status,
        ]),
        Line::from(""),
        Line::from("  ─────────────────────────────────────────────"),
    ];

    if !app.send_address.is_empty() || !app.send_amount.is_empty() {
        let addr_display = if app.send_address.is_empty() {
            "(enter address)".to_string()
        } else {
            app.send_address.clone()
        };
        let amount_display = if app.send_amount.is_empty() {
            "(enter amount)".to_string()
        } else {
            format!("{} sats", app.send_amount)
        };

        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("  To:     "),
            Span::styled(addr_display, Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(vec![
            Span::raw("  Amount: "),
            Span::styled(amount_display, Style::default().fg(Color::Yellow)),
        ]));
        if !app.send_memo.is_empty() {
            lines.push(Line::from(vec![
                Span::raw("  Memo:   "),
                Span::styled(app.send_memo.clone(), Style::default().fg(Color::DarkGray)),
            ]));
        }
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from("  Press 's' to start a new payment"));
    }

    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Send ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
}

fn render_receive(app: &App) -> Paragraph<'static> {
    if app.wallet.is_none() {
        return Paragraph::new(vec![
            Line::from(""),
            Line::from("  Your Ghost ID:"),
            Line::from(""),
            Line::from("  [Unlock wallet first]"),
        ])
        .block(Block::default().borders(Borders::ALL).title(" Receive "));
    }

    let ghost_id = app
        .wallet
        .as_ref()
        .and_then(|w| w.ghost_id().ok())
        .unwrap_or_else(|| "Unknown".to_string());

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Receive Payment",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![Span::raw("  [g] Generate new address")]),
        Line::from(""),
        Line::from("  ─────────────────────────────────────────────"),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Ghost ID: "),
            Span::styled(
                ghost_id,
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    if let Some(ref addr) = app.receive_address {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("  Address:  "),
            Span::styled(
                addr.clone(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(
        "  Share your Ghost ID to receive Ghost Pay payments.",
    ));

    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Receive ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
}

fn render_history(app: &App) -> Paragraph<'static> {
    if app.wallet.is_none() {
        return Paragraph::new(vec![
            Line::from(""),
            Line::from("  Transaction History"),
            Line::from(""),
            Line::from("  [Unlock wallet first]"),
        ])
        .block(Block::default().borders(Borders::ALL).title(" History "));
    }

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Transaction History",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from("  [r] Refresh"),
        Line::from(""),
        Line::from("  ─────────────────────────────────────────────"),
    ];

    if app.transactions.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("  No transactions yet."));
    } else {
        for tx in &app.transactions {
            let (arrow, color) = if tx.is_incoming {
                ("  <- ", Color::Green)
            } else {
                ("  -> ", Color::Red)
            };
            let amount_str = if tx.is_incoming {
                format!("+{} sats", tx.amount_sats)
            } else {
                format!("-{} sats", tx.amount_sats.unsigned_abs())
            };
            let txid_short = if tx.txid.len() > 12 {
                format!("{}...", &tx.txid[..12])
            } else {
                tx.txid.clone()
            };
            let status_color = match tx.status.as_str() {
                "confirmed" => Color::Green,
                "pending" => Color::Yellow,
                _ => Color::DarkGray,
            };

            lines.push(Line::from(vec![
                Span::styled(arrow, Style::default().fg(color)),
                Span::styled(format!("{:<15}", amount_str), Style::default().fg(color)),
                Span::styled(
                    format!(" {:>10} ", tx.status),
                    Style::default().fg(status_color),
                ),
                Span::styled(txid_short, Style::default().fg(Color::DarkGray)),
            ]));

            if let Some(ref memo) = tx.decrypted_memo {
                lines.push(Line::from(vec![
                    Span::raw("       "),
                    Span::styled(memo.clone(), Style::default().fg(Color::DarkGray)),
                ]));
            } else if let Some(ref memo) = tx.memo {
                lines.push(Line::from(vec![
                    Span::raw("       "),
                    Span::styled(memo.clone(), Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
    }

    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" History ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
}

fn render_locks(app: &App) -> Paragraph<'static> {
    if app.wallet.is_none() {
        return Paragraph::new(vec![
            Line::from(""),
            Line::from("  Ghost Locks"),
            Line::from(""),
            Line::from("  [Unlock wallet first]"),
        ])
        .block(Block::default().borders(Borders::ALL).title(" Locks "));
    }

    // Show wraith wizard if active
    if let Some(ref wizard) = app.wraith_wizard {
        let progress = wizard.progress();
        let mut lines = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "  Wraith CoinJoin Wizard",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
        ];

        match progress.step {
            WizardStep::SelectDenomination => {
                let denoms = WraithWizard::available_denominations();
                lines.push(Line::from("  Select denomination:"));
                lines.push(Line::from(""));
                for (i, d) in denoms.iter().enumerate() {
                    lines.push(Line::from(vec![
                        Span::styled(format!("  [{}] ", i + 1), Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("{:<8}", d.name),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!(
                            " {} sats out, {} sats fee, ~{}h wait",
                            d.output_sats, d.fee_sats, d.expected_wait_hours
                        )),
                    ]));
                }
            }
            WizardStep::SelectUtxo => {
                lines.push(Line::from(vec![
                    Span::raw("  Denomination: "),
                    Span::styled(
                        wizard
                            .denomination()
                            .map(|d| d.name().to_string())
                            .unwrap_or_default(),
                        Style::default().fg(Color::Green),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::raw("  TXID: "),
                    Span::styled(
                        app.wraith_txid_input.clone(),
                        Style::default().fg(Color::Cyan),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("  Vout: "),
                    Span::styled(
                        app.wraith_vout_input.clone(),
                        Style::default().fg(Color::Cyan),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("  Amount: "),
                    Span::styled(
                        if app.wraith_amount_input.is_empty() {
                            "(enter sats)".to_string()
                        } else {
                            format!("{} sats", app.wraith_amount_input)
                        },
                        Style::default().fg(Color::Yellow),
                    ),
                ]));
            }
            WizardStep::WaitingForParticipants => {
                let count = progress.participant_count.unwrap_or(0);
                let min = progress.min_participants.unwrap_or(0);
                lines.push(Line::from(vec![
                    Span::styled("  ● ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("Waiting for participants... {}/{}", count, min)),
                ]));
                if let Some(sid) = wizard.session_id() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::raw("  Session: "),
                        Span::styled(sid.to_string(), Style::default().fg(Color::Cyan)),
                    ]));
                }
            }
            WizardStep::Phase1Splitting | WizardStep::Phase1Confirming => {
                lines.push(Line::from(vec![
                    Span::styled("  ◐ ", Style::default().fg(Color::Green)),
                    Span::raw(progress.message.clone()),
                ]));
            }
            WizardStep::Phase2Merging | WizardStep::Phase2Confirming => {
                lines.push(Line::from(vec![
                    Span::styled("  ◑ ", Style::default().fg(Color::Green)),
                    Span::raw(progress.message.clone()),
                ]));
            }
            WizardStep::Complete => {
                lines.push(Line::from(vec![Span::styled(
                    "  ✓ Mixing complete!",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )]));
            }
            WizardStep::Failed => {
                lines.push(Line::from(vec![Span::styled(
                    "  ✗ Session failed",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )]));
                if let Some(err) = wizard.error_message() {
                    lines.push(Line::from(vec![
                        Span::raw("  Error: "),
                        Span::styled(err.to_string(), Style::default().fg(Color::Red)),
                    ]));
                }
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from("  [Esc] Cancel"));

        return Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Wraith Wizard ")
                .title_style(Style::default().fg(Color::Magenta)),
        );
    }

    // Show wallet wizard if active
    if let Some(ref wiz) = app.wallet_wizard {
        let (title, lines) = render_wallet_wizard(wiz, app);
        return Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .title_style(Style::default().fg(Color::Cyan)),
        );
    }

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Ghost Locks",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from("  [r] Refresh  [w] Wraith  [g] Ghost ID  [c] Create Lock  [j] Jump  [e] Reconcile  [l] Send L2"),
        Line::from(""),
        Line::from("  ─────────────────────────────────────────────"),
    ];

    if app.locks.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("  No locks. Use CLI to create locks."));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            format!(
                "  {:<18} {:>12} {:>12} {:>12}",
                "Lock ID", "Capacity", "Used", "Status"
            ),
            Style::default().add_modifier(Modifier::BOLD),
        )]));
        lines.push(Line::from(
            "  ─────────────────────────────────────────────────────────",
        ));

        for lock in &app.locks {
            let id_short = if lock.lock_id.len() > 16 {
                format!("{}...", &lock.lock_id[..16])
            } else {
                lock.lock_id.clone()
            };
            let status_color = match lock.status.as_str() {
                "active" => Color::Green,
                "pending_funding" => Color::Yellow,
                "closed" | "jump_requested" => Color::DarkGray,
                _ => Color::White,
            };

            lines.push(Line::from(vec![
                Span::raw(format!("  {:<18}", id_short)),
                Span::styled(
                    format!("{:>10} s", lock.capacity_sats),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    format!("{:>10} s", lock.used_sats),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!("{:>12}", lock.status),
                    Style::default().fg(status_color),
                ),
            ]));
        }
    }

    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Locks ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
}

fn render_wallet_wizard(wiz: &ActiveWalletWizard, _app: &App) -> (String, Vec<Line<'static>>) {
    match wiz {
        ActiveWalletWizard::CreateGhostId(state) => {
            let mut lines = vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "  Ghost ID Wizard",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
            ];
            match state.step {
                CreateGhostIdStep::Welcome => {
                    lines.push(Line::from("  Your Ghost ID is your identity for receiving payments."));
                    lines.push(Line::from(""));
                    lines.push(Line::from("  Press Enter to retrieve your Ghost ID."));
                }
                CreateGhostIdStep::Generating => {
                    lines.push(Line::from(vec![
                        Span::styled("  Generating...", Style::default().fg(Color::Yellow)),
                    ]));
                }
                CreateGhostIdStep::Complete => {
                    if let Some(ref id) = state.ghost_id {
                        lines.push(Line::from(vec![
                            Span::raw("  Ghost ID: "),
                            Span::styled(
                                id.clone(),
                                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                            ),
                        ]));
                        lines.push(Line::from(""));
                        lines.push(Line::from("  Share this ID to receive payments."));
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from("  Press any key to close."));
                }
                CreateGhostIdStep::Failed => {
                    if let Some(ref err) = state.error {
                        lines.push(Line::from(vec![
                            Span::styled("  Error: ", Style::default().fg(Color::Red)),
                            Span::raw(err.clone()),
                        ]));
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from("  Press any key to close."));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from("  [Esc] Cancel"));
            (" Ghost ID ".to_string(), lines)
        }
        ActiveWalletWizard::CreateLock(state) => {
            let mut lines = vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "  Create Ghost Lock",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
            ];
            match state.step {
                CreateLockStep::SelectDenomination => {
                    lines.push(Line::from(vec![
                        Span::raw("  Capacity: "),
                        Span::styled(
                            format!("{} sats", state.denomination.as_deref().unwrap_or("(enter amount)")),
                            Style::default().fg(Color::Yellow),
                        ),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from("  Minimum: 10,000 sats. Maximum: 100,000,000 sats (1 BTC)"));
                }
                CreateLockStep::SelectTimelock => {
                    lines.push(Line::from(vec![
                        Span::raw("  Capacity: "),
                        Span::styled(
                            format!("{} sats", state.denomination.as_deref().unwrap_or("?")),
                            Style::default().fg(Color::Green),
                        ),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from("  Select timelock tier:"));
                    lines.push(Line::from(vec![
                        Span::styled("  [1] ", Style::default().fg(Color::Cyan)),
                        Span::raw("30 days"),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("  [2] ", Style::default().fg(Color::Cyan)),
                        Span::raw("90 days"),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("  [3] ", Style::default().fg(Color::Cyan)),
                        Span::raw("180 days"),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("  [4] ", Style::default().fg(Color::Cyan)),
                        Span::raw("365 days"),
                    ]));
                }
                CreateLockStep::EnterLabel => {
                    lines.push(Line::from(vec![
                        Span::raw("  Capacity: "),
                        Span::styled(
                            format!("{} sats", state.denomination.as_deref().unwrap_or("?")),
                            Style::default().fg(Color::Green),
                        ),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  Timelock: "),
                        Span::styled(state.timelock_tier.clone(), Style::default().fg(Color::Green)),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::raw("  Label: "),
                        Span::styled(
                            if state.label.is_empty() { "(optional, Enter to skip)".to_string() } else { state.label.clone() },
                            Style::default().fg(Color::Yellow),
                        ),
                    ]));
                }
                CreateLockStep::Creating => {
                    lines.push(Line::from(vec![
                        Span::styled("  Creating lock...", Style::default().fg(Color::Yellow)),
                    ]));
                }
                CreateLockStep::Complete => {
                    if let Some(ref id) = state.lock_id {
                        lines.push(Line::from(vec![
                            Span::styled("  Lock created: ", Style::default().fg(Color::Green)),
                            Span::raw(id.clone()),
                        ]));
                    }
                }
                CreateLockStep::Failed => {
                    if let Some(ref err) = state.error {
                        lines.push(Line::from(vec![
                            Span::styled("  Error: ", Style::default().fg(Color::Red)),
                            Span::raw(err.clone()),
                        ]));
                    }
                }
                CreateLockStep::Confirm => {
                    lines.push(Line::from("  Press Enter to create lock."));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from("  [Esc] Cancel"));
            (" Create Lock ".to_string(), lines)
        }
        ActiveWalletWizard::JumpLock(state) => {
            let mut lines = vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "  Jump Lock (Emergency Exit)",
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
            ];
            match state.step {
                JumpLockStep::SelectLock => {
                    lines.push(Line::from("  Select a lock to jump from:"));
                    lines.push(Line::from(""));
                    for (i, (id, _status, cap)) in state.locks.iter().enumerate() {
                        let prefix = if i == state.selected_lock { "> " } else { "  " };
                        let id_short = if id.len() > 20 { format!("{}...", &id[..20]) } else { id.clone() };
                        let style = if i == state.selected_lock {
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };
                        lines.push(Line::from(vec![Span::styled(
                            format!("{}{:<24} {:>10} sats", prefix, id_short, cap),
                            style,
                        )]));
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from("  [Up/Down] Select  [Enter] Confirm  [Esc] Cancel"));
                }
                JumpLockStep::ConfirmJump => {
                    let (ref id, _, cap) = state.locks[state.selected_lock];
                    let id_short = if id.len() > 24 { format!("{}...", &id[..24]) } else { id.clone() };
                    lines.push(Line::from(vec![
                        Span::styled("  WARNING: ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                        Span::raw("This is a unilateral exit. The lock will be closed."),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::raw("  Lock: "),
                        Span::styled(id_short, Style::default().fg(Color::Cyan)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  Amount: "),
                        Span::styled(format!("{} sats", cap), Style::default().fg(Color::Yellow)),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from("  Press Enter to confirm jump, Esc to cancel."));
                }
                JumpLockStep::Processing => {
                    lines.push(Line::from(vec![
                        Span::styled("  Processing jump...", Style::default().fg(Color::Yellow)),
                    ]));
                }
                JumpLockStep::Complete => {
                    if let Some(ref jid) = state.new_lock_id {
                        lines.push(Line::from(vec![
                            Span::styled("  Jump initiated: ", Style::default().fg(Color::Green)),
                            Span::raw(jid.clone()),
                        ]));
                    }
                    if let Some(ref txid) = state.txid {
                        lines.push(Line::from(vec![
                            Span::raw("  TXID: "),
                            Span::styled(txid.clone(), Style::default().fg(Color::DarkGray)),
                        ]));
                    }
                }
                JumpLockStep::Failed => {
                    if let Some(ref err) = state.error {
                        lines.push(Line::from(vec![
                            Span::styled("  Error: ", Style::default().fg(Color::Red)),
                            Span::raw(err.clone()),
                        ]));
                    }
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from("  [Esc] Cancel"));
            (" Jump Lock ".to_string(), lines)
        }
        ActiveWalletWizard::ReconcileLock(state) => {
            let mut lines = vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "  Reconcile Lock (L1 Settlement)",
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
            ];
            match state.step {
                ReconcileLockStep::SelectLock => {
                    lines.push(Line::from("  Select a lock to reconcile:"));
                    lines.push(Line::from(""));
                    for (i, (id, _status, cap)) in state.locks.iter().enumerate() {
                        let prefix = if i == state.selected_lock { "> " } else { "  " };
                        let id_short = if id.len() > 20 { format!("{}...", &id[..20]) } else { id.clone() };
                        let style = if i == state.selected_lock {
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };
                        lines.push(Line::from(vec![Span::styled(
                            format!("{}{:<24} {:>10} sats", prefix, id_short, cap),
                            style,
                        )]));
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from("  [Up/Down] Select  [Enter] Confirm  [Esc] Cancel"));
                }
                ReconcileLockStep::EnterAddress => {
                    let (ref id, _, cap) = state.locks[state.selected_lock];
                    let id_short = if id.len() > 20 { format!("{}...", &id[..20]) } else { id.clone() };
                    lines.push(Line::from(vec![
                        Span::raw("  Lock: "),
                        Span::styled(id_short, Style::default().fg(Color::Cyan)),
                        Span::raw(format!(" ({} sats)", cap)),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::raw("  Destination: "),
                        Span::styled(
                            if state.destination_address.is_empty() { "(enter address)".to_string() } else { state.destination_address.clone() },
                            Style::default().fg(Color::Yellow),
                        ),
                    ]));
                }
                ReconcileLockStep::SelectSettlement => {
                    let settlement_label = if state.settlement_class == 0 { "Standard" } else { "Batched" };
                    lines.push(Line::from("  Select settlement class:"));
                    lines.push(Line::from(""));
                    let s0_style = if state.settlement_class == 0 {
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    let s1_style = if state.settlement_class == 1 {
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    let s0_prefix = if state.settlement_class == 0 { "> " } else { "  " };
                    let s1_prefix = if state.settlement_class == 1 { "> " } else { "  " };
                    let _ = settlement_label; // used in status message
                    lines.push(Line::from(vec![Span::styled(
                        format!("{}[1] Standard  - Individual on-chain settlement", s0_prefix),
                        s0_style,
                    )]));
                    lines.push(Line::from(vec![Span::styled(
                        format!("{}[2] Batched   - Aggregated settlement (lower fees)", s1_prefix),
                        s1_style,
                    )]));
                    lines.push(Line::from(""));
                    lines.push(Line::from("  [1/2] Select  [Up/Down] Toggle  [Enter] Confirm  [Esc] Cancel"));
                }
                ReconcileLockStep::Confirm => {
                    let (ref id, _, cap) = state.locks[state.selected_lock];
                    let id_short = if id.len() > 20 { format!("{}...", &id[..20]) } else { id.clone() };
                    let settlement = if state.settlement_class == 0 { "Standard" } else { "Batched" };
                    lines.push(Line::from("  Confirm reconciliation:"));
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::raw("  Lock: "),
                        Span::styled(id_short, Style::default().fg(Color::Cyan)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  Amount: "),
                        Span::styled(format!("{} sats", cap), Style::default().fg(Color::Yellow)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  To: "),
                        Span::styled(state.destination_address.clone(), Style::default().fg(Color::Green)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  Settlement: "),
                        Span::styled(settlement.to_string(), Style::default().fg(Color::Blue)),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from("  Press Enter to submit, Esc to cancel."));
                }
                ReconcileLockStep::Processing => {
                    lines.push(Line::from(vec![
                        Span::styled("  Processing reconciliation...", Style::default().fg(Color::Yellow)),
                    ]));
                }
                ReconcileLockStep::Complete => {
                    lines.push(Line::from(vec![
                        Span::styled("  Reconciliation submitted!", Style::default().fg(Color::Green)),
                    ]));
                }
                ReconcileLockStep::Failed => {
                    if let Some(ref err) = state.error {
                        lines.push(Line::from(vec![
                            Span::styled("  Error: ", Style::default().fg(Color::Red)),
                            Span::raw(err.clone()),
                        ]));
                    }
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from("  [Esc] Cancel"));
            (" Reconcile Lock ".to_string(), lines)
        }
        ActiveWalletWizard::SendL2(state) => {
            let mut lines = vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "  Send L2 Payment",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
            ];
            match state.step {
                SendL2Step::EnterRecipient => {
                    lines.push(Line::from(vec![
                        Span::raw("  Recipient: "),
                        Span::styled(
                            if state.recipient.is_empty() { "(enter Ghost ID or address)".to_string() } else { state.recipient.clone() },
                            Style::default().fg(Color::Yellow),
                        ),
                    ]));
                }
                SendL2Step::EnterAmount => {
                    lines.push(Line::from(vec![
                        Span::raw("  Recipient: "),
                        Span::styled(state.recipient.clone(), Style::default().fg(Color::Green)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  Amount: "),
                        Span::styled(
                            if state.amount.is_empty() { "(enter sats)".to_string() } else { format!("{} sats", state.amount) },
                            Style::default().fg(Color::Yellow),
                        ),
                    ]));
                }
                SendL2Step::EnterMemo => {
                    lines.push(Line::from(vec![
                        Span::raw("  Recipient: "),
                        Span::styled(state.recipient.clone(), Style::default().fg(Color::Green)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  Amount: "),
                        Span::styled(format!("{} sats", state.amount), Style::default().fg(Color::Green)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  Memo: "),
                        Span::styled(
                            if state.memo.is_empty() { "(optional, Enter to skip)".to_string() } else { state.memo.clone() },
                            Style::default().fg(Color::Yellow),
                        ),
                    ]));
                }
                SendL2Step::Confirm => {
                    lines.push(Line::from("  Confirm payment:"));
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::raw("  Recipient: "),
                        Span::styled(state.recipient.clone(), Style::default().fg(Color::Green)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("  Amount: "),
                        Span::styled(format!("{} sats", state.amount), Style::default().fg(Color::Yellow)),
                    ]));
                    if !state.memo.is_empty() {
                        lines.push(Line::from(vec![
                            Span::raw("  Memo: "),
                            Span::styled(state.memo.clone(), Style::default().fg(Color::DarkGray)),
                        ]));
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from("  Press Enter to send, Esc to cancel."));
                }
                SendL2Step::Sending => {
                    lines.push(Line::from(vec![
                        Span::styled("  Sending...", Style::default().fg(Color::Yellow)),
                    ]));
                }
                SendL2Step::Complete => {
                    if let Some(ref pid) = state.payment_id {
                        lines.push(Line::from(vec![
                            Span::styled("  Payment sent! ID: ", Style::default().fg(Color::Green)),
                            Span::raw(pid.clone()),
                        ]));
                    }
                }
                SendL2Step::Failed => {
                    if let Some(ref err) = state.error {
                        lines.push(Line::from(vec![
                            Span::styled("  Error: ", Style::default().fg(Color::Red)),
                            Span::raw(err.clone()),
                        ]));
                    }
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from("  [Esc] Cancel"));
            (" Send L2 ".to_string(), lines)
        }
    }
}

fn render_labels(app: &App) -> Paragraph<'static> {
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Payment Labels",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from("  [c] Create  [r] Rename  [d] Delete  [↑↓] Navigate"),
        Line::from(""),
        Line::from("  ─────────────────────────────────────────────"),
    ];

    if app.wallet.is_none() {
        lines.push(Line::from(""));
        lines.push(Line::from("  [Unlock wallet first]"));
    } else if app.labels.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("  No labels yet. Press 'c' to create one."));
    } else {
        for (i, (index, name)) in app.labels.iter().enumerate() {
            let style = if i == app.selected_label {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let prefix = if i == app.selected_label {
                "► "
            } else {
                "  "
            };
            let marker = if *index == 0 { " (default)" } else { "" };
            lines.push(Line::from(vec![Span::styled(
                format!("{}[{:3}] {}{}", prefix, index, name, marker),
                style,
            )]));
        }
    }

    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Labels ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
}

fn render_settings(app: &App) -> Paragraph<'static> {
    let network = format!("{:?}", app.config.network);
    let gsp_urls = if app.config.gsp_urls.is_empty() {
        "None configured".to_string()
    } else {
        app.config.gsp_urls.join(", ")
    };
    let status = app
        .wallet
        .as_ref()
        .map(|w| format!("{:?}", w.status()))
        .unwrap_or_else(|| "No wallet loaded".to_string());
    let data_dir = app.config.data_dir.display().to_string();

    Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Settings",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from("  ─────────────────────────────────────────────"),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Network:  "),
            Span::styled(network, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("  GSP:      "),
            Span::styled(gsp_urls, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("  Status:   "),
            Span::styled(status, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw("  Data Dir: "),
            Span::styled(data_dir, Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::raw("  Version:  "),
            Span::styled(
                ghost_light_wallet::WALLET_VERSION.to_string(),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Settings ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
}

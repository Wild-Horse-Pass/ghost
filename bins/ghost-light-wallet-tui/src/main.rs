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
use ghost_light_wallet::wraith::{WraithWizard, WizardStep};
use ghost_light_wallet::{LightWallet, WalletConfig, WalletStatus};

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

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()>
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
                                match wallet.generate_address(ghost_light_wallet::payments::AddressType::GhostPay) {
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
                                KeyCode::Char('s') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
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

                        // Locks tab: 'r' to refresh, 'w' to start wraith wizard
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
                        KeyCode::Backspace => { app.send_address.pop(); }
                        _ => {}
                    },
                    InputMode::SendAmount => match key.code {
                        KeyCode::Enter => {
                            app.input_mode = InputMode::SendMemo;
                            app.status_message = "Enter memo (optional, Enter to skip):".to_string();
                        }
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                            app.status_message = "Cancelled".to_string();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => app.send_amount.push(c),
                        KeyCode::Backspace => { app.send_amount.pop(); }
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
                                    app.status_message = format!("Sent! ID: {}", &payment_id[..16.min(payment_id.len())]);
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
                        KeyCode::Backspace => { app.send_memo.pop(); }
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
                                        denom.name(), denom.input_sats()
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
                        KeyCode::Backspace => { app.wraith_txid_input.pop(); }
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
                        KeyCode::Backspace => { app.wraith_vout_input.pop(); }
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
                                    Ok(()) => {
                                        match wizard.join() {
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
                                        }
                                    }
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
                        KeyCode::Backspace => { app.wraith_amount_input.pop(); }
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
        Span::styled("ON", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("OFF", Style::default().fg(Color::DarkGray))
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Send Ghost Pay", Style::default().add_modifier(Modifier::BOLD)),
        ]),
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
        Line::from(vec![
            Span::styled("  Receive Payment", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  [g] Generate new address"),
        ]),
        Line::from(""),
        Line::from("  ─────────────────────────────────────────────"),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Ghost ID: "),
            Span::styled(ghost_id, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]),
    ];

    if let Some(ref addr) = app.receive_address {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("  Address:  "),
            Span::styled(addr.clone(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
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
        Line::from(vec![
            Span::styled("  Transaction History", Style::default().add_modifier(Modifier::BOLD)),
        ]),
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
                Span::styled(
                    format!("{:<15}", amount_str),
                    Style::default().fg(color),
                ),
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
            Line::from(vec![
                Span::styled("  Wraith CoinJoin Wizard", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            ]),
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
                        Span::styled(format!("{:<8}", d.name), Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(format!(" {} sats out, {} sats fee, ~{}h wait", d.output_sats, d.fee_sats, d.expected_wait_hours)),
                    ]));
                }
            }
            WizardStep::SelectUtxo => {
                lines.push(Line::from(vec![
                    Span::raw("  Denomination: "),
                    Span::styled(
                        wizard.denomination().map(|d| d.name().to_string()).unwrap_or_default(),
                        Style::default().fg(Color::Green),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::raw("  TXID: "),
                    Span::styled(app.wraith_txid_input.clone(), Style::default().fg(Color::Cyan)),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("  Vout: "),
                    Span::styled(app.wraith_vout_input.clone(), Style::default().fg(Color::Cyan)),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("  Amount: "),
                    Span::styled(
                        if app.wraith_amount_input.is_empty() { "(enter sats)".to_string() } else { format!("{} sats", app.wraith_amount_input) },
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
                lines.push(Line::from(vec![
                    Span::styled("  ✓ Mixing complete!", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                ]));
            }
            WizardStep::Failed => {
                lines.push(Line::from(vec![
                    Span::styled("  ✗ Session failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                ]));
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

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Ghost Locks", Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from("  [r] Refresh  [w] Wraith Wizard"),
        Line::from(""),
        Line::from("  ─────────────────────────────────────────────"),
    ];

    if app.locks.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(
            "  No locks. Use CLI to create locks.",
        ));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<18} {:>12} {:>12} {:>12}", "Lock ID", "Capacity", "Used", "Status"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from("  ─────────────────────────────────────────────────────────"));

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
        Line::from(vec![
            Span::styled("  Settings", Style::default().add_modifier(Modifier::BOLD)),
        ]),
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

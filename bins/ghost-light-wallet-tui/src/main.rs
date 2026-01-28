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
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs},
    Frame, Terminal,
};

use bitcoin::Network;
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
    Settings,
}

struct App {
    wallet: Option<LightWallet>,
    current_tab: Tab,
    should_quit: bool,
    status_message: String,
    password_input: String,
    input_mode: InputMode,
}

#[derive(PartialEq)]
enum InputMode {
    Normal,
    Password,
    Amount,
    Address,
}

impl App {
    fn new() -> Self {
        Self {
            wallet: None,
            current_tab: Tab::Dashboard,
            should_quit: false,
            status_message: "Press 'u' to unlock wallet, 'q' to quit".to_string(),
            password_input: String::new(),
            input_mode: InputMode::Normal,
        }
    }

    fn next_tab(&mut self) {
        self.current_tab = match self.current_tab {
            Tab::Dashboard => Tab::Send,
            Tab::Send => Tab::Receive,
            Tab::Receive => Tab::History,
            Tab::History => Tab::Locks,
            Tab::Locks => Tab::Settings,
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
            Tab::Settings => Tab::Locks,
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

    // Create app
    let mut app = App::new();

    // Try to load existing wallet
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

    // Main loop
    let res = run_app(&mut terminal, &mut app, config);

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
    _config: WalletConfig,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.input_mode {
                    InputMode::Normal => match key.code {
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
                        KeyCode::Char('6') => app.current_tab = Tab::Settings,
                        KeyCode::Char('u') => {
                            app.input_mode = InputMode::Password;
                            app.status_message = "Enter password:".to_string();
                        }
                        _ => {}
                    },
                    InputMode::Password => match key.code {
                        KeyCode::Enter => {
                            app.status_message = format!("Unlocking wallet...");
                            app.password_input.clear();
                            app.input_mode = InputMode::Normal;
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
                    _ => {}
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
        .split(f.size());

    // Header
    let header = Paragraph::new(Text::from(vec![
        Line::from(vec![
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
        ]),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    // Tabs
    let titles = vec!["[1]Dashboard", "[2]Send", "[3]Receive", "[4]History", "[5]Locks", "[6]Settings"];
    let tabs = Tabs::new(titles)
        .select(match app.current_tab {
            Tab::Dashboard => 0,
            Tab::Send => 1,
            Tab::Receive => 2,
            Tab::History => 3,
            Tab::Locks => 4,
            Tab::Settings => 5,
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
        Tab::Settings => render_settings(app),
    };
    f.render_widget(content, chunks[2]);

    // Status bar
    let password_mask = "*".repeat(app.password_input.len());
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::raw(&app.status_message),
        Span::raw(" │ "),
        Span::styled(
            if app.input_mode == InputMode::Password {
                password_mask.as_str()
            } else {
                ""
            },
            Style::default().fg(Color::Yellow),
        ),
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
                format!(
                    "{} sats",
                    balance.map(|b| b.confirmed).unwrap_or(0)
                ),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Unconfirmed: "),
            Span::styled(
                format!(
                    "{} sats",
                    balance.map(|b| b.unconfirmed).unwrap_or(0)
                ),
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

fn render_send(_app: &App) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(""),
        Line::from("  Send Ghost Pay"),
        Line::from(""),
        Line::from("  [Unlock wallet first]"),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Send "))
}

fn render_receive(_app: &App) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(""),
        Line::from("  Your Ghost ID:"),
        Line::from(""),
        Line::from("  [Unlock wallet first]"),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Receive "))
}

fn render_history(_app: &App) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(""),
        Line::from("  Transaction History"),
        Line::from(""),
        Line::from("  [No transactions yet]"),
    ])
    .block(Block::default().borders(Borders::ALL).title(" History "))
}

fn render_locks(_app: &App) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(""),
        Line::from("  Ghost Locks"),
        Line::from(""),
        Line::from("  [No locks yet]"),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Locks "))
}

fn render_settings(_app: &App) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(""),
        Line::from("  Settings"),
        Line::from(""),
        Line::from("  Network: Regtest"),
        Line::from("  GSP: Not connected"),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Settings "))
}

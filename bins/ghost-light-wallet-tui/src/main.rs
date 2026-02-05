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
}

#[derive(PartialEq)]
#[allow(dead_code)]
enum InputMode {
    Normal,
    Password,
    Amount,
    Address,
}

#[derive(PartialEq)]
enum LabelInputMode {
    None,
    Creating,
    Renaming(u32),
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
            labels: vec![(0, "Uncategorized".to_string())],
            selected_label: 0,
            label_input: String::new(),
            label_input_mode: LabelInputMode::None,
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
                            app.status_message = "Unlocking wallet...".to_string();
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

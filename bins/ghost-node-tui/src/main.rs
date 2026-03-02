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
//| FILE: main.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Node TUI - Terminal dashboard for Ghost Node operators
//!
//! A retro-style terminal interface for monitoring Bitcoin L1, Ghost Pay L2,
//! mining operations, and managing multiple nodes.

use std::io;
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
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame, Terminal,
};
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

mod api;
mod app;
mod config;
mod pages;
mod setup;
mod theme;
mod widgets;
mod wizard;

use app::{App, InputMode, Tab};
use config::SwarmConfig;
use wizard::WizardAction;

#[derive(Parser, Debug)]
#[command(name = "ghost-node-tui")]
#[command(author, version, about = "Ghost Node Terminal Dashboard")]
struct Args {
    /// Node URL (overrides config default)
    #[arg(short, long)]
    url: Option<String>,

    /// Config file path
    #[arg(short, long)]
    config: Option<String>,

    /// Log level
    #[arg(short, long, default_value = "warn")]
    log_level: String,
}

#[derive(Debug)]
enum AppEvent {
    Tick,
    Key(KeyCode, KeyModifiers),
    Resize(#[allow(dead_code)] u16, #[allow(dead_code)] u16),
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let log_level = match args.log_level.to_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::WARN,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_writer(io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Load config
    let mut swarm_config = match &args.config {
        Some(path) => SwarmConfig::load_from(&std::path::PathBuf::from(path))?,
        None => SwarmConfig::load()?,
    };

    // Override with CLI args
    if let Some(url) = args.url {
        swarm_config.nodes.clear();
        swarm_config.nodes.push(config::NodeEntry {
            name: "CLI Node".to_string(),
            url,
            default: true,
            auth_token: None,
            hmac_secret: None,
            group: None,
            notes: None,
        });
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(swarm_config);

    // Create API client for active node
    if let Some(node) = app.active_node() {
        app.api_client = Some(create_client(
            &node.url,
            node.auth_token.as_deref(),
            node.hmac_secret.as_deref(),
        ));
    }

    // Run app
    let result = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<AppEvent>(100);

    // Spawn event handler
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        loop {
            if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    let _ = tx_clone.send(AppEvent::Key(key.code, key.modifiers)).await;
                } else if let Ok(Event::Resize(w, h)) = event::read() {
                    let _ = tx_clone.send(AppEvent::Resize(w, h)).await;
                }
            }
        }
    });

    // Spawn tick handler
    let tx_tick = tx.clone();
    let tick_rate = Duration::from_millis(250);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tick_rate).await;
            let _ = tx_tick.send(AppEvent::Tick).await;
        }
    });

    // Initial data fetch
    refresh_data(app).await;

    let mut tick_count = 0u64;
    let refresh_interval = app.swarm.settings.refresh_interval_secs;

    loop {
        // Draw UI
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Header
                    Constraint::Min(10),   // Content
                    Constraint::Length(3), // Footer
                ])
                .split(f.area());

            widgets::render_header(f, chunks[0], app);
            pages::render_page(f, chunks[1], app);
            widgets::render_footer(f, chunks[2], app);

            // Render overlays
            if matches!(app.input_mode, InputMode::Help) {
                widgets::render_help_overlay(f, f.area());
            }
            if matches!(app.input_mode, InputMode::ConfirmAction) {
                widgets::render_confirm_dialog(f, f.area(), app);
            }
            if matches!(app.input_mode, InputMode::WizardPicker) {
                render_wizard_picker(f, f.area());
            }
            if let Some(ref wiz) = app.active_wizard {
                wizard::render::render_wizard(f, f.area(), wiz);
            }
        })?;

        // Handle events
        if let Some(event) = rx.recv().await {
            match event {
                AppEvent::Key(code, modifiers) => {
                    if handle_input(app, code, modifiers).await {
                        break;
                    }
                }
                AppEvent::Tick => {
                    tick_count += 1;
                    // Refresh data every N ticks (based on refresh_interval)
                    if tick_count.is_multiple_of(refresh_interval * 4) {
                        refresh_data(app).await;
                    }
                }
                AppEvent::Resize(_, _) => {
                    // Terminal will redraw automatically
                }
            }
        }
    }

    Ok(())
}

async fn handle_input(app: &mut App, code: KeyCode, modifiers: KeyModifiers) -> bool {
    // Handle active wizard first — all keys go to wizard when one is open
    if let Some(ref mut wiz) = app.active_wizard {
        match wiz.handle_key(code) {
            WizardAction::Continue => {}
            WizardAction::Submit => {
                let wizard_id = app
                    .active_wizard
                    .as_ref()
                    .and_then(|w| w.steps.first().map(|s| s.id))
                    .unwrap_or("");

                if wizard_id == "welcome" {
                    let fields = app.active_wizard.as_ref().unwrap().fields.clone();
                    let config_dir = std::path::PathBuf::from("/etc/ghost");
                    let data_dir = dirs::home_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                        .join(".ghost/data");

                    match crate::setup::apply_initial_setup(&fields, &config_dir, &data_dir) {
                        Ok(result) => {
                            app.status_message = format!(
                                "Setup complete! Node: {}... Config: {}",
                                &result.node_id_hex[..16],
                                result.config_path.display()
                            );
                        }
                        Err(e) => {
                            app.status_message = format!("Setup failed: {}", e);
                        }
                    }
                } else {
                    app.status_message = format!("Wizard '{}' submitted", wizard_id);
                }
                app.active_wizard = None;
            }
            WizardAction::Close => {
                app.active_wizard = None;
            }
        }
        return false;
    }

    // Handle input mode first
    match app.input_mode {
        InputMode::Normal => {}
        InputMode::Help => {
            // Any key closes help
            app.input_mode = InputMode::Normal;
            return false;
        }
        InputMode::NodeUrl => {
            match code {
                KeyCode::Esc => {
                    app.input_mode = InputMode::Normal;
                    app.input_buffer.clear();
                    app.status_message.clear();
                    return false;
                }
                KeyCode::Enter => {
                    // Add new node with the URL
                    if !app.input_buffer.is_empty() {
                        let url = app.input_buffer.clone();
                        let new_node = config::NodeEntry {
                            name: extract_hostname(&url),
                            url: url.clone(),
                            default: app.swarm.nodes.is_empty(),
                            auth_token: None,
                            hmac_secret: None,
                            group: None,
                            notes: None,
                        };
                        app.swarm.nodes.push(new_node);
                        save_swarm_config(app);
                        app.status_message = format!("Added node: {}", url);
                    }
                    app.input_mode = InputMode::Normal;
                    app.input_buffer.clear();
                    return false;
                }
                KeyCode::Char(c) => {
                    app.input_buffer.push(c);
                    return false;
                }
                KeyCode::Backspace => {
                    app.input_buffer.pop();
                    return false;
                }
                _ => return false,
            }
        }
        InputMode::NodeName => {
            match code {
                KeyCode::Esc => {
                    app.input_mode = InputMode::Normal;
                    app.input_buffer.clear();
                    app.status_message.clear();
                    return false;
                }
                KeyCode::Enter => {
                    // Rename selected node
                    if !app.input_buffer.is_empty() && app.selected_row < app.swarm.nodes.len() {
                        let new_name = app.input_buffer.clone();
                        app.swarm.nodes[app.selected_row].name = new_name.clone();
                        save_swarm_config(app);
                        app.status_message = format!("Renamed to: {}", new_name);
                    }
                    app.input_mode = InputMode::Normal;
                    app.input_buffer.clear();
                    return false;
                }
                KeyCode::Char(c) => {
                    app.input_buffer.push(c);
                    return false;
                }
                KeyCode::Backspace => {
                    app.input_buffer.pop();
                    return false;
                }
                _ => return false,
            }
        }
        InputMode::Search => {
            match code {
                KeyCode::Esc => {
                    app.input_mode = InputMode::Normal;
                    app.input_buffer.clear();
                    app.status_message.clear();
                    return false;
                }
                KeyCode::Enter => {
                    // Search is applied in real-time via input_buffer
                    app.input_mode = InputMode::Normal;
                    return false;
                }
                KeyCode::Char(c) => {
                    app.input_buffer.push(c);
                    return false;
                }
                KeyCode::Backspace => {
                    app.input_buffer.pop();
                    return false;
                }
                _ => return false,
            }
        }
        InputMode::Filter => match code {
            KeyCode::Esc | KeyCode::Enter => {
                app.input_mode = InputMode::Normal;
                return false;
            }
            _ => return false,
        },
        InputMode::ConfirmDelete => {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    // Delete selected node
                    if app.selected_row < app.swarm.nodes.len() {
                        let removed_name = app.swarm.nodes[app.selected_row].name.clone();
                        app.swarm.nodes.remove(app.selected_row);
                        // Adjust active_node_idx if needed
                        if app.active_node_idx >= app.swarm.nodes.len()
                            && !app.swarm.nodes.is_empty()
                        {
                            app.active_node_idx = app.swarm.nodes.len() - 1;
                        }
                        if app.selected_row > 0 {
                            app.selected_row -= 1;
                        }
                        save_swarm_config(app);
                        app.status_message = format!("Deleted: {}", removed_name);
                    }
                    app.input_mode = InputMode::Normal;
                    return false;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    app.input_mode = InputMode::Normal;
                    app.status_message.clear();
                    return false;
                }
                _ => return false,
            }
        }
        InputMode::ConfirmAction => match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                execute_action(app).await;
                app.input_mode = InputMode::Normal;
                return false;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.pending_action = None;
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            _ => return false,
        },
        InputMode::InputNickname => match code {
            KeyCode::Esc => {
                app.input_mode = InputMode::Normal;
                app.input_buffer.clear();
                app.status_message.clear();
                return false;
            }
            KeyCode::Enter => {
                if !app.input_buffer.is_empty() {
                    let nickname = app.input_buffer.clone();
                    if let Some(client) = &app.api_client {
                        match client.set_nickname(&nickname).await {
                            Ok(_) => {
                                app.status_message = format!("Nickname set: {}", nickname);
                            }
                            Err(e) => {
                                app.status_message = format!("Failed: {}", e);
                            }
                        }
                    }
                }
                app.input_mode = InputMode::Normal;
                app.input_buffer.clear();
                return false;
            }
            KeyCode::Char(c) => {
                app.input_buffer.push(c);
                return false;
            }
            KeyCode::Backspace => {
                app.input_buffer.pop();
                return false;
            }
            _ => return false,
        },
        InputMode::InputPayoutAddress => match code {
            KeyCode::Esc => {
                app.input_mode = InputMode::Normal;
                app.input_buffer.clear();
                app.status_message.clear();
                return false;
            }
            KeyCode::Enter => {
                if !app.input_buffer.is_empty() {
                    let addr = app.input_buffer.clone();
                    if let Some(client) = &app.api_client {
                        match client.set_payout_address(&addr).await {
                            Ok(_) => {
                                app.status_message = format!(
                                    "Payout address set: {}...",
                                    &addr[..addr.len().min(16)]
                                );
                            }
                            Err(e) => {
                                app.status_message = format!("Failed: {}", e);
                            }
                        }
                    }
                }
                app.input_mode = InputMode::Normal;
                app.input_buffer.clear();
                return false;
            }
            KeyCode::Char(c) => {
                app.input_buffer.push(c);
                return false;
            }
            KeyCode::Backspace => {
                app.input_buffer.pop();
                return false;
            }
            _ => return false,
        },
        InputMode::WizardPicker => match code {
            KeyCode::Esc => {
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('1') => {
                app.active_wizard = Some(wizard::initial_setup::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('2') => {
                app.active_wizard = Some(wizard::change_setup::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('3') => {
                app.active_wizard = Some(wizard::ghost_mode::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('4') => {
                app.active_wizard = Some(wizard::reaper::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('5') => {
                app.active_wizard = Some(wizard::pool_setup::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('6') => {
                app.active_wizard = Some(wizard::haze::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('7') => {
                app.active_wizard = Some(wizard::shroud::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('8') => {
                app.active_wizard = Some(wizard::mempool_policy::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            KeyCode::Char('9') => {
                app.active_wizard = Some(wizard::build_run::create());
                app.input_mode = InputMode::Normal;
                app.status_message.clear();
                return false;
            }
            _ => return false,
        },
    }

    // Normal mode key handling
    match code {
        // Quit
        KeyCode::Char('q') => return true,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => return true,

        // Help
        KeyCode::Char('?') => {
            app.input_mode = InputMode::Help;
        }

        // Refresh
        KeyCode::Char('r') => {
            app.status_message = "Refreshing...".to_string();
            refresh_data(app).await;
            app.status_message.clear();
        }

        // Page-specific actions (must come before general number keys)
        KeyCode::Char('a') if matches!(app.current_tab, Tab::Swarm) => {
            app.input_mode = InputMode::NodeUrl;
            app.input_buffer.clear();
            app.status_message = "Enter node URL (e.g., http://192.168.1.100:8080):".to_string();
        }
        KeyCode::Char('e') if matches!(app.current_tab, Tab::Swarm) => {
            if app.selected_row < app.swarm.nodes.len() {
                app.input_mode = InputMode::NodeName;
                app.input_buffer = app.swarm.nodes[app.selected_row].name.clone();
                app.status_message = "Edit node name:".to_string();
            }
        }
        KeyCode::Char('d') if matches!(app.current_tab, Tab::Swarm) => {
            if app.selected_row < app.swarm.nodes.len() {
                let name = &app.swarm.nodes[app.selected_row].name;
                app.input_mode = InputMode::ConfirmDelete;
                app.status_message = format!("Delete '{}'? (y/n)", name);
            }
        }

        // Watchdog actions
        KeyCode::Char('R') if matches!(app.current_tab, Tab::Watchdog) => {
            if let Some(wd) = &app.node_data.watchdog {
                let services: Vec<_> = if !wd.services.is_empty() {
                    wd.services.iter().map(|s| s.name.clone()).collect()
                } else {
                    wd.components.iter().map(|c| c.name.clone()).collect()
                };
                if let Some(name) = services.get(app.selected_row) {
                    app.pending_action = Some(app::PendingAction::RestartService(name.clone()));
                    app.input_mode = InputMode::ConfirmAction;
                    app.status_message = format!("Restart '{}'?", name);
                }
            }
        }
        KeyCode::Char('S') if matches!(app.current_tab, Tab::Watchdog) => {
            if let Some(wd) = &app.node_data.watchdog {
                let services: Vec<_> = if !wd.services.is_empty() {
                    wd.services.iter().map(|s| s.name.clone()).collect()
                } else {
                    wd.components.iter().map(|c| c.name.clone()).collect()
                };
                if let Some(name) = services.get(app.selected_row) {
                    app.pending_action = Some(app::PendingAction::StopService(name.clone()));
                    app.input_mode = InputMode::ConfirmAction;
                    app.status_message = format!("Stop '{}'?", name);
                }
            }
        }

        // Settings actions
        KeyCode::Char('n') if matches!(app.current_tab, Tab::Settings) => {
            app.input_mode = InputMode::InputNickname;
            app.input_buffer.clear();
            app.status_message = "Enter nickname:".to_string();
        }
        KeyCode::Char('p') if matches!(app.current_tab, Tab::Settings) => {
            app.input_mode = InputMode::InputPayoutAddress;
            app.input_buffer.clear();
            app.status_message = "Enter payout address:".to_string();
        }
        KeyCode::Char('w') if matches!(app.current_tab, Tab::Settings) => {
            app.input_mode = InputMode::WizardPicker;
            app.status_message = "Select wizard: 1=Setup 2=Change 3=Ghost Mode 4=Reaper 5=Pool 6=Haze 7=Shroud 8=Mempool 9=Build".to_string();
        }

        // Backup actions
        KeyCode::Char('b') if matches!(app.current_tab, Tab::Backup) => {
            app.pending_action = Some(app::PendingAction::TriggerBackup);
            app.input_mode = InputMode::ConfirmAction;
            app.status_message = "Create backup?".to_string();
        }
        KeyCode::Char('d') if matches!(app.current_tab, Tab::Backup) => {
            if let Some(backups) = &app.node_data.backup_history {
                if let Some(backup) = backups.get(app.selected_row) {
                    let id = backup.backup_id.clone();
                    app.pending_action = Some(app::PendingAction::DeleteBackup(id.clone()));
                    app.input_mode = InputMode::ConfirmAction;
                    app.status_message = format!("Delete backup '{}'?", id);
                }
            }
        }

        KeyCode::Char('/') if matches!(app.current_tab, Tab::Logs) => {
            app.input_mode = InputMode::Search;
            app.input_buffer.clear();
            app.status_message = "Search logs:".to_string();
        }

        // Log level filter (in Logs tab) - must come before general number keys
        KeyCode::Char('1') if matches!(app.current_tab, Tab::Logs) => {
            app.node_data.log_filter_level = api::types::LogLevel::Error;
            app.status_message = "Filter: ERROR only".to_string();
        }
        KeyCode::Char('2') if matches!(app.current_tab, Tab::Logs) => {
            app.node_data.log_filter_level = api::types::LogLevel::Warn;
            app.status_message = "Filter: WARN and above".to_string();
        }
        KeyCode::Char('3') if matches!(app.current_tab, Tab::Logs) => {
            app.node_data.log_filter_level = api::types::LogLevel::Info;
            app.status_message = "Filter: INFO and above".to_string();
        }
        KeyCode::Char('4') if matches!(app.current_tab, Tab::Logs) => {
            app.node_data.log_filter_level = api::types::LogLevel::Debug;
            app.status_message = "Filter: DEBUG and above".to_string();
        }
        KeyCode::Char('5') if matches!(app.current_tab, Tab::Logs) => {
            app.node_data.log_filter_level = api::types::LogLevel::Trace;
            app.status_message = "Filter: ALL logs".to_string();
        }

        // Tab navigation (general number keys)
        KeyCode::Char('1') => {
            app.current_tab = Tab::Overview;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::Char('2') => {
            app.current_tab = Tab::Bitcoin;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::Char('3') => {
            app.current_tab = Tab::L2Service;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::Char('4') => {
            app.current_tab = Tab::Mining;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::Char('5') => {
            app.current_tab = Tab::Swarm;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::Char('6') => {
            app.current_tab = Tab::Logs;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::Char('7') => {
            app.current_tab = Tab::Watchdog;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::Char('8') => {
            app.current_tab = Tab::Backup;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::Char('9') => {
            app.current_tab = Tab::Settings;
            app.scroll_offset = 0;
            app.selected_row = 0;
        }

        KeyCode::Tab => {
            app.current_tab = app.current_tab.next();
            app.scroll_offset = 0;
            app.selected_row = 0;
        }
        KeyCode::BackTab => {
            app.current_tab = app.current_tab.prev();
            app.scroll_offset = 0;
            app.selected_row = 0;
        }

        // Scrolling / selection
        KeyCode::Char('j') | KeyCode::Down => {
            app.selected_row = app.selected_row.saturating_add(1);
            app.clamp_scroll();
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.selected_row = app.selected_row.saturating_sub(1);
        }
        KeyCode::PageDown => {
            app.scroll_offset = app.scroll_offset.saturating_add(10);
            app.clamp_scroll();
        }
        KeyCode::PageUp => {
            app.scroll_offset = app.scroll_offset.saturating_sub(10);
        }
        KeyCode::Home => {
            app.scroll_offset = 0;
            app.selected_row = 0;
        }

        KeyCode::Enter => {
            // Context-specific enter handling
            if matches!(app.current_tab, Tab::Swarm) {
                // Switch to selected node
                if app.selected_row < app.swarm.nodes.len() {
                    app.active_node_idx = app.selected_row;
                    let node_info = app.active_node().map(|n| {
                        (
                            n.url.clone(),
                            n.auth_token.clone(),
                            n.hmac_secret.clone(),
                            n.name.clone(),
                        )
                    });
                    if let Some((url, auth_token, hmac_secret, name)) = node_info {
                        app.api_client = Some(create_client(
                            &url,
                            auth_token.as_deref(),
                            hmac_secret.as_deref(),
                        ));
                        app.status_message = format!("Switched to {}", name);
                        refresh_data(app).await;
                    }
                }
            }
        }

        _ => {}
    }

    false
}

async fn refresh_data(app: &mut App) {
    let Some(client) = &app.api_client else {
        return;
    };

    // Always fetch node status (used by header + multiple tabs)
    // and update connection status based on result
    let active_url = app.active_node().map(|n| n.url.clone());
    match client.get_node_status().await {
        Ok(status) => {
            app.node_data.node_status = Some(status);
            if let Some(url) = &active_url {
                app.swarm
                    .connection_status
                    .insert(url.clone(), app::ConnectionStatus::Connected);
            }
        }
        Err(_) => {
            if let Some(url) = &active_url {
                app.swarm.connection_status.insert(
                    url.clone(),
                    app::ConnectionStatus::Error("Connection failed".to_string()),
                );
            }
        }
    }

    // Fetch additional data based on current tab
    match app.current_tab {
        Tab::Overview => {
            if let Ok(resources) = client.get_resources().await {
                app.node_data.resources = Some(resources);
            }
            if let Ok(rewards) = client.get_rewards().await {
                app.node_data.rewards = Some(rewards);
            }
            if let Ok(mining) = client.get_mining_status().await {
                app.node_data.mining_status = Some(mining);
            }
            if let Ok(gp) = client.get_ghostpay_status().await {
                app.node_data.ghostpay_status = Some(gp);
            }
        }
        Tab::Bitcoin => {
            if let Ok(peers) = client.get_peers().await {
                app.node_data.peers = Some(peers);
            }
        }
        Tab::L2Service => {
            if let Ok(gp) = client.get_ghostpay_status().await {
                app.node_data.ghostpay_status = Some(gp);
            }
            if let Ok(sessions) = client.get_wraith_sessions().await {
                app.node_data.wraith_sessions = Some(sessions);
            }
            if let Ok(locks) = client.get_locks().await {
                app.node_data.locks_summary = Some(locks);
            }
        }
        Tab::Mining => {
            if let Ok(mining) = client.get_mining_status().await {
                app.node_data.mining_status = Some(mining);
            }
            if let Ok(miners) = client.get_miners().await {
                app.node_data.miners = Some(miners);
            }
        }
        Tab::Swarm => {
            // Refresh status for all nodes (not just active)
            let nodes: Vec<_> = app
                .swarm
                .nodes
                .iter()
                .map(|n| (n.url.clone(), n.auth_token.clone(), n.hmac_secret.clone()))
                .collect();
            for (url, auth_token, hmac_secret) in nodes {
                // Skip active node — already checked above
                if active_url.as_deref() == Some(&url) {
                    continue;
                }
                let node_client =
                    create_client(&url, auth_token.as_deref(), hmac_secret.as_deref());
                match node_client.get_node_status().await {
                    Ok(status) => {
                        app.swarm.node_statuses.insert(url.clone(), status);
                        app.swarm
                            .connection_status
                            .insert(url, app::ConnectionStatus::Connected);
                    }
                    Err(_) => {
                        app.swarm.connection_status.insert(
                            url,
                            app::ConnectionStatus::Error("Connection failed".to_string()),
                        );
                    }
                }
            }
        }
        Tab::Logs => {
            if let Ok(logs) = client.get_logs(app.node_data.log_filter_level, 100).await {
                app.node_data.logs = Some(logs);
            }
        }
        Tab::Watchdog => {
            if let Ok(wd) = client.get_watchdog_status().await {
                app.node_data.watchdog = Some(wd);
            }
        }
        Tab::Backup => {
            if let Ok(history) = client.get_backup_history().await {
                app.node_data.backup_history = Some(history);
            }
        }
        Tab::Settings => {}
    }

    app.node_data.mark_refreshed(app.current_tab.data_type());
}

/// Create an API client with optional authentication and HMAC secret
fn create_client(
    url: &str,
    auth_token: Option<&str>,
    hmac_secret: Option<&str>,
) -> api::client::NodeApiClient {
    let mut client = match auth_token {
        Some(token) => api::client::NodeApiClient::with_auth(url, token),
        None => api::client::NodeApiClient::new(url),
    };
    client.set_hmac_secret(hmac_secret.map(String::from));
    client
}

/// Execute a pending action via the API
async fn execute_action(app: &mut App) {
    let Some(action) = app.pending_action.take() else {
        return;
    };
    let Some(client) = &app.api_client else {
        app.status_message = "No active connection".to_string();
        return;
    };

    match action {
        app::PendingAction::RestartService(name) => match client.restart_service(&name).await {
            Ok(_) => app.status_message = format!("Restarting {}", name),
            Err(e) => app.status_message = format!("Failed: {}", e),
        },
        app::PendingAction::StopService(name) => match client.stop_service(&name).await {
            Ok(_) => app.status_message = format!("Stopping {}", name),
            Err(e) => app.status_message = format!("Failed: {}", e),
        },
        app::PendingAction::StartService(name) => match client.start_service(&name).await {
            Ok(_) => app.status_message = format!("Starting {}", name),
            Err(e) => app.status_message = format!("Failed: {}", e),
        },
        app::PendingAction::ToggleCapability { name, new_value } => {
            app.status_message = format!(
                "Toggle {} → {} (not yet implemented)",
                name,
                if new_value { "on" } else { "off" }
            );
        }
        app::PendingAction::TriggerBackup => match client.trigger_backup().await {
            Ok(_) => app.status_message = "Backup triggered".to_string(),
            Err(e) => app.status_message = format!("Failed: {}", e),
        },
        app::PendingAction::DeleteBackup(id) => match client.delete_backup(&id).await {
            Ok(_) => app.status_message = format!("Deleted backup: {}", id),
            Err(e) => app.status_message = format!("Failed: {}", e),
        },
    }
}

/// Extract hostname from URL for default node name
fn extract_hostname(url: &str) -> String {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or("node")
        .to_string()
}

/// Save swarm config to disk
fn save_swarm_config(app: &App) {
    let config = config::SwarmConfig {
        nodes: app.swarm.nodes.clone(),
        settings: app.swarm.settings.clone(),
    };
    if let Err(e) = config.save() {
        tracing::error!("Failed to save config: {}", e);
    }
}

/// Render the wizard picker overlay (shown when user presses 'w' on Settings page)
fn render_wizard_picker(f: &mut Frame, area: Rect) {
    let popup_width = 50u16;
    let popup_height = 15u16;
    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(
        x,
        y,
        popup_width.min(area.width),
        popup_height.min(area.height),
    );

    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Launch Wizard ",
            Style::default()
                .fg(Color::Rgb(234, 88, 12))
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(31, 41, 55)));

    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let entries = [
        ("1", "Initial Setup"),
        ("2", "Change Setup"),
        ("3", "Ghost Mode"),
        ("4", "Reaper"),
        ("5", "Pool Setup"),
        ("6", "Haze / Exorcism"),
        ("7", "Shroud"),
        ("8", "Mempool Policy"),
        ("9", "Build / Run"),
    ];

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        "  Select a wizard:",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    for (key, label) in &entries {
        lines.push(Line::from(vec![
            Span::styled(
                format!("    [{}]", key),
                Style::default().fg(Color::Rgb(234, 88, 12)),
            ),
            Span::styled(format!("  {}", label), Style::default().fg(Color::Gray)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Esc to cancel",
        Style::default().fg(Color::Rgb(156, 163, 175)),
    )));

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

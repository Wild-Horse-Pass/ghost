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
//| FILE: watchdog.rs                                                                                                    |
//|======================================================================================================================|

//! Watchdog page - service health and capabilities

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::app::App;
use crate::theme;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Service health
            Constraint::Min(8),     // Capabilities & events
        ])
        .split(area);

    // Row 1: Service health cards
    let health_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    render_service_health(f, health_chunks[0], app);
    render_capabilities(f, health_chunks[1], app);

    // Row 2: Events
    render_events(f, chunks[1], app);
}

fn render_service_health(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Service Health ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(watchdog) = &app.node_data.watchdog {
        // Use dynamic services/components arrays from backend
        let display_services = if !watchdog.services.is_empty() {
            watchdog
                .services
                .iter()
                .map(|s| (s.name.clone(), s.status.clone()))
                .collect::<Vec<_>>()
        } else if !watchdog.components.is_empty() {
            watchdog
                .components
                .iter()
                .map(|c| (c.name.clone(), c.status.clone()))
                .collect::<Vec<_>>()
        } else {
            // Fallback: use service_status() lookup for well-known services
            vec![
                (
                    "ghost_pool".to_string(),
                    watchdog.service_status("ghost_pool").to_string(),
                ),
                (
                    "ghost_core".to_string(),
                    watchdog.service_status("ghost_core").to_string(),
                ),
                (
                    "ghost_pay".to_string(),
                    watchdog.service_status("ghost_pay").to_string(),
                ),
            ]
        };

        for (name, status) in &display_services {
            let (status_text, color) = match status.as_str() {
                "healthy" | "running" | "active" | "ok" => ("●", Color::Green),
                "degraded" | "warning" => ("◐", Color::Yellow),
                "unhealthy" | "failed" | "stopped" | "dead" | "error" => ("○", Color::Red),
                "not_enabled" | "disabled" => ("○", Color::DarkGray),
                _ => ("?", Color::Gray),
            };

            // Pretty-print service name (preserve known acronyms)
            let display_name = name
                .replace('_', " ")
                .split(' ')
                .map(|w| {
                    // Keep known acronyms uppercase
                    match w.to_lowercase().as_str() {
                        "gsp" => "GSP".to_string(),
                        _ => {
                            let mut c = w.chars();
                            match c.next() {
                                None => String::new(),
                                Some(f) => f.to_uppercase().to_string() + c.as_str(),
                            }
                        }
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");

            // Display-friendly status text
            let display_status = status.replace('_', " ");

            lines.push(Line::from(vec![
                Span::styled(format!("{} ", status_text), Style::default().fg(color)),
                Span::styled(
                    format!("{:<15}", display_name),
                    Style::default().fg(if color == Color::DarkGray {
                        Color::DarkGray
                    } else {
                        Color::White
                    }),
                ),
                Span::styled(display_status, Style::default().fg(color)),
            ]));
        }

        lines.push(Line::from(Span::raw("")));

        let health_label = watchdog
            .overall_health
            .as_deref()
            .unwrap_or(if watchdog.healthy {
                "healthy"
            } else {
                "unhealthy"
            });

        lines.push(Line::from(vec![
            Span::styled("Overall: ", Style::default().fg(Color::Gray)),
            Span::styled(
                health_label,
                Style::default().fg(if watchdog.healthy {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
        ]));

        if watchdog.last_check > 0 {
            lines.push(Line::from(vec![
                Span::styled("Last check: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format_timestamp(watchdog.last_check),
                    Style::default().fg(Color::White),
                ),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Waiting for watchdog...",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_capabilities(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Node Capabilities ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(status) = &app.node_data.node_status {
        let caps = status.get_capabilities();
        let capabilities = [
            ("Archive Mode", caps.archive_mode, "+5 shares"),
            ("Ghost Pay", caps.ghost_pay, "+4 shares"),
            ("Public Mining", caps.public_mining, "+3 shares"),
            ("Reaper", caps.reaper, "+2 shares"),
            ("Elder Status", caps.elder_status, "+1 share"),
        ];

        for (name, enabled, bonus) in capabilities {
            let (indicator, color) = if enabled {
                ("✓", Color::Green)
            } else {
                ("✗", Color::Gray)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("{} ", indicator), Style::default().fg(color)),
                Span::styled(
                    format!("{:<15}", name),
                    Style::default().fg(if enabled { Color::White } else { Color::Gray }),
                ),
                Span::styled(
                    if enabled { bonus } else { "" },
                    Style::default().fg(Color::Yellow),
                ),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Waiting for node status...",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_events(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Recent Events ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    if let Some(watchdog) = &app.node_data.watchdog {
        if watchdog.recent_events.is_empty() {
            let inner = block.inner(area);
            f.render_widget(block, area);

            let paragraph = Paragraph::new(Span::styled(
                "All systems nominal — no recent events.",
                Style::default().fg(theme::OK),
            ));
            f.render_widget(paragraph, inner);
            return;
        }

        let header = Row::new(vec![
            Cell::from("Time").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Service").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Event").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);

        let visible_rows = area.height.saturating_sub(4) as usize; // borders + header
        let rows: Vec<Row> = watchdog
            .recent_events
            .iter()
            .skip(app.scroll_offset)
            .take(visible_rows)
            .map(|event| {
                let color = match event.event_type.as_str() {
                    "error" | "failure" => Color::Red,
                    "warning" => Color::Yellow,
                    "recovery" => Color::Green,
                    _ => Color::White,
                };

                Row::new(vec![
                    Cell::from(format_timestamp(event.timestamp)),
                    Cell::from(event.service.clone()),
                    Cell::from(Span::styled(
                        event.message.clone(),
                        Style::default().fg(color),
                    )),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(60),
            ],
        )
        .header(header)
        .block(block);

        f.render_widget(table, area);
    } else {
        let inner = block.inner(area);
        f.render_widget(block, area);

        let paragraph = Paragraph::new(Span::styled(
            "Waiting for watchdog...",
            Style::default().fg(theme::TEXT_DIM),
        ));
        f.render_widget(paragraph, inner);
    }
}

fn format_timestamp(ts: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let diff = now - ts;

    if diff < 60 {
        format!("{}s ago", diff)
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

//! L2 Service page - Ghost Pay service status (not wallet)

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::app::App;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Status cards
            Constraint::Min(8),     // Wraith sessions
        ])
        .split(area);

    // Row 1: Status cards
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(chunks[0]);

    render_service_status(f, status_chunks[0], app);
    render_epoch_progress(f, status_chunks[1], app);
    render_locks_summary(f, status_chunks[2], app);

    // Row 2: Wraith sessions
    render_wraith_sessions(f, chunks[1], app);
}

fn render_service_status(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Ghost Pay Service ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(gp) = &app.node_data.ghostpay_status {
        let (status, color) = if gp.enabled {
            ("ACTIVE", Color::Green)
        } else {
            ("DISABLED", Color::Gray)
        };

        lines.push(Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::Gray)),
            Span::styled(
                status,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Block: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_number(gp.block_height),
                Style::default().fg(Color::Yellow),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Peers: ", Style::default().fg(Color::Gray)),
            Span::styled(gp.peer_count.to_string(), Style::default().fg(Color::Cyan)),
        ]));

        let wraith_status = gp.wraith_enabled.unwrap_or(false);
        let (wraith_text, wraith_color) = if wraith_status {
            ("Enabled", Color::Green)
        } else {
            ("Disabled", Color::Gray)
        };

        lines.push(Line::from(vec![
            Span::styled("Wraith: ", Style::default().fg(Color::Gray)),
            Span::styled(wraith_text, Style::default().fg(wraith_color)),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "No data available",
            Style::default().fg(Color::Gray),
        )));
    }

    // Note about service view
    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(Span::styled(
        "Service view only",
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::ITALIC),
    )));

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_epoch_progress(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Epoch Progress ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(gp) = &app.node_data.ghostpay_status {
        if let Some(epoch) = gp.epoch {
            lines.push(Line::from(vec![
                Span::styled("Epoch: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    epoch.to_string(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }

        if let Some(vblock) = gp.virtual_block {
            let vblock_in_epoch = vblock % 2160;
            let _progress = (vblock_in_epoch as f64 / 2160.0 * 100.0) as u16;

            lines.push(Line::from(vec![
                Span::styled("VBlock: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{}/2160", vblock_in_epoch),
                    Style::default().fg(Color::White),
                ),
            ]));

            lines.push(Line::from(Span::raw("")));

            // Remaining time estimate
            let remaining_vblocks = 2160 - vblock_in_epoch;
            let remaining_secs = remaining_vblocks * 10; // 10s per vblock

            lines.push(Line::from(vec![
                Span::styled("Next reconciliation: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format_duration(remaining_secs),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No data available",
            Style::default().fg(Color::Gray),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_locks_summary(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Locks Managed ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(locks) = &app.node_data.locks_summary {
        lines.push(Line::from(vec![
            Span::styled("Active Locks: ", Style::default().fg(Color::Gray)),
            Span::styled(
                locks.active_locks.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Total Value: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_sats(locks.total_locked_sats),
                Style::default().fg(Color::Yellow),
            ),
        ]));

        // Note about aggregate view
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::styled(
            "Aggregate count only",
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::ITALIC),
        )));
        lines.push(Line::from(Span::styled(
            "(no individual balances)",
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::ITALIC),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "No data available",
            Style::default().fg(Color::Gray),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_wraith_sessions(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Wraith Mixing Sessions (Coordinator View) ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    if let Some(sessions) = &app.node_data.wraith_sessions {
        if sessions.is_empty() {
            let inner = block.inner(area);
            f.render_widget(block, area);

            let paragraph = Paragraph::new(Span::styled(
                "No active sessions",
                Style::default().fg(Color::Gray),
            ));
            f.render_widget(paragraph, inner);
            return;
        }

        let header = Row::new(vec![
            Cell::from("Session").style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Denomination").style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Phase").style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Participants").style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);

        let rows: Vec<Row> = sessions
            .iter()
            .take(10)
            .map(|session| {
                let phase_color = match session.phase.as_str() {
                    "registration" => Color::Yellow,
                    "signing" | "split" | "shuffle" | "merge" => Color::Cyan,
                    "complete" => Color::Green,
                    _ => Color::White,
                };

                Row::new(vec![
                    Cell::from(truncate_id(&session.round_id)),
                    Cell::from(session.denomination.clone()),
                    Cell::from(Span::styled(
                        session.phase.clone(),
                        Style::default().fg(phase_color),
                    )),
                    Cell::from(session.participant_count.to_string()),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(30),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(20),
            ],
        )
        .header(header)
        .block(block);

        f.render_widget(table, area);
    } else {
        let inner = block.inner(area);
        f.render_widget(block, area);

        let paragraph = Paragraph::new(Span::styled(
            "No session data available",
            Style::default().fg(Color::Gray),
        ));
        f.render_widget(paragraph, inner);
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

fn format_sats(sats: u64) -> String {
    let btc = sats as f64 / 100_000_000.0;
    if btc >= 0.001 {
        format!("{:.4} BTC", btc)
    } else {
        format!("{} sats", format_number(sats))
    }
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;

    if hours > 0 {
        format!("~{}h {}m", hours, mins)
    } else {
        format!("~{}m", mins)
    }
}

fn truncate_id(id: &str) -> String {
    if id.len() > 12 {
        format!("{}...", &id[..12])
    } else {
        id.to_string()
    }
}

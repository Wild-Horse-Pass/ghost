//! Backup page - backup history and management

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
            Constraint::Length(8), // Backup status
            Constraint::Min(10),   // Backup history
        ])
        .split(area);

    render_backup_status(f, chunks[0], app);
    render_backup_history(f, chunks[1], app);
}

fn render_backup_status(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Backup Status ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(backups) = &app.node_data.backup_history {
        if let Some(latest) = backups.first() {
            let (status_text, status_color) = match latest.status.as_str() {
                "completed" => ("COMPLETED", Color::Green),
                "in_progress" => ("IN PROGRESS", Color::Yellow),
                "failed" => ("FAILED", Color::Red),
                _ => ("UNKNOWN", Color::Gray),
            };

            lines.push(Line::from(vec![
                Span::styled("Last backup: ", Style::default().fg(theme::TEXT_DIM)),
                Span::styled(
                    status_text,
                    Style::default()
                        .fg(status_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Time: ", Style::default().fg(theme::TEXT_DIM)),
                Span::styled(
                    format_datetime(latest.timestamp),
                    Style::default().fg(theme::TEXT),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Type: ", Style::default().fg(theme::TEXT_DIM)),
                Span::styled(&latest.backup_type, Style::default().fg(theme::PRIMARY_DIM)),
            ]));

            if let Some(size) = latest.size_bytes {
                lines.push(Line::from(vec![
                    Span::styled("Size: ", Style::default().fg(theme::TEXT_DIM)),
                    Span::styled(format_bytes(size), Style::default().fg(theme::TEXT)),
                ]));
            }
        } else {
            lines.push(Line::from(Span::styled(
                "No backups found.",
                Style::default().fg(theme::TEXT_DIM),
            )));
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(Span::styled(
                "Backups preserve node config, keys, and DB.",
                Style::default().fg(theme::PRIMARY_DIM),
            )));
            lines.push(Line::from(Span::styled(
                "Press [b] to create one.",
                Style::default().fg(theme::PRIMARY_DIM),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Waiting for backup data...",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(Span::styled(
        "[b] Trigger backup  [r] Refresh",
        Style::default().fg(theme::TEXT_DIM),
    )));

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_backup_history(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Backup History ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    if let Some(backups) = &app.node_data.backup_history {
        if backups.is_empty() {
            let inner = block.inner(area);
            f.render_widget(block, area);

            let lines = vec![
                Line::from(Span::styled(
                    "No backups found.",
                    Style::default().fg(theme::TEXT_DIM),
                )),
                Line::from(Span::raw("")),
                Line::from(Span::styled(
                    "Backups preserve node config, keys, and DB.",
                    Style::default().fg(theme::PRIMARY_DIM),
                )),
                Line::from(Span::styled(
                    "Press [b] to create one.",
                    Style::default().fg(theme::PRIMARY_DIM),
                )),
            ];
            let paragraph = Paragraph::new(lines);
            f.render_widget(paragraph, inner);
            return;
        }

        let header = Row::new(vec![
            Cell::from("ID").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Type").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Time").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Size").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Status").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);

        let visible_rows = area.height.saturating_sub(4) as usize; // borders + header
        let rows: Vec<Row> = backups
            .iter()
            .skip(app.scroll_offset)
            .take(visible_rows)
            .map(|backup| {
                let status_color = match backup.status.as_str() {
                    "completed" => Color::Green,
                    "in_progress" => Color::Yellow,
                    "failed" => Color::Red,
                    _ => Color::Gray,
                };

                Row::new(vec![
                    Cell::from(truncate_id(&backup.backup_id)),
                    Cell::from(backup.backup_type.clone()),
                    Cell::from(format_datetime(backup.timestamp)),
                    Cell::from(
                        backup
                            .size_bytes
                            .map(format_bytes)
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(Span::styled(
                        backup.status.clone(),
                        Style::default().fg(status_color),
                    )),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(20),
                Constraint::Percentage(15),
                Constraint::Percentage(30),
                Constraint::Percentage(15),
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
            "Waiting for backup data...",
            Style::default().fg(theme::TEXT_DIM),
        ));
        f.render_widget(paragraph, inner);
    }
}

fn truncate_id(id: &str) -> String {
    if id.chars().count() > 12 {
        format!("{}...", id.chars().take(12).collect::<String>())
    } else {
        id.to_string()
    }
}

fn format_datetime(ts: i64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "Invalid".to_string())
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

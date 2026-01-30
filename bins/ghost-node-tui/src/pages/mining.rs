//! Mining page - pool status, workers, blocks

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, Cell},
};

use crate::app::App;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),   // Mining status
            Constraint::Min(10),     // Workers table
        ])
        .split(area);

    // Row 1: Mining status cards
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(chunks[0]);

    render_pool_status(f, status_chunks[0], app);
    render_network_status(f, status_chunks[1], app);

    // Row 2: Workers table
    render_workers_table(f, chunks[1], app);
}

fn render_pool_status(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Your Pool ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(mining) = &app.node_data.mining_status {
        let (mode, mode_color) = if mining.public_mining {
            ("PUBLIC", Color::Green)
        } else {
            ("PRIVATE", Color::Yellow)
        };

        lines.push(Line::from(vec![
            Span::styled("Mode: ", Style::default().fg(Color::Gray)),
            Span::styled(mode, Style::default().fg(mode_color).add_modifier(Modifier::BOLD)),
        ]));

        if let Some(hashrate) = mining.total_hashrate {
            lines.push(Line::from(vec![
                Span::styled("Hashrate: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format_hashrate(hashrate),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
            ]));
        }

        lines.push(Line::from(vec![
            Span::styled("Workers: ", Style::default().fg(Color::Gray)),
            Span::styled(
                mining.miner_count.to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Shares: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_number(mining.shares_this_round),
                Style::default().fg(Color::White),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Difficulty: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:.2}", mining.difficulty),
                Style::default().fg(Color::White),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "No data available",
            Style::default().fg(Color::Gray),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_network_status(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Network ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(mining) = &app.node_data.mining_status {
        lines.push(Line::from(vec![
            Span::styled("Block: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_number(mining.block_height),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Round: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_number(mining.round_id),
                Style::default().fg(Color::White),
            ),
        ]));

        let (sync_text, sync_color) = if mining.is_synced {
            ("SYNCED", Color::Green)
        } else {
            ("SYNCING", Color::Yellow)
        };

        lines.push(Line::from(vec![
            Span::styled("Sync: ", Style::default().fg(Color::Gray)),
            Span::styled(sync_text, Style::default().fg(sync_color)),
        ]));

        if let Some(best_hash) = &mining.best_hash {
            lines.push(Line::from(vec![
                Span::styled("Best: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    truncate_hash(best_hash),
                    Style::default().fg(Color::White),
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

fn render_workers_table(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Workers ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    if let Some(miners) = &app.node_data.miners {
        let header = Row::new(vec![
            Cell::from("Miner ID").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Cell::from("Hashrate").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Cell::from("Shares").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Cell::from("Work").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Cell::from("Status").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]);

        let rows: Vec<Row> = miners
            .iter()
            .take(20)
            .map(|miner| {
                let (status_text, status_color) = if miner.active {
                    ("Online", Color::Green)
                } else {
                    ("Offline", Color::Red)
                };

                Row::new(vec![
                    Cell::from(truncate_id(&miner.miner_id)),
                    Cell::from(
                        miner
                            .avg_hashrate_ths
                            .map(|h| format_hashrate(h))
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(format_number(miner.shares_this_round)),
                    Cell::from(format!("{:.2}", miner.work)),
                    Cell::from(Span::styled(status_text, Style::default().fg(status_color))),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(30),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(15),
                Constraint::Percentage(15),
            ],
        )
        .header(header)
        .block(block);

        f.render_widget(table, area);
    } else {
        let inner = block.inner(area);
        f.render_widget(block, area);

        let paragraph = Paragraph::new(Span::styled(
            "No worker data available",
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

fn format_hashrate(ths: f64) -> String {
    if ths >= 1000.0 {
        format!("{:.2} PH/s", ths / 1000.0)
    } else if ths >= 1.0 {
        format!("{:.2} TH/s", ths)
    } else {
        format!("{:.2} GH/s", ths * 1000.0)
    }
}

fn truncate_id(id: &str) -> String {
    if id.len() > 16 {
        format!("{}...", &id[..16])
    } else {
        id.to_string()
    }
}

fn truncate_hash(hash: &str) -> String {
    if hash.len() > 20 {
        format!("{}...", &hash[..20])
    } else {
        hash.to_string()
    }
}

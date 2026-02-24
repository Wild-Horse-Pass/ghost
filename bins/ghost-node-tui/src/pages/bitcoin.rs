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
//| FILE: bitcoin.rs                                                                                                     |
//|======================================================================================================================|

//! Bitcoin L1 page - chain status, peers, mempool

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
            Constraint::Length(8), // Chain info
            Constraint::Min(10),   // Peers table
        ])
        .split(area);

    // Row 1: Chain info cards
    let info_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    render_chain_info(f, info_chunks[0], app);
    render_mempool_info(f, info_chunks[1], app);

    // Row 2: Peers table
    render_peers_table(f, chunks[1], app);
}

fn render_chain_info(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Chain ",
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
        let (sync_text, sync_color) = if status.is_synced {
            ("SYNCED", Color::Green)
        } else {
            ("SYNCING", Color::Yellow)
        };

        lines.push(Line::from(vec![
            Span::styled("Status: ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                sync_text,
                Style::default().fg(sync_color).add_modifier(Modifier::BOLD),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Block Height: ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format_number(status.block_height),
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Sync Height: ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format_number(status.sync_height),
                Style::default().fg(theme::TEXT),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Peers: ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                status.peer_count.to_string(),
                Style::default().fg(theme::PRIMARY_DIM),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "Waiting for Bitcoin Core...",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_mempool_info(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Mempool ",
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
        if let Some(profile) = &status.mempool_profile {
            lines.push(Line::from(vec![
                Span::styled("Profile: ", Style::default().fg(theme::TEXT_DIM)),
                Span::styled(profile.clone(), Style::default().fg(theme::TEXT)),
            ]));
        }

        lines.push(Line::from(vec![
            Span::styled("Round: ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                status.round_id.to_string(),
                Style::default().fg(theme::TEXT),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "Waiting for Bitcoin Core...",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_peers_table(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Connected Peers ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    if let Some(peers) = &app.node_data.peers {
        let header = Row::new(vec![
            Cell::from("Address").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Node ID").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Latency").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from("Last Seen").style(
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);

        let visible_rows = area.height.saturating_sub(4) as usize; // borders + header
        let rows: Vec<Row> = peers
            .iter()
            .skip(app.scroll_offset)
            .take(visible_rows)
            .map(|peer| {
                Row::new(vec![
                    Cell::from(peer.address.clone()),
                    Cell::from(
                        peer.node_id
                            .as_ref()
                            .map(|id| truncate_id(id))
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(
                        peer.latency_ms
                            .map(|l| format!("{:.0}ms", l))
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(format_timestamp(peer.last_seen)),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(35),
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

        let empty_lines = vec![
            Line::from(Span::styled(
                "No peers connected.",
                Style::default().fg(theme::TEXT_DIM),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Peer data appears once the node",
                Style::default().fg(theme::PRIMARY_DIM),
            )),
            Line::from(Span::styled(
                "joins the Bitcoin network.",
                Style::default().fg(theme::PRIMARY_DIM),
            )),
        ];

        let paragraph = Paragraph::new(empty_lines);
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

fn truncate_id(id: &str) -> String {
    if id.chars().count() > 16 {
        format!("{}...", id.chars().take(16).collect::<String>())
    } else {
        id.to_string()
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

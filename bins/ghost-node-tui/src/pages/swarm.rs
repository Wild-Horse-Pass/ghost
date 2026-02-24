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
//| FILE: swarm.rs                                                                                                       |
//|======================================================================================================================|

//! Swarm page - multi-node management

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::app::{App, ConnectionStatus, InputMode};
use crate::theme;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Instructions
            Constraint::Min(10),   // Node list
            Constraint::Length(5), // Selected node details
        ])
        .split(area);

    render_instructions(f, chunks[0], app);
    render_node_list(f, chunks[1], app);
    render_node_details(f, chunks[2], app);
}

fn render_instructions(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Swarm Management ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let text = match app.input_mode {
        InputMode::Normal => Line::from(Span::styled(
            "[a] Add node  [e] Edit  [d] Delete  [Enter] Connect  [j/k] Navigate",
            Style::default().fg(Color::Gray),
        )),
        InputMode::NodeUrl => Line::from(vec![
            Span::styled("URL: ", Style::default().fg(Color::Yellow)),
            Span::styled(&app.input_buffer, Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(theme::PRIMARY)),
            Span::styled(
                "  [Enter] Confirm  [Esc] Cancel",
                Style::default().fg(Color::Gray),
            ),
        ]),
        InputMode::NodeName => Line::from(vec![
            Span::styled("Name: ", Style::default().fg(Color::Yellow)),
            Span::styled(&app.input_buffer, Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(theme::PRIMARY)),
            Span::styled(
                "  [Enter] Confirm  [Esc] Cancel",
                Style::default().fg(Color::Gray),
            ),
        ]),
        InputMode::ConfirmDelete => Line::from(Span::styled(
            &app.status_message,
            Style::default().fg(Color::Red),
        )),
        _ => Line::from(Span::styled(
            "[Esc] Back to normal mode",
            Style::default().fg(Color::Gray),
        )),
    };

    let paragraph = Paragraph::new(text);
    f.render_widget(paragraph, inner);
}

fn render_node_list(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Configured Nodes ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    let header = Row::new(vec![
        Cell::from("").style(Style::default().fg(theme::PRIMARY)),
        Cell::from("Name").style(
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("URL").style(
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Status").style(
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Block").style(
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Peers").style(
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let rows: Vec<Row> = app
        .swarm
        .nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| {
            let is_active = idx == app.active_node_idx;
            let is_selected = idx == app.selected_row;

            let indicator = if is_active { "►" } else { " " };

            let status = app.swarm.connection_status.get(&node.url);
            let (status_text, status_color) = match status {
                Some(ConnectionStatus::Connected) => ("Online", Color::Green),
                Some(ConnectionStatus::Connecting) => ("Connecting", Color::Yellow),
                Some(ConnectionStatus::Error(_)) => ("Error", Color::Red),
                _ => ("Unknown", Color::Gray),
            };

            let block_height = app
                .swarm
                .node_statuses
                .get(&node.url)
                .map(|s| format_number(s.block_height))
                .unwrap_or_else(|| "-".to_string());

            let peer_count = app
                .swarm
                .node_statuses
                .get(&node.url)
                .map(|s| s.peer_count.to_string())
                .unwrap_or_else(|| "-".to_string());

            let style = if is_selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(indicator).style(Style::default().fg(Color::Yellow)),
                Cell::from(node.name.clone()).style(Style::default().fg(Color::White)),
                Cell::from(truncate_url(&node.url)),
                Cell::from(Span::styled(status_text, Style::default().fg(status_color))),
                Cell::from(block_height),
                Cell::from(peer_count),
            ])
            .style(style)
        })
        .collect();

    if rows.is_empty() {
        let inner = block.inner(area);
        f.render_widget(block, area);

        let paragraph = Paragraph::new(vec![
            Line::from(Span::styled(
                "No nodes configured",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::raw("")),
            Line::from(Span::styled(
                "Press 'a' to add your first node",
                Style::default().fg(Color::Yellow),
            )),
        ]);
        f.render_widget(paragraph, inner);
    } else {
        let table = Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Percentage(20),
                Constraint::Percentage(35),
                Constraint::Percentage(15),
                Constraint::Percentage(15),
                Constraint::Percentage(15),
            ],
        )
        .header(header)
        .block(block);

        f.render_widget(table, area);
    }
}

fn render_node_details(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Node Details ",
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::PRIMARY));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(node) = app.swarm.nodes.get(app.selected_row) {
        let mut lines = vec![];

        lines.push(Line::from(vec![
            Span::styled("Name: ", Style::default().fg(Color::Gray)),
            Span::styled(
                &node.name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("URL: ", Style::default().fg(Color::Gray)),
            Span::styled(&node.url, Style::default().fg(theme::PRIMARY_DIM)),
        ]));

        if let Some(group) = &node.group {
            lines.push(Line::from(vec![
                Span::styled("Group: ", Style::default().fg(Color::Gray)),
                Span::styled(group, Style::default().fg(Color::White)),
            ]));
        }

        if let Some(notes) = &node.notes {
            lines.push(Line::from(vec![
                Span::styled("Notes: ", Style::default().fg(Color::Gray)),
                Span::styled(notes, Style::default().fg(Color::Gray)),
            ]));
        }

        let paragraph = Paragraph::new(lines);
        f.render_widget(paragraph, inner);
    } else {
        let paragraph = Paragraph::new(Span::styled(
            "No node selected",
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

fn truncate_url(url: &str) -> String {
    if url.chars().count() > 30 {
        format!("{}...", url.chars().take(27).collect::<String>())
    } else {
        url.to_string()
    }
}

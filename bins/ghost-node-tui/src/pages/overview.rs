//! Overview page - all services at a glance

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

use crate::app::{App, ConnectionStatus};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9), // Status cards row
            Constraint::Length(9), // Mining + L2 row
            Constraint::Min(5),    // Rewards + Activity
        ])
        .split(area);

    // Row 1: Node status cards
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(chunks[0]);

    render_node_status_card(f, status_chunks[0], app);
    render_sync_status_card(f, status_chunks[1], app);
    render_resources_card(f, status_chunks[2], app);

    // Row 2: Mining + L2
    let service_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    render_mining_card(f, service_chunks[0], app);
    render_l2_card(f, service_chunks[1], app);

    // Row 3: Rewards
    render_rewards_card(f, chunks[2], app);
}

fn render_node_status_card(f: &mut Frame, area: Rect, app: &App) {
    let (status_text, status_color) = match &app.active_connection_status() {
        ConnectionStatus::Connected => ("CONNECTED", Color::Green),
        ConnectionStatus::Connecting => ("CONNECTING", Color::Yellow),
        ConnectionStatus::Disconnected => ("DISCONNECTED", Color::Red),
        ConnectionStatus::Error(_) => ("ERROR", Color::Red),
    };

    let node_name = app
        .active_node()
        .map(|n| n.name.as_str())
        .unwrap_or("No Node");

    let block = Block::default()
        .title(Span::styled(
            " Node Status ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let status = app.node_data.node_status.as_ref();

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Node: ", Style::default().fg(Color::Gray)),
            Span::styled(
                node_name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::Gray)),
            Span::styled(
                status_text,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    if let Some(s) = status {
        lines.push(Line::from(vec![
            Span::styled("Version: ", Style::default().fg(Color::Gray)),
            Span::styled(&s.version, Style::default().fg(Color::White)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Uptime: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_uptime(s.uptime_seconds),
                Style::default().fg(Color::White),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Peers: ", Style::default().fg(Color::Gray)),
            Span::styled(s.peer_count.to_string(), Style::default().fg(Color::Cyan)),
        ]));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_sync_status_card(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Bitcoin Core ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let status = app.node_data.node_status.as_ref();

    let mut lines = vec![];

    if let Some(s) = status {
        let (sync_text, sync_color) = if s.is_synced {
            ("SYNCED", Color::Green)
        } else {
            ("SYNCING", Color::Yellow)
        };

        lines.push(Line::from(vec![
            Span::styled("Sync: ", Style::default().fg(Color::Gray)),
            Span::styled(
                sync_text,
                Style::default().fg(sync_color).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Block: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_number(s.block_height),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Round: ", Style::default().fg(Color::Gray)),
            Span::styled(s.round_id.to_string(), Style::default().fg(Color::White)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Miners: ", Style::default().fg(Color::Gray)),
            Span::styled(s.miner_count.to_string(), Style::default().fg(Color::Cyan)),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "No data",
            Style::default().fg(Color::Gray),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_resources_card(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Resources ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(res) = &app.node_data.resources {
        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(2),
                Constraint::Length(2),
            ])
            .split(inner);

        // CPU gauge
        render_resource_gauge(f, inner_chunks[0], "CPU", res.cpu_percent);
        // Memory gauge
        render_resource_gauge(f, inner_chunks[1], "MEM", res.memory_percent);
        // Disk gauge
        render_resource_gauge(f, inner_chunks[2], "DISK", res.disk_percent);
    } else {
        let paragraph = Paragraph::new(Span::styled("No data", Style::default().fg(Color::Gray)));
        f.render_widget(paragraph, inner);
    }
}

fn render_resource_gauge(f: &mut Frame, area: Rect, label: &str, percent: f64) {
    let color = if percent > 90.0 {
        Color::Red
    } else if percent > 70.0 {
        Color::Yellow
    } else {
        Color::Green
    };

    let gauge = Gauge::default()
        .block(Block::default())
        .gauge_style(Style::default().fg(color))
        .percent(percent.min(100.0) as u16)
        .label(format!("{}: {:.1}%", label, percent));

    f.render_widget(gauge, area);
}

fn render_mining_card(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Mining Pool ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
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
            Span::styled(
                mode,
                Style::default().fg(mode_color).add_modifier(Modifier::BOLD),
            ),
        ]));
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

        if let Some(hashrate) = mining.total_hashrate {
            lines.push(Line::from(vec![
                Span::styled("Hashrate: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format_hashrate(hashrate),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No data",
            Style::default().fg(Color::Gray),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_l2_card(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Ghost Pay (L2) ",
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

        if let Some(epoch) = gp.epoch {
            lines.push(Line::from(vec![
                Span::styled("Epoch: ", Style::default().fg(Color::Gray)),
                Span::styled(epoch.to_string(), Style::default().fg(Color::White)),
            ]));
        }

        if let Some(vblock) = gp.virtual_block {
            lines.push(Line::from(vec![
                Span::styled("VBlock: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{}/2160", vblock % 2160),
                    Style::default().fg(Color::White),
                ),
            ]));
        }

        lines.push(Line::from(vec![
            Span::styled("Peers: ", Style::default().fg(Color::Gray)),
            Span::styled(gp.peer_count.to_string(), Style::default().fg(Color::Cyan)),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "No data",
            Style::default().fg(Color::Gray),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_rewards_card(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Node Rewards ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(rewards) = &app.node_data.rewards {
        lines.push(Line::from(vec![
            Span::styled("Shares: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}/15", rewards.node_shares),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" (network: {})", rewards.total_network_shares),
                Style::default().fg(Color::Gray),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Pending: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_sats(rewards.pending_rewards_sats),
                Style::default().fg(Color::Yellow),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Total Earned: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_sats(rewards.total_earned_sats),
                Style::default().fg(Color::Green),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "No data",
            Style::default().fg(Color::Gray),
        )));
    }

    // Show capabilities if available
    if let Some(status) = &app.node_data.node_status {
        let caps = status.get_capabilities();
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(vec![
            Span::styled("Capabilities: ", Style::default().fg(Color::Gray)),
            capability_span("Archive", caps.archive_mode, 5),
            Span::raw(" "),
            capability_span("GhostPay", caps.ghost_pay, 4),
            Span::raw(" "),
            capability_span("Public", caps.public_mining, 3),
            Span::raw(" "),
            capability_span("Policy", caps.bitcoin_pure, 2),
            Span::raw(" "),
            capability_span("Elder", caps.elder_status, 1),
        ]));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn capability_span(name: &str, enabled: bool, shares: i32) -> Span<'static> {
    if enabled {
        Span::styled(
            format!("{}+{}", name, shares),
            Style::default().fg(Color::Green),
        )
    } else {
        Span::styled(name.to_string(), Style::default().fg(Color::Gray))
    }
}

// Helper functions

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
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

fn format_hashrate(ths: f64) -> String {
    if ths == 0.0 {
        "0 H/s".to_string()
    } else if ths >= 1000.0 {
        format!("{:.2} PH/s", ths / 1000.0)
    } else if ths >= 1.0 {
        format!("{:.2} TH/s", ths)
    } else {
        format!("{:.2} GH/s", ths * 1000.0)
    }
}

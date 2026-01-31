//! Settings page - node configuration

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12), // Node config
            Constraint::Length(10), // Display settings
            Constraint::Min(5),     // Help
        ])
        .split(area);

    render_node_config(f, chunks[0], app);
    render_display_settings(f, chunks[1], app);
    render_help(f, chunks[2]);
}

fn render_node_config(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Node Configuration ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![];

    if let Some(node) = app.active_node() {
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
            Span::styled(&node.url, Style::default().fg(Color::Cyan)),
        ]));

        let auth_status = if node.auth_token.is_some() {
            ("Configured", Color::Green)
        } else {
            ("None", Color::Gray)
        };

        lines.push(Line::from(vec![
            Span::styled("Auth: ", Style::default().fg(Color::Gray)),
            Span::styled(auth_status.0, Style::default().fg(auth_status.1)),
        ]));

        lines.push(Line::from(Span::raw("")));

        if let Some(status) = &app.node_data.node_status {
            lines.push(Line::from(vec![
                Span::styled("Version: ", Style::default().fg(Color::Gray)),
                Span::styled(&status.version, Style::default().fg(Color::White)),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Network: ", Style::default().fg(Color::Gray)),
                Span::styled(&status.network, Style::default().fg(Color::Yellow)),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No node configured",
            Style::default().fg(Color::Gray),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_display_settings(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Display Settings ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let refresh_interval = app.swarm.settings.refresh_interval_secs;
    let theme = &app.swarm.settings.theme;

    let lines = vec![
        Line::from(vec![
            Span::styled("Refresh interval: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}s", refresh_interval),
                Style::default().fg(Color::White),
            ),
            Span::styled(" [+/-]", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("Theme: ", Style::default().fg(Color::Gray)),
            Span::styled(theme, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Notifications: ", Style::default().fg(Color::Gray)),
            Span::styled(
                if app.swarm.settings.notifications_enabled {
                    "Enabled"
                } else {
                    "Disabled"
                },
                Style::default().fg(if app.swarm.settings.notifications_enabled {
                    Color::Green
                } else {
                    Color::Gray
                }),
            ),
            Span::styled(" [n]", Style::default().fg(Color::Gray)),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(
            "Config: ~/.config/ghost-node-tui/swarm.toml",
            Style::default().fg(Color::Gray),
        )),
    ];

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn render_help(f: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(Span::styled(
            " Keyboard Shortcuts ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = vec![
        Line::from(vec![
            Span::styled("1-9", Style::default().fg(Color::Yellow)),
            Span::styled(" Jump to page  ", Style::default().fg(Color::Gray)),
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::styled(" Next page  ", Style::default().fg(Color::Gray)),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::styled(" Quit", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("j/k", Style::default().fg(Color::Yellow)),
            Span::styled(" Navigate  ", Style::default().fg(Color::Gray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" Select  ", Style::default().fg(Color::Gray)),
            Span::styled("r", Style::default().fg(Color::Yellow)),
            Span::styled(" Refresh", Style::default().fg(Color::Gray)),
        ]),
    ];

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

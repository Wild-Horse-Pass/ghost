//! Common widgets for Ghost Node TUI

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
    Frame,
};

use crate::app::{App, ConnectionStatus, InputMode};

/// Render the header/status bar with connection status and tab navigation
pub fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let titles: Vec<Span> = [
        ("1", "Overview"),
        ("2", "Bitcoin"),
        ("3", "L2"),
        ("4", "Mining"),
        ("5", "Swarm"),
        ("6", "Logs"),
        ("7", "Watchdog"),
        ("8", "Backup"),
        ("9", "Settings"),
    ]
    .iter()
    .enumerate()
    .map(|(idx, (num, name))| {
        let is_active = idx == app.current_tab.index();
        if is_active {
            Span::styled(
                format!(" [{}]{} ", num, name),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                format!(" {}{} ", num, name),
                Style::default().fg(Color::Gray),
            )
        }
    })
    .collect();

    let (status_text, status_color) = match &app.active_connection_status() {
        ConnectionStatus::Connected => ("●", Color::Green),
        ConnectionStatus::Connecting => ("◐", Color::Yellow),
        ConnectionStatus::Disconnected => ("○", Color::Red),
        ConnectionStatus::Error(_) => ("○", Color::Red),
    };

    let node_name = app
        .active_node()
        .map(|n| n.name.as_str())
        .unwrap_or("No Node");

    let title = format!(" Ghost Node TUI {} {} ", status_text, node_name);

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(status_color)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .select(app.current_tab.index())
        .highlight_style(Style::default().fg(Color::Cyan));

    f.render_widget(tabs, area);
}

/// Render the footer status bar
pub fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let status = if !app.status_message.is_empty() {
        app.status_message.clone()
    } else {
        "Tab/Shift+Tab: Navigate | 1-9: Jump | q: Quit | r: Refresh | ?: Help".to_string()
    };

    // Show input buffer for input modes
    let display_text = match app.input_mode {
        InputMode::NodeUrl | InputMode::NodeName | InputMode::Search => {
            format!("{} {}_", app.status_message, app.input_buffer)
        }
        _ => status,
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let paragraph = Paragraph::new(Span::styled(display_text, Style::default().fg(Color::Gray)));
    f.render_widget(paragraph, inner);
}

/// Render help overlay
pub fn render_help_overlay(f: &mut Frame, area: Rect) {
    // Calculate centered popup area
    let popup_area = centered_rect(70, 80, area);

    // Clear the area first
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Help - Press any key to close ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let help_text = vec![
        Line::from(Span::styled(
            "═══════════════════════════════════════════════════════",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            "                    NAVIGATION",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  1-9       ", Style::default().fg(Color::Green)),
            Span::raw("Jump to page (Overview, Bitcoin, L2, Mining, etc.)"),
        ]),
        Line::from(vec![
            Span::styled("  Tab       ", Style::default().fg(Color::Green)),
            Span::raw("Next page"),
        ]),
        Line::from(vec![
            Span::styled("  Shift+Tab ", Style::default().fg(Color::Green)),
            Span::raw("Previous page"),
        ]),
        Line::from(vec![
            Span::styled("  j/k, ↓/↑  ", Style::default().fg(Color::Green)),
            Span::raw("Navigate lists / scroll"),
        ]),
        Line::from(vec![
            Span::styled("  Enter     ", Style::default().fg(Color::Green)),
            Span::raw("Select / activate"),
        ]),
        Line::from(vec![
            Span::styled("  Home      ", Style::default().fg(Color::Green)),
            Span::raw("Go to top"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "                    GENERAL",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  r         ", Style::default().fg(Color::Green)),
            Span::raw("Refresh data"),
        ]),
        Line::from(vec![
            Span::styled("  q         ", Style::default().fg(Color::Green)),
            Span::raw("Quit"),
        ]),
        Line::from(vec![
            Span::styled("  ?         ", Style::default().fg(Color::Green)),
            Span::raw("Show this help"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "                 SWARM PAGE (5)",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  a         ", Style::default().fg(Color::Green)),
            Span::raw("Add new node"),
        ]),
        Line::from(vec![
            Span::styled("  e         ", Style::default().fg(Color::Green)),
            Span::raw("Edit node name"),
        ]),
        Line::from(vec![
            Span::styled("  d         ", Style::default().fg(Color::Green)),
            Span::raw("Delete node"),
        ]),
        Line::from(vec![
            Span::styled("  Enter     ", Style::default().fg(Color::Green)),
            Span::raw("Connect to selected node"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "                  LOGS PAGE (6)",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  1-5       ", Style::default().fg(Color::Green)),
            Span::raw("Filter: Error, Warn, Info, Debug, All"),
        ]),
        Line::from(vec![
            Span::styled("  /         ", Style::default().fg(Color::Green)),
            Span::raw("Search logs"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "═══════════════════════════════════════════════════════",
            Style::default().fg(Color::Cyan),
        )),
    ];

    let paragraph = Paragraph::new(help_text)
        .block(block)
        .alignment(Alignment::Left);

    f.render_widget(paragraph, popup_area);
}

/// Helper function to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

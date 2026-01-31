//! Logs page - live log viewer with filtering

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::api::types::LogLevel;
use crate::app::App;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Filter bar
            Constraint::Min(10),   // Log entries
        ])
        .split(area);

    render_filter_bar(f, chunks[0], app);
    render_log_entries(f, chunks[1], app);
}

fn render_filter_bar(f: &mut Frame, area: Rect, app: &App) {
    let current_level = app.node_data.log_filter_level;

    let block = Block::default()
        .title(Span::styled(
            format!(" Log Filter: {} ", current_level.as_str().to_uppercase()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    use crate::api::types::LogLevel;

    // Build filter options with current selection highlighted
    let levels = [
        ("1", "Error", LogLevel::Error),
        ("2", "Warn", LogLevel::Warn),
        ("3", "Info", LogLevel::Info),
        ("4", "Debug", LogLevel::Debug),
        ("5", "All", LogLevel::Trace),
    ];

    let mut spans = vec![Span::styled(
        "[/] Search  ",
        Style::default().fg(Color::Gray),
    )];

    for (key, name, level) in levels {
        let style = if level == current_level {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        spans.push(Span::styled(format!("[{}] {} ", key, name), style));
    }

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, inner);
}

fn render_log_entries(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            " Log Entries ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    if let Some(logs) = &app.node_data.logs {
        let items: Vec<ListItem> = logs
            .iter()
            .skip(app.scroll_offset)
            .take(area.height.saturating_sub(2) as usize)
            .map(|entry| {
                let level_color = match entry.level.to_uppercase().as_str() {
                    "ERROR" => Color::Red,
                    "WARN" => Color::Yellow,
                    "INFO" => Color::Green,
                    "DEBUG" => Color::Cyan,
                    "TRACE" => Color::Gray,
                    _ => Color::White,
                };

                let timestamp = format_timestamp(&entry.timestamp);

                let line = Line::from(vec![
                    Span::styled(format!("{} ", timestamp), Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{:5} ", entry.level.to_uppercase()),
                        Style::default()
                            .fg(level_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("[{}] ", entry.component),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(&entry.message, Style::default().fg(Color::White)),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items).block(block);
        f.render_widget(list, area);
    } else {
        let inner = block.inner(area);
        f.render_widget(block, area);

        let paragraph = Paragraph::new(Span::styled(
            "No log data available",
            Style::default().fg(Color::Gray),
        ));
        f.render_widget(paragraph, inner);
    }
}

fn format_timestamp(ts: &str) -> String {
    // Assuming ISO format, extract time portion
    if let Some(time_part) = ts.split('T').nth(1) {
        if let Some(time) = time_part.split('.').next() {
            return time.to_string();
        }
    }
    ts.chars().take(8).collect()
}

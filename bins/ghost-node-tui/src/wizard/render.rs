//! Generic wizard rendering for the TUI

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use super::{FieldType, WizardState};

/// Theme colors matching the dashboard's palette
const ORANGE: Color = Color::Rgb(234, 88, 12);
const GRAY_400: Color = Color::Rgb(156, 163, 175);
const GRAY_800: Color = Color::Rgb(31, 41, 55);

/// Render a wizard overlay centered on the given area
pub fn render_wizard(f: &mut Frame, area: Rect, wizard: &WizardState) {
    // Calculate centered popup: 70% width, 80% height
    let popup_area = centered_rect(70, 80, area);

    // Clear background behind the popup
    f.render_widget(Clear, popup_area);

    // Build outer block title: "{title} [step/total]"
    let title_text = format!(
        " {} [{}/{}] ",
        wizard.title,
        wizard.current_step + 1,
        wizard.total_steps()
    );

    let outer_block = Block::default()
        .title(Span::styled(
            title_text,
            Style::default().fg(ORANGE).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GRAY_800));

    let inner_area = outer_block.inner(popup_area);
    f.render_widget(outer_block, popup_area);

    // Split inner area vertically:
    //   - Step indicator bar (3 lines)
    //   - Step title + description (3 lines)
    //   - Fields area (remaining)
    //   - Footer with keybindings (2 lines)
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Step indicator dots
            Constraint::Length(3), // Step title + description
            Constraint::Min(4),    // Fields area
            Constraint::Length(2), // Footer keybindings
        ])
        .split(inner_area);

    // --- Step indicator bar ---
    render_step_indicator(f, sections[0], wizard);

    // --- Step title + description ---
    render_step_header(f, sections[1], wizard);

    // --- Error / completion message or fields ---
    if wizard.complete {
        render_completion(f, sections[2], wizard);
    } else if wizard.error.is_some() {
        // Split fields area to show error above fields
        let error_split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2), // Error message
                Constraint::Min(2),    // Fields
            ])
            .split(sections[2]);
        render_error(f, error_split[0], wizard);
        render_fields(f, error_split[1], wizard);
    } else {
        render_fields(f, sections[2], wizard);
    }

    // --- Footer keybindings ---
    render_footer(f, sections[3], wizard);
}

/// Render step indicator dots with step titles
fn render_step_indicator(f: &mut Frame, area: Rect, wizard: &WizardState) {
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::raw("  "));

    for (i, step) in wizard.steps.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" - ", Style::default().fg(GRAY_400)));
        }

        let dot = if i == wizard.current_step {
            "\u{25cf}" // filled circle
        } else {
            "\u{25cb}" // empty circle
        };

        let style = if i == wizard.current_step {
            Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
        } else if i < wizard.current_step {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(GRAY_400)
        };

        spans.push(Span::styled(format!("{} {}", dot, step.title), style));
    }

    let indicator = Paragraph::new(Line::from(spans)).wrap(Wrap { trim: false });

    f.render_widget(indicator, area);
}

/// Render the current step's title and description
fn render_step_header(f: &mut Frame, area: Rect, wizard: &WizardState) {
    let step = wizard.current_step_def();

    let lines = vec![
        Line::from(Span::styled(
            step.title,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            step.description,
            Style::default().fg(GRAY_400),
        )),
    ];

    let header = Paragraph::new(lines).wrap(Wrap { trim: false });

    f.render_widget(header, area);
}

/// Render the error message in red
fn render_error(f: &mut Frame, area: Rect, wizard: &WizardState) {
    if let Some(ref err) = wizard.error {
        let error_line = Paragraph::new(Line::from(Span::styled(
            format!("  Error: {}", err),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        f.render_widget(error_line, area);
    }
}

/// Render the completion/result message in green
fn render_completion(f: &mut Frame, area: Rect, wizard: &WizardState) {
    let msg = wizard.result_message.as_deref().unwrap_or("Complete!");

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", msg),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to close",
            Style::default().fg(GRAY_400),
        )),
    ];

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

/// Render all fields for the current wizard step
fn render_fields(f: &mut Frame, area: Rect, wizard: &WizardState) {
    let step = wizard.current_step_def();

    // Calculate constraints: each field gets a dynamic height
    let mut constraints: Vec<Constraint> = Vec::new();
    for field in &step.fields {
        match &field.field_type {
            FieldType::Info(_) => constraints.push(Constraint::Length(2)),
            FieldType::Text => constraints.push(Constraint::Length(2)),
            FieldType::Toggle => constraints.push(Constraint::Length(2)),
            FieldType::Select(options) => {
                // 1 line for label + 1 per option
                constraints.push(Constraint::Length((1 + options.len()) as u16));
            }
        }
    }
    // Fill remaining space
    constraints.push(Constraint::Min(0));

    let field_areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut editable_idx: usize = 0;

    for (i, field) in step.fields.iter().enumerate() {
        let field_area = field_areas[i];

        match &field.field_type {
            FieldType::Info(text) => {
                render_info_field(f, field_area, field.label, text);
            }
            FieldType::Text => {
                let is_active = editable_idx == wizard.active_field;
                let value = wizard
                    .fields
                    .get(field.key)
                    .map(|v| v.as_text().to_string())
                    .unwrap_or_default();
                render_text_field(f, field_area, field.label, &value, is_active);
                editable_idx += 1;
            }
            FieldType::Toggle => {
                let is_active = editable_idx == wizard.active_field;
                let value = wizard
                    .fields
                    .get(field.key)
                    .map(|v| v.as_bool())
                    .unwrap_or(false);
                render_toggle_field(f, field_area, field.label, value, is_active);
                editable_idx += 1;
            }
            FieldType::Select(options) => {
                let is_active = editable_idx == wizard.active_field;
                let selected = wizard
                    .fields
                    .get(field.key)
                    .map(|v| v.as_selected())
                    .unwrap_or(0);
                render_select_field(f, field_area, field.label, options, selected, is_active);
                editable_idx += 1;
            }
        }
    }
}

/// Render an informational (read-only) field
fn render_info_field(f: &mut Frame, area: Rect, label: &str, text: &str) {
    let line = Line::from(vec![
        Span::styled(format!("  {}: ", label), Style::default().fg(GRAY_400)),
        Span::styled(
            text.to_string(),
            Style::default().fg(GRAY_400).add_modifier(Modifier::DIM),
        ),
    ]);

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}

/// Render a text input field with cursor indicator when active
fn render_text_field(f: &mut Frame, area: Rect, label: &str, value: &str, is_active: bool) {
    let label_style = if is_active {
        Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(GRAY_400)
    };

    let value_style = if is_active {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(GRAY_400)
    };

    let cursor = if is_active { "_" } else { "" };

    let line = Line::from(vec![
        Span::styled(format!("  {}: ", label), label_style),
        Span::styled(format!("{}{}", value, cursor), value_style),
    ]);

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}

/// Render a boolean toggle field
fn render_toggle_field(f: &mut Frame, area: Rect, label: &str, value: bool, is_active: bool) {
    let label_style = if is_active {
        Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(GRAY_400)
    };

    let (indicator, indicator_color) = if value {
        ("\u{2713}", Color::Green) // checkmark
    } else {
        ("\u{2717}", Color::Red) // x mark
    };

    let line = Line::from(vec![
        Span::styled(format!("  {}: ", label), label_style),
        Span::styled("[", Style::default().fg(GRAY_400)),
        Span::styled(indicator.to_string(), Style::default().fg(indicator_color)),
        Span::styled("]", Style::default().fg(GRAY_400)),
    ]);

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}

/// Render a select field with vertically listed options
fn render_select_field(
    f: &mut Frame,
    area: Rect,
    label: &str,
    options: &[(&'static str, &'static str)],
    selected: usize,
    is_active: bool,
) {
    let label_style = if is_active {
        Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(GRAY_400)
    };

    let mut lines: Vec<Line> = Vec::new();

    // Label line
    lines.push(Line::from(Span::styled(
        format!("  {}:", label),
        label_style,
    )));

    // Option lines
    for (idx, (_value, display)) in options.iter().enumerate() {
        let is_selected = idx == selected;
        let prefix = if is_selected { ">" } else { " " };

        let option_style = if is_selected && is_active {
            Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
        } else if is_selected {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(GRAY_400)
        };

        lines.push(Line::from(Span::styled(
            format!("    {} {}", prefix, display),
            option_style,
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, area);
}

/// Render the footer keybinding hints
fn render_footer(f: &mut Frame, area: Rect, wizard: &WizardState) {
    let nav_hint = if wizard.is_last() {
        "Enter: Submit"
    } else {
        "Enter: Next Step"
    };

    let back_hint = if wizard.is_first() {
        "Esc: Cancel"
    } else {
        "Esc: Back"
    };

    let line = Line::from(vec![
        Span::styled("  Tab", Style::default().fg(ORANGE)),
        Span::styled(": Next Field", Style::default().fg(GRAY_400)),
        Span::styled("  |  ", Style::default().fg(GRAY_800)),
        Span::styled(nav_hint, Style::default().fg(GRAY_400)),
        Span::styled("  |  ", Style::default().fg(GRAY_800)),
        Span::styled(back_hint, Style::default().fg(GRAY_400)),
        Span::styled("  |  ", Style::default().fg(GRAY_800)),
        Span::styled("Space", Style::default().fg(ORANGE)),
        Span::styled(": Toggle", Style::default().fg(GRAY_400)),
    ]);

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}

/// Create a centered rectangle using the standard Ratatui pattern
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

//! Centralized color theme for Ghost Node TUI

#![allow(dead_code)]

use ratatui::style::Color;

/// Vivid orange — titles, borders, active tab
pub const PRIMARY: Color = Color::Rgb(255, 140, 0);

/// Dim orange — secondary accents, inline data values
pub const PRIMARY_DIM: Color = Color::Rgb(180, 100, 0);

/// Highlights, block heights
pub const ACCENT: Color = Color::Yellow;

/// Main text
pub const TEXT: Color = Color::White;

/// Secondary text
pub const TEXT_DIM: Color = Color::Gray;

/// Muted text, disabled items
pub const TEXT_MUTED: Color = Color::DarkGray;

/// Success indicators
pub const OK: Color = Color::Green;

/// Warning indicators
pub const WARN: Color = Color::Yellow;

/// Error indicators
pub const ERR: Color = Color::Red;

/// Selected row background
pub const BG_SELECTED: Color = Color::DarkGray;

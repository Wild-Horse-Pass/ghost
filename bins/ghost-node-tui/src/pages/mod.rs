//! Page rendering module for Ghost Node TUI

pub mod overview;
pub mod bitcoin;
pub mod l2_service;
pub mod mining;
pub mod swarm;
pub mod logs;
pub mod watchdog;
pub mod backup;
pub mod settings;

use ratatui::Frame;
use ratatui::layout::Rect;

use crate::app::{App, Tab};

/// Render the current page based on active tab
pub fn render_page(f: &mut Frame, area: Rect, app: &App) {
    match app.current_tab {
        Tab::Overview => overview::render(f, area, app),
        Tab::Bitcoin => bitcoin::render(f, area, app),
        Tab::L2Service => l2_service::render(f, area, app),
        Tab::Mining => mining::render(f, area, app),
        Tab::Swarm => swarm::render(f, area, app),
        Tab::Logs => logs::render(f, area, app),
        Tab::Watchdog => watchdog::render(f, area, app),
        Tab::Backup => backup::render(f, area, app),
        Tab::Settings => settings::render(f, area, app),
    }
}

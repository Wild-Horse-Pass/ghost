//! Application state management for Ghost Node TUI

use std::collections::HashMap;
use std::time::Instant;

use crate::api::client::NodeApiClient;
use crate::api::types::*;
use crate::config::{NodeEntry, SwarmConfig, TuiSettings};
use crate::wizard::WizardState;

/// Main application state
pub struct App {
    // Navigation
    pub current_tab: Tab,
    pub input_mode: InputMode,
    #[allow(dead_code)]
    pub should_quit: bool,

    // Swarm Management
    pub swarm: SwarmState,
    pub active_node_idx: usize,

    // API Client (for active node)
    pub api_client: Option<NodeApiClient>,

    // Cached Data (for active node)
    pub node_data: NodeDataCache,

    // UI State
    pub status_message: String,
    pub scroll_offset: usize,
    pub selected_row: usize,
    pub input_buffer: String,
    pub pending_action: Option<PendingAction>,

    // Wizard overlay
    pub active_wizard: Option<WizardState>,

    // Refresh tracking
    #[allow(dead_code)]
    pub last_refresh: Instant,
}

/// Swarm state for multi-node management
pub struct SwarmState {
    pub nodes: Vec<NodeEntry>,
    pub settings: TuiSettings,
    pub connection_status: HashMap<String, ConnectionStatus>,
    pub node_statuses: HashMap<String, NodeStatus>,
}

/// Tab pages in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Overview = 1,
    Bitcoin = 2,
    L2Service = 3,
    Mining = 4,
    Swarm = 5,
    Logs = 6,
    Watchdog = 7,
    Backup = 8,
    Settings = 9,
}

impl Tab {
    #[allow(dead_code)]
    pub fn all() -> &'static [Tab] {
        &[
            Tab::Overview,
            Tab::Bitcoin,
            Tab::L2Service,
            Tab::Mining,
            Tab::Swarm,
            Tab::Logs,
            Tab::Watchdog,
            Tab::Backup,
            Tab::Settings,
        ]
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Bitcoin => "Bitcoin",
            Tab::L2Service => "L2 Service",
            Tab::Mining => "Mining",
            Tab::Swarm => "Swarm",
            Tab::Logs => "Logs",
            Tab::Watchdog => "Watchdog",
            Tab::Backup => "Backup",
            Tab::Settings => "Settings",
        }
    }

    #[allow(dead_code)]
    pub fn from_number(n: u8) -> Option<Tab> {
        match n {
            1 => Some(Tab::Overview),
            2 => Some(Tab::Bitcoin),
            3 => Some(Tab::L2Service),
            4 => Some(Tab::Mining),
            5 => Some(Tab::Swarm),
            6 => Some(Tab::Logs),
            7 => Some(Tab::Watchdog),
            8 => Some(Tab::Backup),
            9 => Some(Tab::Settings),
            _ => None,
        }
    }

    pub fn next(&self) -> Tab {
        match self {
            Tab::Overview => Tab::Bitcoin,
            Tab::Bitcoin => Tab::L2Service,
            Tab::L2Service => Tab::Mining,
            Tab::Mining => Tab::Swarm,
            Tab::Swarm => Tab::Logs,
            Tab::Logs => Tab::Watchdog,
            Tab::Watchdog => Tab::Backup,
            Tab::Backup => Tab::Settings,
            Tab::Settings => Tab::Overview,
        }
    }

    pub fn prev(&self) -> Tab {
        match self {
            Tab::Overview => Tab::Settings,
            Tab::Bitcoin => Tab::Overview,
            Tab::L2Service => Tab::Bitcoin,
            Tab::Mining => Tab::L2Service,
            Tab::Swarm => Tab::Mining,
            Tab::Logs => Tab::Swarm,
            Tab::Watchdog => Tab::Logs,
            Tab::Backup => Tab::Watchdog,
            Tab::Settings => Tab::Backup,
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Bitcoin => 1,
            Tab::L2Service => 2,
            Tab::Mining => 3,
            Tab::Swarm => 4,
            Tab::Logs => 5,
            Tab::Watchdog => 6,
            Tab::Backup => 7,
            Tab::Settings => 8,
        }
    }

    pub fn data_type(&self) -> DataType {
        match self {
            Tab::Overview => DataType::NodeStatus,
            Tab::Bitcoin => DataType::Peers,
            Tab::L2Service => DataType::GhostPay,
            Tab::Mining => DataType::Mining,
            Tab::Swarm => DataType::NodeStatus,
            Tab::Logs => DataType::Logs,
            Tab::Watchdog => DataType::Watchdog,
            Tab::Backup => DataType::Backup,
            Tab::Settings => DataType::NodeStatus,
        }
    }
}

/// Input modes for the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Normal navigation mode
    Normal,
    /// Editing node name in swarm
    NodeName,
    /// Entering new node URL
    NodeUrl,
    /// Search mode
    Search,
    /// Filter mode
    #[allow(dead_code)]
    Filter,
    /// Confirmation dialog (delete node)
    ConfirmDelete,
    /// Confirmation dialog (generic action)
    ConfirmAction,
    /// Entering node nickname
    InputNickname,
    /// Entering payout address
    InputPayoutAddress,
    /// Help overlay visible
    Help,
    /// Wizard picker overlay (press 1-9 to launch a wizard)
    WizardPicker,
}

/// Actions that require confirmation before execution
#[derive(Debug, Clone)]
pub enum PendingAction {
    RestartService(String),
    StopService(String),
    #[allow(dead_code)]
    StartService(String),
    #[allow(dead_code)]
    ToggleCapability {
        name: String,
        new_value: bool,
    },
    TriggerBackup,
    DeleteBackup(String),
}

/// Connection status for a node
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConnectionStatus {
    Connected,
    #[allow(dead_code)]
    Connecting,
    #[default]
    Disconnected,
    Error(String),
}

/// Cached data from API responses
#[derive(Default)]
pub struct NodeDataCache {
    // Node status
    pub node_status: Option<NodeStatus>,
    pub resources: Option<ResourceStatus>,
    pub rewards: Option<RewardsData>,

    // Bitcoin/L1
    pub peers: Option<Vec<PeerInfo>>,

    // Mining
    pub mining_status: Option<MiningStatus>,
    pub miners: Option<Vec<MinerInfo>>,

    // L2/Ghost Pay
    pub ghostpay_status: Option<GhostPayStatus>,
    pub wraith_sessions: Option<Vec<WraithSession>>,
    pub locks_summary: Option<LocksSummary>,

    // Watchdog
    pub watchdog: Option<WatchdogStatus>,

    // Backup
    pub backup_history: Option<Vec<BackupEntry>>,

    // Logs
    pub logs: Option<Vec<LogEntry>>,
    pub log_filter_level: LogLevel,

    // Timestamps for staleness
    pub last_updated: HashMap<DataType, Instant>,
}

/// Types of data that can be refreshed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataType {
    NodeStatus,
    #[allow(dead_code)]
    Resources,
    #[allow(dead_code)]
    Rewards,
    Peers,
    Mining,
    #[allow(dead_code)]
    Miners,
    GhostPay,
    #[allow(dead_code)]
    Wraith,
    #[allow(dead_code)]
    Locks,
    Watchdog,
    Backup,
    Logs,
}

impl App {
    pub fn new(config: SwarmConfig) -> Self {
        let active_idx = config.nodes.iter().position(|n| n.default).unwrap_or(0);

        let swarm = SwarmState {
            nodes: config.nodes,
            settings: config.settings,
            connection_status: HashMap::new(),
            node_statuses: HashMap::new(),
        };

        Self {
            current_tab: Tab::Overview,
            input_mode: InputMode::Normal,
            should_quit: false,
            swarm,
            active_node_idx: active_idx,
            api_client: None,
            node_data: NodeDataCache::default(),
            status_message: String::new(),
            scroll_offset: 0,
            selected_row: 0,
            input_buffer: String::new(),
            pending_action: None,
            active_wizard: None,
            last_refresh: Instant::now(),
        }
    }

    pub fn active_node(&self) -> Option<&NodeEntry> {
        self.swarm.nodes.get(self.active_node_idx)
    }

    pub fn active_connection_status(&self) -> ConnectionStatus {
        self.active_node()
            .and_then(|node| self.swarm.connection_status.get(&node.url))
            .cloned()
            .unwrap_or(ConnectionStatus::Disconnected)
    }

    /// Get the number of scrollable rows for the current tab
    pub fn scrollable_row_count(&self) -> usize {
        match self.current_tab {
            Tab::Swarm => self.swarm.nodes.len(),
            Tab::Mining => self.node_data.miners.as_ref().map_or(0, |m| m.len()),
            Tab::Bitcoin => self.node_data.peers.as_ref().map_or(0, |p| p.len()),
            Tab::Backup => self
                .node_data
                .backup_history
                .as_ref()
                .map_or(0, |b| b.len()),
            Tab::Logs => self.node_data.logs.as_ref().map_or(0, |l| l.len()),
            Tab::L2Service => self
                .node_data
                .wraith_sessions
                .as_ref()
                .map_or(0, |s| s.len()),
            Tab::Watchdog => self
                .node_data
                .watchdog
                .as_ref()
                .map_or(0, |w| w.recent_events.len()),
            _ => 0,
        }
    }

    /// Clamp scroll_offset and selected_row to valid range
    pub fn clamp_scroll(&mut self) {
        let max = self.scrollable_row_count();
        if max == 0 {
            self.selected_row = 0;
            self.scroll_offset = 0;
        } else {
            self.selected_row = self.selected_row.min(max.saturating_sub(1));
            self.scroll_offset = self.scroll_offset.min(max.saturating_sub(1));
        }
    }

    #[allow(dead_code)]
    pub fn set_status_message(&mut self, msg: impl Into<String>) {
        self.status_message = msg.into();
    }

    #[allow(dead_code)]
    pub fn clear_status_message(&mut self) {
        self.status_message.clear();
    }

    #[allow(dead_code)]
    pub fn next_tab(&mut self) {
        self.current_tab = self.current_tab.next();
        self.scroll_offset = 0;
        self.selected_row = 0;
    }

    #[allow(dead_code)]
    pub fn prev_tab(&mut self) {
        self.current_tab = self.current_tab.prev();
        self.scroll_offset = 0;
        self.selected_row = 0;
    }

    #[allow(dead_code)]
    pub fn goto_tab(&mut self, tab: Tab) {
        self.current_tab = tab;
        self.scroll_offset = 0;
        self.selected_row = 0;
    }
}

impl NodeDataCache {
    #[allow(dead_code)]
    pub fn is_stale(&self, data_type: DataType, max_age_secs: u64) -> bool {
        self.last_updated
            .get(&data_type)
            .map(|t| t.elapsed().as_secs() > max_age_secs)
            .unwrap_or(true)
    }

    fn mark_updated(&mut self, data_type: DataType) {
        self.last_updated.insert(data_type, Instant::now());
    }

    pub fn mark_refreshed(&mut self, data_type: DataType) {
        self.mark_updated(data_type);
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

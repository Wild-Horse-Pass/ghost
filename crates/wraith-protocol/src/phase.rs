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
//| FILE: phase.rs                                                                                                       |
//|======================================================================================================================|

//! Phase execution for Wraith Protocol
//!
//! Two phases:
//! - Phase 1 (Split): N inputs -> 10N intermediates
//! - Phase 2 (Merge): 10N intermediates -> N outputs

use serde::{Deserialize, Serialize};

/// Phase execution state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PhaseState {
    /// Not yet started
    Pending,
    /// Collecting signatures
    CollectingSignatures,
    /// Ready to execute (all signatures collected)
    Ready,
    /// Transaction broadcast, waiting for confirmation
    Broadcasting,
    /// Confirmed on-chain
    Confirmed,
    /// Failed
    Failed,
}

impl PhaseState {
    /// Check if phase is complete (successfully or failed)
    pub fn is_terminal(&self) -> bool {
        matches!(self, PhaseState::Confirmed | PhaseState::Failed)
    }

    /// Check if phase can accept signatures
    pub fn can_accept_signatures(&self) -> bool {
        matches!(self, PhaseState::Pending | PhaseState::CollectingSignatures)
    }
}

impl std::fmt::Display for PhaseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PhaseState::Pending => write!(f, "Pending"),
            PhaseState::CollectingSignatures => write!(f, "Collecting Signatures"),
            PhaseState::Ready => write!(f, "Ready"),
            PhaseState::Broadcasting => write!(f, "Broadcasting"),
            PhaseState::Confirmed => write!(f, "Confirmed"),
            PhaseState::Failed => write!(f, "Failed"),
        }
    }
}

/// Which phase of the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Phase {
    /// Phase 1: Split (N inputs -> 10N intermediates)
    Split,
    /// Phase 2: Merge (10N intermediates -> N outputs)
    Merge,
}

impl Phase {
    /// Get phase number
    pub fn number(&self) -> u8 {
        match self {
            Phase::Split => 1,
            Phase::Merge => 2,
        }
    }

    /// Get phase name
    pub fn name(&self) -> &'static str {
        match self {
            Phase::Split => "Split",
            Phase::Merge => "Merge",
        }
    }

    /// Get next phase
    pub fn next(&self) -> Option<Phase> {
        match self {
            Phase::Split => Some(Phase::Merge),
            Phase::Merge => None,
        }
    }

    /// Get input count ratio
    pub fn input_ratio(&self) -> usize {
        match self {
            Phase::Split => 1,
            Phase::Merge => 10,
        }
    }

    /// Get output count ratio
    pub fn output_ratio(&self) -> usize {
        match self {
            Phase::Split => 10,
            Phase::Merge => 1,
        }
    }

    /// Calculate number of inputs for N participants
    pub fn inputs_for_participants(&self, n: usize) -> usize {
        n * self.input_ratio()
    }

    /// Calculate number of outputs for N participants
    pub fn outputs_for_participants(&self, n: usize) -> usize {
        n * self.output_ratio()
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Phase {} ({})", self.number(), self.name())
    }
}

/// Phase execution tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseExecution {
    /// Which phase
    phase: Phase,
    /// Current state
    state: PhaseState,
    /// Transaction ID (once broadcast)
    txid: Option<String>,
    /// Block height where confirmed
    confirmed_height: Option<u32>,
    /// Number of signatures collected
    signatures_collected: usize,
    /// Number of signatures required
    signatures_required: usize,
    /// Started at (Unix timestamp)
    started_at: Option<u64>,
    /// Completed at (Unix timestamp)
    completed_at: Option<u64>,
}

impl PhaseExecution {
    /// Create new phase execution
    pub fn new(phase: Phase, participants: usize) -> Self {
        Self {
            phase,
            state: PhaseState::Pending,
            txid: None,
            confirmed_height: None,
            signatures_collected: 0,
            signatures_required: participants,
            started_at: None,
            completed_at: None,
        }
    }

    /// Get phase
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Get current state
    pub fn state(&self) -> PhaseState {
        self.state
    }

    /// Get transaction ID
    pub fn txid(&self) -> Option<&str> {
        self.txid.as_deref()
    }

    /// Get confirmation height
    pub fn confirmed_height(&self) -> Option<u32> {
        self.confirmed_height
    }

    /// Check if all signatures collected
    pub fn has_all_signatures(&self) -> bool {
        self.signatures_collected >= self.signatures_required
    }

    /// Get signature progress as percentage
    pub fn signature_progress(&self) -> f64 {
        if self.signatures_required == 0 {
            100.0
        } else {
            (self.signatures_collected as f64 / self.signatures_required as f64) * 100.0
        }
    }

    /// Start collecting signatures
    pub fn start(&mut self) {
        if self.state == PhaseState::Pending {
            self.state = PhaseState::CollectingSignatures;
            self.started_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
        }
    }

    /// Record signature collected
    pub fn add_signature(&mut self) {
        self.signatures_collected += 1;
        if self.has_all_signatures() {
            self.state = PhaseState::Ready;
        }
    }

    /// Mark as broadcasting
    pub fn broadcast(&mut self, txid: String) {
        if self.state == PhaseState::Ready {
            self.state = PhaseState::Broadcasting;
            self.txid = Some(txid);
        }
    }

    /// Mark as confirmed
    pub fn confirm(&mut self, height: u32) {
        if self.state == PhaseState::Broadcasting {
            self.state = PhaseState::Confirmed;
            self.confirmed_height = Some(height);
            self.completed_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
        }
    }

    /// Mark as failed
    pub fn fail(&mut self) {
        self.state = PhaseState::Failed;
        self.completed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_ratios() {
        // Split: 1 input -> 10 outputs
        assert_eq!(Phase::Split.input_ratio(), 1);
        assert_eq!(Phase::Split.output_ratio(), 10);
        assert_eq!(Phase::Split.inputs_for_participants(100), 100);
        assert_eq!(Phase::Split.outputs_for_participants(100), 1000);

        // Merge: 10 inputs -> 1 output
        assert_eq!(Phase::Merge.input_ratio(), 10);
        assert_eq!(Phase::Merge.output_ratio(), 1);
        assert_eq!(Phase::Merge.inputs_for_participants(100), 1000);
        assert_eq!(Phase::Merge.outputs_for_participants(100), 100);
    }

    #[test]
    fn test_phase_execution_lifecycle() {
        let mut exec = PhaseExecution::new(Phase::Split, 3);

        assert_eq!(exec.state(), PhaseState::Pending);

        exec.start();
        assert_eq!(exec.state(), PhaseState::CollectingSignatures);

        exec.add_signature();
        exec.add_signature();
        assert_eq!(exec.state(), PhaseState::CollectingSignatures);

        exec.add_signature();
        assert_eq!(exec.state(), PhaseState::Ready);
        assert!(exec.has_all_signatures());

        exec.broadcast("abc123".to_string());
        assert_eq!(exec.state(), PhaseState::Broadcasting);
        assert_eq!(exec.txid(), Some("abc123"));

        exec.confirm(800_000);
        assert_eq!(exec.state(), PhaseState::Confirmed);
        assert_eq!(exec.confirmed_height(), Some(800_000));
    }
}

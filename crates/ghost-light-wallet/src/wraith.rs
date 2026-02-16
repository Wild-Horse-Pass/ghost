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
//| FILE: wraith.rs                                                                                                      |
//|======================================================================================================================|

//! Wraith Wizard — high-level wrapper for CoinJoin mixing sessions
//!
//! Provides a simplified API for CLI and TUI wallets to drive
//! the full Wraith mixing lifecycle: denomination selection,
//! UTXO selection, session join, and progress polling.

use std::fmt;

use wraith_protocol::{
    ParticipantTier, SessionState, WraithDenomination, WraithError, WraithSession,
};

/// Wizard step tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    /// User selects denomination tier
    SelectDenomination,
    /// User selects UTXO to mix
    SelectUtxo,
    /// Session joined, waiting for participants
    WaitingForParticipants,
    /// Phase 1: Split transaction
    Phase1Splitting,
    /// Phase 1 waiting for confirmation
    Phase1Confirming,
    /// Phase 2: Merge transaction
    Phase2Merging,
    /// Phase 2 waiting for confirmation
    Phase2Confirming,
    /// Mixing complete
    Complete,
    /// Session failed
    Failed,
}

impl fmt::Display for WizardStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WizardStep::SelectDenomination => write!(f, "Select denomination"),
            WizardStep::SelectUtxo => write!(f, "Select UTXO to mix"),
            WizardStep::WaitingForParticipants => write!(f, "Waiting for participants..."),
            WizardStep::Phase1Splitting => write!(f, "Phase 1: Splitting..."),
            WizardStep::Phase1Confirming => write!(f, "Phase 1: Waiting for confirmation..."),
            WizardStep::Phase2Merging => write!(f, "Phase 2: Merging..."),
            WizardStep::Phase2Confirming => write!(f, "Phase 2: Waiting for confirmation..."),
            WizardStep::Complete => write!(f, "Mixing complete!"),
            WizardStep::Failed => write!(f, "Session failed"),
        }
    }
}

/// Progress information for display
#[derive(Debug, Clone)]
pub struct WizardProgress {
    /// Current step
    pub step: WizardStep,
    /// Human-readable status message
    pub message: String,
    /// Number of participants in session (if applicable)
    pub participant_count: Option<usize>,
    /// Minimum participants needed
    pub min_participants: Option<usize>,
    /// Fill percentage (0.0 - 1.0)
    pub fill_percentage: Option<f64>,
    /// Phase 1 txid (once broadcast)
    pub phase1_txid: Option<String>,
    /// Phase 2 txid (once broadcast)
    pub phase2_txid: Option<String>,
}

/// UTXO selected for mixing
#[derive(Debug, Clone)]
pub struct SelectedUtxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount_sats: u64,
}

/// Denomination info for display
#[derive(Debug, Clone)]
pub struct DenominationInfo {
    /// The denomination
    pub denomination: WraithDenomination,
    /// Human-readable name
    pub name: String,
    /// Short code (MI, SM, MD, LG)
    pub short_code: String,
    /// Output amount in sats
    pub output_sats: u64,
    /// Required input amount (output + fee)
    pub input_sats: u64,
    /// Fee in sats
    pub fee_sats: u64,
    /// Expected wait time in hours
    pub expected_wait_hours: u32,
}

/// High-level Wraith wizard for light wallets
///
/// Wraps the low-level `WraithSession` state machine with a
/// step-by-step interface suitable for interactive CLI/TUI use.
pub struct WraithWizard {
    session: Option<WraithSession>,
    step: WizardStep,
    denomination: Option<WraithDenomination>,
    selected_utxo: Option<SelectedUtxo>,
    session_id: Option<String>,
    error_message: Option<String>,
}

impl WraithWizard {
    /// Create a new wizard in denomination selection step
    pub fn new() -> Self {
        Self {
            session: None,
            step: WizardStep::SelectDenomination,
            denomination: None,
            selected_utxo: None,
            session_id: None,
            error_message: None,
        }
    }

    /// Get all available denominations with display info
    pub fn available_denominations() -> Vec<DenominationInfo> {
        WraithDenomination::all()
            .iter()
            .map(|d| {
                let tier = ParticipantTier::for_balance(d.output_sats());
                DenominationInfo {
                    denomination: *d,
                    name: d.name().to_string(),
                    short_code: d.short_code().to_string(),
                    output_sats: d.output_sats(),
                    input_sats: d.input_sats(),
                    fee_sats: d.fee_sats(),
                    expected_wait_hours: tier.expected_wait_hours(),
                }
            })
            .collect()
    }

    /// Get denominations that fit within a given balance
    pub fn fitting_denominations(balance_sats: u64) -> Vec<DenominationInfo> {
        Self::available_denominations()
            .into_iter()
            .filter(|d| d.input_sats <= balance_sats)
            .collect()
    }

    /// Select a denomination and advance to UTXO selection
    pub fn select_denomination(
        &mut self,
        denomination: WraithDenomination,
    ) -> Result<(), WraithError> {
        if self.step != WizardStep::SelectDenomination {
            return Err(WraithError::InvalidState {
                expected: "SelectDenomination".to_string(),
                actual: format!("{:?}", self.step),
            });
        }

        self.denomination = Some(denomination);
        self.step = WizardStep::SelectUtxo;
        Ok(())
    }

    /// Select a UTXO for mixing
    pub fn select_utxo(
        &mut self,
        txid: &str,
        vout: u32,
        amount_sats: u64,
    ) -> Result<(), WraithError> {
        if self.step != WizardStep::SelectUtxo {
            return Err(WraithError::InvalidState {
                expected: "SelectUtxo".to_string(),
                actual: format!("{:?}", self.step),
            });
        }

        let denomination = self.denomination.ok_or(WraithError::MissingData(
            "Denomination not selected".to_string(),
        ))?;

        // Verify UTXO has enough sats
        if amount_sats < denomination.input_sats() {
            return Err(WraithError::InvalidInput(format!(
                "UTXO amount {} sats is less than required {} sats ({})",
                amount_sats,
                denomination.input_sats(),
                denomination.name()
            )));
        }

        self.selected_utxo = Some(SelectedUtxo {
            txid: txid.to_string(),
            vout,
            amount_sats,
        });

        Ok(())
    }

    /// Join a session and create the internal WraithSession
    ///
    /// This transitions to WaitingForParticipants. The caller should
    /// then poll `progress()` to track session state.
    pub fn join(&mut self) -> Result<String, WraithError> {
        if self.step != WizardStep::SelectUtxo {
            return Err(WraithError::InvalidState {
                expected: "SelectUtxo".to_string(),
                actual: format!("{:?}", self.step),
            });
        }

        if self.selected_utxo.is_none() {
            return Err(WraithError::MissingData("No UTXO selected".to_string()));
        }

        let denomination = self.denomination.ok_or(WraithError::MissingData(
            "Denomination not selected".to_string(),
        ))?;

        let tier = ParticipantTier::for_balance(denomination.output_sats());
        let session = WraithSession::new(tier, denomination);
        let session_id = format!(
            "wraith-{}-{}",
            denomination.short_code().to_lowercase(),
            chrono::Utc::now().timestamp()
        );

        self.session = Some(session);
        self.session_id = Some(session_id.clone());
        self.step = WizardStep::WaitingForParticipants;

        Ok(session_id)
    }

    /// Get current progress for display
    pub fn progress(&self) -> WizardProgress {
        let (participant_count, min_participants, fill_percentage) =
            if let Some(ref session) = self.session {
                let tier = ParticipantTier::for_balance(
                    self.denomination
                        .map(|d| d.output_sats())
                        .unwrap_or(10_000),
                );
                (
                    Some(session.participant_count()),
                    Some(tier.min_participants()),
                    Some(session.fill_percentage()),
                )
            } else {
                (None, None, None)
            };

        let (phase1_txid, phase2_txid) = if let Some(ref session) = self.session {
            (
                session.phase1().and_then(|p| p.txid().map(String::from)),
                session.phase2().and_then(|p| p.txid().map(String::from)),
            )
        } else {
            (None, None)
        };

        WizardProgress {
            step: self.step,
            message: self.step.to_string(),
            participant_count,
            min_participants,
            fill_percentage,
            phase1_txid,
            phase2_txid,
        }
    }

    /// Update wizard state from session state changes
    ///
    /// Call this after external events (coordinator updates, blockchain
    /// confirmations) to advance the wizard step.
    pub fn sync_from_session(&mut self) {
        if let Some(ref session) = self.session {
            self.step = match session.state() {
                SessionState::WaitingForParticipants => WizardStep::WaitingForParticipants,
                SessionState::CollectingInputs => WizardStep::WaitingForParticipants,
                SessionState::ExecutingPhase1 => WizardStep::Phase1Splitting,
                SessionState::WaitingPhase1Confirmation => WizardStep::Phase1Confirming,
                SessionState::ExecutingPhase2 => WizardStep::Phase2Merging,
                SessionState::WaitingPhase2Confirmation => WizardStep::Phase2Confirming,
                SessionState::Completed => WizardStep::Complete,
                SessionState::Failed => WizardStep::Failed,
                SessionState::Refunded => WizardStep::Failed,
            };
        }
    }

    /// Check if the wizard is in a terminal state
    pub fn is_complete(&self) -> bool {
        matches!(self.step, WizardStep::Complete | WizardStep::Failed)
    }

    /// Check if the wizard succeeded
    pub fn is_success(&self) -> bool {
        self.step == WizardStep::Complete
    }

    /// Get the current wizard step
    pub fn step(&self) -> WizardStep {
        self.step
    }

    /// Get the selected denomination
    pub fn denomination(&self) -> Option<WraithDenomination> {
        self.denomination
    }

    /// Get the selected UTXO
    pub fn selected_utxo(&self) -> Option<&SelectedUtxo> {
        self.selected_utxo.as_ref()
    }

    /// Get the session ID (after join)
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Get mutable reference to the underlying session
    pub fn session_mut(&mut self) -> Option<&mut WraithSession> {
        self.session.as_mut()
    }

    /// Get reference to the underlying session
    pub fn session(&self) -> Option<&WraithSession> {
        self.session.as_ref()
    }

    /// Set error and move to failed state
    pub fn fail(&mut self, message: &str) {
        self.error_message = Some(message.to_string());
        self.step = WizardStep::Failed;
    }

    /// Get error message if in failed state
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }
}

impl Default for WraithWizard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wizard_creation() {
        let wizard = WraithWizard::new();
        assert_eq!(wizard.step(), WizardStep::SelectDenomination);
        assert!(!wizard.is_complete());
    }

    #[test]
    fn test_available_denominations() {
        let denoms = WraithWizard::available_denominations();
        assert_eq!(denoms.len(), 4);
        assert_eq!(denoms[0].short_code, "MI");
        assert_eq!(denoms[3].short_code, "LG");
    }

    #[test]
    fn test_fitting_denominations() {
        // 50,000 sats should only fit Micro (requires 10,100)
        let fitting = WraithWizard::fitting_denominations(50_000);
        assert_eq!(fitting.len(), 1);
        assert_eq!(fitting[0].short_code, "MI");

        // 1 BTC should fit all
        let fitting = WraithWizard::fitting_denominations(200_000_000);
        assert_eq!(fitting.len(), 4);
    }

    #[test]
    fn test_wizard_flow() {
        let mut wizard = WraithWizard::new();

        // Select denomination
        wizard
            .select_denomination(WraithDenomination::Micro)
            .unwrap();
        assert_eq!(wizard.step(), WizardStep::SelectUtxo);

        // Select UTXO (10,100+ sats for Micro)
        wizard
            .select_utxo(
                "abc123def456abc123def456abc123def456abc123def456abc123def456abc123de",
                0,
                20_000,
            )
            .unwrap();
        assert_eq!(wizard.step(), WizardStep::SelectUtxo); // stays until join

        // Join session
        let session_id = wizard.join().unwrap();
        assert!(session_id.starts_with("wraith-mi-"));
        assert_eq!(wizard.step(), WizardStep::WaitingForParticipants);
    }

    #[test]
    fn test_insufficient_utxo() {
        let mut wizard = WraithWizard::new();
        wizard
            .select_denomination(WraithDenomination::Large)
            .unwrap();

        // Large requires 101,000,000 sats, try with 1000
        let result = wizard.select_utxo("abc123", 0, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_step_errors() {
        let mut wizard = WraithWizard::new();

        // Can't select UTXO before denomination
        let result = wizard.select_utxo("abc", 0, 1000);
        assert!(result.is_err());

        // Can't join before UTXO selection
        let result = wizard.join();
        assert!(result.is_err());
    }

    #[test]
    fn test_progress() {
        let wizard = WraithWizard::new();
        let progress = wizard.progress();
        assert_eq!(progress.step, WizardStep::SelectDenomination);
        assert!(progress.participant_count.is_none());
    }

    #[test]
    fn test_fail() {
        let mut wizard = WraithWizard::new();
        wizard.fail("Connection lost");
        assert!(wizard.is_complete());
        assert!(!wizard.is_success());
        assert_eq!(wizard.error_message(), Some("Connection lost"));
    }
}

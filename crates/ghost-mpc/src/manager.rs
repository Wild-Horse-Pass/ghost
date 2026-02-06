//! MPC Ceremony Manager
//!
//! Manages the state of the rolling MPC ceremony, including:
//! - Tracking contribution count and current parameters
//! - Generating and verifying contributions
//! - Hot-swapping parameters after contributions are applied
//! - Detecting and enforcing ossification

use crate::contribution::{
    generate_contribution, hash_parameters, verify_contribution, ContributionCommitment,
    MpcContribution,
};
use std::collections::HashMap;
use crate::errors::{MpcError, MpcResult};
use crate::params::{
    load_parameters, save_parameters, save_verifying_key, update_current_params, ParameterFiles,
};
use crate::MAX_CEREMONY_CONTRIBUTORS;
use bellperson::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey};
use blstrs::Bls12;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// 3.9 SECURITY: Maximum ceremony duration before auto-ossification (30 days)
/// This ensures the ceremony cannot remain open indefinitely, preventing
/// attackers from waiting for an opportune moment to contribute malicious parameters.
const MAX_CEREMONY_DURATION_SECS: u64 = 30 * 24 * 60 * 60; // 30 days

/// State of the MPC ceremony
#[derive(Debug, Clone)]
pub struct CeremonyState {
    /// Number of contributions applied (0 = genesis, 101 = ossified)
    pub contribution_count: u32,
    /// Hash of the current parameters
    pub current_params_hash: [u8; 32],
    /// Whether the ceremony has ossified (permanently closed)
    pub is_ossified: bool,
    /// Block height when ossification occurred (if ossified)
    pub ossified_at: Option<u64>,
    /// Hash of the block verifying key
    pub block_vk_hash: Option<[u8; 32]>,
    /// Hash of the payout verifying key
    pub payout_vk_hash: Option<[u8; 32]>,
    /// Last update timestamp
    pub updated_at: u64,
    /// 3.9: Genesis timestamp for time-based ossification
    pub genesis_timestamp: Option<u64>,
    /// 4.22 SECURITY: Unique ceremony identifier for binding proofs
    /// Derived from genesis parameters hash to ensure uniqueness across ceremonies
    pub ceremony_id: [u8; 32],
    /// CRIT-2 FIX: Number of pending commitments (not yet fulfilled)
    pub pending_commitment_count: u32,
}

impl Default for CeremonyState {
    fn default() -> Self {
        Self {
            contribution_count: 0,
            current_params_hash: [0u8; 32],
            is_ossified: false,
            ossified_at: None,
            block_vk_hash: None,
            payout_vk_hash: None,
            updated_at: 0,
            genesis_timestamp: None,
            // Default ceremony_id is all zeros - must be set at initialization
            ceremony_id: [0u8; 32],
            // CRIT-2 FIX: No pending commitments initially
            pending_commitment_count: 0,
        }
    }
}

impl CeremonyState {
    /// 3.9 SECURITY: Check if ceremony should auto-ossify due to time limit
    ///
    /// The ceremony automatically ossifies 30 days after genesis to prevent
    /// attackers from waiting indefinitely for an opportune moment to contribute.
    pub fn should_time_ossify(&self) -> bool {
        if self.is_ossified {
            return false; // Already ossified
        }

        let Some(genesis_ts) = self.genesis_timestamp else {
            return false; // No genesis yet
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now.saturating_sub(genesis_ts) >= MAX_CEREMONY_DURATION_SECS
    }
}

/// Manager for the MPC ceremony
///
/// This struct maintains the ceremony state and provides methods for:
/// - Generating contributions (for registering elders)
/// - Verifying contributions (for current elders)
/// - Applying contributions after BFT approval
/// - Hot-swapping parameters in memory
/// - CRIT-2 FIX: Tracking contribution commitments to prevent ordering attacks
pub struct CeremonyManager {
    /// Current ceremony state
    state: RwLock<CeremonyState>,
    /// Parameter file manager
    files: ParameterFiles,
    /// Current block proving parameters (hot-swappable)
    block_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
    /// Current payout proving parameters (hot-swappable)
    payout_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
    /// Prepared block verifying key (for fast verification)
    block_vk: RwLock<Option<Arc<PreparedVerifyingKey<Bls12>>>>,
    /// Prepared payout verifying key
    payout_vk: RwLock<Option<Arc<PreparedVerifyingKey<Bls12>>>>,
    /// CRIT-2 FIX: Pending contribution commitments (commitment_hash -> commitment)
    /// Contributors broadcast commitments BEFORE revealing their contribution.
    /// This prevents a malicious coordinator from silently dropping contributions.
    pending_commitments: RwLock<HashMap<[u8; 32], ContributionCommitment>>,
    /// CRIT-2 FIX: Fulfilled commitments (for audit trail)
    fulfilled_commitments: RwLock<Vec<[u8; 32]>>,
}

impl CeremonyManager {
    /// Create a new ceremony manager with the given parameters directory
    pub fn new(params_dir: PathBuf) -> Self {
        Self {
            state: RwLock::new(CeremonyState::default()),
            files: ParameterFiles::new(params_dir),
            block_params: RwLock::new(None),
            payout_params: RwLock::new(None),
            block_vk: RwLock::new(None),
            payout_vk: RwLock::new(None),
            // CRIT-2 FIX: Initialize commitment tracking
            pending_commitments: RwLock::new(HashMap::new()),
            fulfilled_commitments: RwLock::new(Vec::new()),
        }
    }

    /// Initialize the ceremony from database state or create genesis
    ///
    /// Returns the manager with state loaded from the database.
    /// If no state exists, initializes with default (pre-genesis) state.
    pub fn load_or_init(params_dir: PathBuf, db_state: Option<CeremonyState>) -> MpcResult<Self> {
        let manager = Self::new(params_dir);

        if let Some(state) = db_state {
            // Load from database
            *manager.state.write() = state;
            info!(
                contribution_count = manager.contribution_count(),
                is_ossified = manager.is_ossified(),
                "Loaded MPC ceremony state from database"
            );

            // Try to load current parameters from disk
            if manager.contribution_count() > 0 {
                manager.load_current_params()?;
            }
        } else {
            info!("No MPC ceremony state found - initializing pre-genesis state");
        }

        Ok(manager)
    }

    /// Load current parameters from disk
    fn load_current_params(&self) -> MpcResult<()> {
        self.files.ensure_dir()?;

        let block_path = self.files.current_block_params_path();
        if block_path.exists() {
            match load_parameters(&block_path) {
                Ok(params) => {
                    let vk = prepare_verifying_key(&params.vk);
                    *self.block_params.write() = Some(Arc::new(params));
                    *self.block_vk.write() = Some(Arc::new(vk));
                    info!("Loaded current block parameters");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load block parameters");
                }
            }
        }

        let payout_path = self.files.current_payout_params_path();
        if payout_path.exists() {
            match load_parameters(&payout_path) {
                Ok(params) => {
                    let vk = prepare_verifying_key(&params.vk);
                    *self.payout_params.write() = Some(Arc::new(params));
                    *self.payout_vk.write() = Some(Arc::new(vk));
                    info!("Loaded current payout parameters");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load payout parameters");
                }
            }
        }

        Ok(())
    }

    /// Get the current contribution count
    pub fn contribution_count(&self) -> u32 {
        self.state.read().contribution_count
    }

    /// Check if the ceremony has ossified
    pub fn is_ossified(&self) -> bool {
        self.state.read().is_ossified
    }

    /// Get the current parameters hash
    pub fn current_params_hash(&self) -> [u8; 32] {
        self.state.read().current_params_hash
    }

    /// Get a snapshot of the current state
    pub fn state(&self) -> CeremonyState {
        self.state.read().clone()
    }

    /// Check if we have current parameters loaded
    pub fn has_current_params(&self) -> bool {
        self.block_params.read().is_some()
    }

    /// Get current block parameters for proving
    pub fn block_params(&self) -> Option<Arc<Parameters<Bls12>>> {
        self.block_params.read().clone()
    }

    /// Get current payout parameters for proving
    pub fn payout_params(&self) -> Option<Arc<Parameters<Bls12>>> {
        self.payout_params.read().clone()
    }

    /// Get current block verifying key
    pub fn block_vk(&self) -> Option<Arc<PreparedVerifyingKey<Bls12>>> {
        self.block_vk.read().clone()
    }

    /// Get current payout verifying key
    pub fn payout_vk(&self) -> Option<Arc<PreparedVerifyingKey<Bls12>>> {
        self.payout_vk.read().clone()
    }

    /// Generate a contribution for a new elder
    ///
    /// This is called by a node that is becoming an elder and the ceremony
    /// is not yet ossified. The contribution transforms the current parameters
    /// and generates a proof of valid transformation.
    ///
    /// # Arguments
    ///
    /// * `contributor_id` - The node ID of the new elder
    ///
    /// # Returns
    ///
    /// The new parameters and contribution record
    pub fn generate_contribution(
        &self,
        contributor_id: &str,
    ) -> MpcResult<(Parameters<Bls12>, MpcContribution)> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // 3.9 SECURITY: Check time-based ossification (30 days from genesis)
        if state.should_time_ossify() {
            drop(state);
            // Trigger ossification
            self.ossify()?;
            return Err(MpcError::CeremonyOssified(self.contribution_count()));
        }

        let next_position = state.contribution_count + 1;
        if next_position > MAX_CEREMONY_CONTRIBUTORS {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Get current parameters
        let current_params = self.block_params.read();
        let params = current_params.as_ref().ok_or_else(|| {
            MpcError::Internal("No current parameters loaded for contribution".into())
        })?;

        // 4.22: Get ceremony_id for binding proofs to this ceremony
        let ceremony_id = state.ceremony_id;
        drop(state); // Release read lock before generating

        // Generate the contribution
        let mut rng = OsRng;
        let (new_params, contribution) = generate_contribution(
            params.as_ref(),
            &ceremony_id,
            next_position,
            contributor_id,
            &mut rng,
        )?;

        info!(
            position = next_position,
            contributor = contributor_id,
            prev_hash = %hex::encode(contribution.prev_params_hash),
            new_hash = %hex::encode(contribution.new_params_hash),
            "Generated MPC contribution"
        );

        Ok((new_params, contribution))
    }

    /// Generate a contribution with a prior commitment (RECOMMENDED)
    ///
    /// CRIT-2 FIX: This is the recommended way to generate contributions.
    /// The contributor should:
    /// 1. Create a commitment with `create_commitment()`
    /// 2. Broadcast the commitment to all elders
    /// 3. Wait for acknowledgment
    /// 4. Call this method with the commitment hash
    ///
    /// This ensures the contribution cannot be silently dropped.
    ///
    /// # Arguments
    ///
    /// * `contributor_id` - The node ID of the new elder
    /// * `commitment_hash` - Hash of the previously broadcast commitment
    ///
    /// # Returns
    ///
    /// The new parameters and contribution record with commitment binding
    pub fn generate_contribution_with_commitment(
        &self,
        contributor_id: &str,
        commitment_hash: [u8; 32],
    ) -> MpcResult<(Parameters<Bls12>, MpcContribution)> {
        // Verify the commitment exists and belongs to this contributor
        {
            let pending = self.pending_commitments.read();
            if let Some(commitment) = pending.get(&commitment_hash) {
                if commitment.contributor != contributor_id {
                    return Err(MpcError::UnauthorizedContributor(
                        contributor_id.to_string(),
                        commitment.contributor.clone(),
                    ));
                }
            } else {
                return Err(MpcError::InvalidProof(
                    "Commitment hash not found - broadcast commitment first".into(),
                ));
            }
        }

        // Generate the contribution
        let (new_params, mut contribution) = self.generate_contribution(contributor_id)?;

        // CRIT-2 FIX: Bind the commitment hash to the contribution
        contribution.commitment_hash = Some(commitment_hash);

        info!(
            commitment_hash = %hex::encode(commitment_hash),
            "Generated contribution bound to commitment"
        );

        Ok((new_params, contribution))
    }

    /// Verify a contribution from another node
    ///
    /// This is called by current elders to verify a contribution before
    /// casting their approval vote.
    pub fn verify_contribution(
        &self,
        new_params: &Parameters<Bls12>,
        contribution: &MpcContribution,
    ) -> MpcResult<bool> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Verify position is correct
        let expected_position = state.contribution_count + 1;
        if contribution.position != expected_position {
            return Err(MpcError::InvalidPosition(
                contribution.position,
                expected_position,
            ));
        }

        // Get current parameters
        let current_params = self.block_params.read();
        let params = current_params.as_ref().ok_or_else(|| {
            MpcError::Internal("No current parameters loaded for verification".into())
        })?;

        // 4.22: Verify the contribution with ceremony_id binding
        verify_contribution(
            params.as_ref(),
            new_params,
            contribution,
            &state.ceremony_id,
        )
    }

    /// Apply a contribution after BFT approval
    ///
    /// This updates the ceremony state and hot-swaps the parameters.
    /// Called when >67% of elders have approved the contribution.
    pub fn apply_contribution(
        &self,
        new_params: Parameters<Bls12>,
        contribution: &MpcContribution,
    ) -> MpcResult<()> {
        let mut state = self.state.write();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Verify position
        let expected_position = state.contribution_count + 1;
        if contribution.position != expected_position {
            return Err(MpcError::InvalidPosition(
                contribution.position,
                expected_position,
            ));
        }

        // Save new parameters to disk
        self.files.ensure_dir()?;
        let params_path = self.files.block_params_path(contribution.position);
        save_parameters(&params_path, &new_params)?;

        // Update current symlink
        update_current_params(&self.files, contribution.position)?;

        // Save verifying key
        save_verifying_key(&self.files.block_vk_path(), &new_params.vk)?;

        // Hot-swap in-memory parameters
        let vk = prepare_verifying_key(&new_params.vk);
        *self.block_params.write() = Some(Arc::new(new_params));
        *self.block_vk.write() = Some(Arc::new(vk));

        // Update state
        state.contribution_count = contribution.position;
        state.current_params_hash = contribution.new_params_hash;
        state.block_vk_hash = Some(contribution.new_params_hash); // Same hash for now
        state.updated_at = contribution.timestamp;

        // CRIT-2 FIX: If contribution has a commitment hash, verify and mark as fulfilled
        if let Some(commitment_hash) = contribution.commitment_hash {
            let mut pending = self.pending_commitments.write();
            if let Some(commitment) = pending.remove(&commitment_hash) {
                // Verify commitment matches contribution
                if !commitment.matches_contribution(contribution) {
                    warn!(
                        contributor = %contribution.contributor,
                        "Contribution commitment mismatch - possible tampering detected"
                    );
                }
                // Record fulfilled commitment for audit
                self.fulfilled_commitments.write().push(commitment_hash);
                state.pending_commitment_count = state.pending_commitment_count.saturating_sub(1);
            }
        }

        info!(
            position = contribution.position,
            contributor = %contribution.contributor,
            params_hash = %hex::encode(contribution.new_params_hash),
            pending_commitments = state.pending_commitment_count,
            "Applied MPC contribution - parameters updated"
        );

        // Check for ossification
        if contribution.position >= MAX_CEREMONY_CONTRIBUTORS {
            self.ossify_internal(&mut state)?;
        }

        Ok(())
    }

    /// Mark the ceremony as ossified
    ///
    /// This is called when elder 101 contributes, permanently closing
    /// the ceremony.
    pub fn ossify(&self) -> MpcResult<()> {
        let mut state = self.state.write();
        self.ossify_internal(&mut state)
    }

    fn ossify_internal(&self, state: &mut CeremonyState) -> MpcResult<()> {
        if state.is_ossified {
            return Ok(()); // Already ossified
        }

        state.is_ossified = true;
        state.ossified_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );

        info!(
            contribution_count = state.contribution_count,
            "MPC ceremony OSSIFIED - parameters are now permanent"
        );

        Ok(())
    }

    // ========================================================================
    // CRIT-2 FIX: Contribution Commitment Methods
    // ========================================================================

    /// Record a contribution commitment
    ///
    /// Contributors should broadcast a commitment BEFORE generating their contribution.
    /// This prevents a malicious coordinator from silently dropping contributions,
    /// as any dropped commitment can be detected during audit.
    ///
    /// # Arguments
    /// * `commitment` - The commitment to record
    ///
    /// # Returns
    /// The commitment hash for inclusion in the contribution
    pub fn record_commitment(&self, commitment: ContributionCommitment) -> MpcResult<[u8; 32]> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Verify commitment is for the correct ceremony
        if commitment.ceremony_id != state.ceremony_id {
            return Err(MpcError::InvalidProof(
                "Commitment is for a different ceremony".into(),
            ));
        }

        // Verify commitment chains from current parameters
        if commitment.prev_params_hash != state.current_params_hash {
            return Err(MpcError::InvalidChain {
                expected: hex::encode(state.current_params_hash),
                actual: hex::encode(commitment.prev_params_hash),
            });
        }

        let commitment_hash = commitment.hash();
        drop(state);

        // Record the commitment
        let mut pending = self.pending_commitments.write();
        if pending.contains_key(&commitment_hash) {
            return Err(MpcError::DuplicateContribution(0));
        }
        pending.insert(commitment_hash, commitment);

        // Update pending count in state
        self.state.write().pending_commitment_count += 1;

        info!(
            commitment_hash = %hex::encode(commitment_hash),
            "Recorded MPC contribution commitment"
        );

        Ok(commitment_hash)
    }

    /// Check if there are pending commitments that haven't been fulfilled
    ///
    /// This is called before ossification to detect if any contributions were dropped.
    /// If there are pending commitments, ossification should be delayed or investigated.
    pub fn has_pending_commitments(&self) -> bool {
        !self.pending_commitments.read().is_empty()
    }

    /// Get the number of pending commitments
    pub fn pending_commitment_count(&self) -> usize {
        self.pending_commitments.read().len()
    }

    /// Get list of pending commitments (for audit)
    pub fn get_pending_commitments(&self) -> Vec<ContributionCommitment> {
        self.pending_commitments.read().values().cloned().collect()
    }

    /// Get list of fulfilled commitment hashes (for audit)
    pub fn get_fulfilled_commitments(&self) -> Vec<[u8; 32]> {
        self.fulfilled_commitments.read().clone()
    }

    /// Create a commitment for this contributor
    ///
    /// Convenience method that creates a properly bound commitment.
    pub fn create_commitment(&self, contributor_id: &str) -> MpcResult<ContributionCommitment> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        ContributionCommitment::new(
            contributor_id,
            state.current_params_hash,
            state.ceremony_id,
        )
    }

    /// Verify all commitments were honored before ossification
    ///
    /// SECURITY: This should be called before finalizing the ceremony to ensure
    /// no contributions were dropped. If this returns an error, the ceremony
    /// should be considered compromised.
    pub fn verify_all_commitments_honored(&self) -> MpcResult<()> {
        let pending = self.pending_commitments.read();
        if !pending.is_empty() {
            let dropped: Vec<String> = pending
                .values()
                .map(|c| c.contributor.clone())
                .collect();
            return Err(MpcError::Internal(format!(
                "SECURITY ALERT: {} contributions were committed but not included: {:?}",
                pending.len(),
                dropped
            )));
        }
        Ok(())
    }

    /// Initialize with genesis parameters
    ///
    /// Called on first network launch to create the initial parameters.
    /// The genesis parameters are created by the network founder.
    pub fn initialize_genesis(&self, genesis_params: Parameters<Bls12>) -> MpcResult<()> {
        let mut state = self.state.write();

        if state.contribution_count > 0 {
            return Err(MpcError::Internal(
                "Cannot initialize genesis - ceremony already started".into(),
            ));
        }

        // Save genesis parameters as v0
        self.files.ensure_dir()?;
        let params_path = self.files.block_params_path(0);
        save_parameters(&params_path, &genesis_params)?;
        update_current_params(&self.files, 0)?;

        // Hash parameters
        let params_hash = hash_parameters(&genesis_params)?;

        // Hot-swap
        let vk = prepare_verifying_key(&genesis_params.vk);
        *self.block_params.write() = Some(Arc::new(genesis_params));
        *self.block_vk.write() = Some(Arc::new(vk));

        // Update state - contribution count stays 0 for genesis
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        state.current_params_hash = params_hash;
        state.updated_at = now;
        // 3.9: Record genesis timestamp for time-based ossification
        state.genesis_timestamp = Some(now);

        info!(
            params_hash = %hex::encode(params_hash),
            genesis_timestamp = now,
            max_duration_days = 30,
            "Initialized MPC ceremony with genesis parameters (30-day ossification timer started)"
        );

        Ok(())
    }

    /// Get the parameters directory path
    pub fn params_dir(&self) -> &PathBuf {
        &self.files.dir
    }

    /// Get the parameter files manager
    pub fn files(&self) -> &ParameterFiles {
        &self.files
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_manager() -> (CeremonyManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let manager = CeremonyManager::new(temp_dir.path().to_path_buf());
        (manager, temp_dir)
    }

    #[test]
    fn test_new_manager_state() {
        let (manager, _temp) = create_test_manager();

        assert_eq!(manager.contribution_count(), 0);
        assert!(!manager.is_ossified());
        assert!(!manager.has_current_params());
    }

    #[test]
    fn test_ossification() {
        let (manager, _temp) = create_test_manager();

        manager.ossify().unwrap();

        assert!(manager.is_ossified());
    }

    #[test]
    fn test_ossified_ceremony_rejects_operations() {
        let (manager, _temp) = create_test_manager();
        manager.ossify().unwrap();

        let result = manager.generate_contribution("node1");
        assert!(matches!(result, Err(MpcError::CeremonyOssified(_))));
    }

    // CRIT-2 FIX: Tests for contribution commitments

    #[test]
    fn test_commitment_tracking() {
        let (manager, _temp) = create_test_manager();

        // Initially no pending commitments
        assert!(!manager.has_pending_commitments());
        assert_eq!(manager.pending_commitment_count(), 0);

        // Create and record a commitment
        // Note: This will fail because ceremony_id is all zeros and params hash is all zeros
        // which matches default state
        let commitment = ContributionCommitment::new("node1", [0u8; 32], [0u8; 32]).unwrap();
        let result = manager.record_commitment(commitment);
        assert!(result.is_ok());

        // Now there should be one pending commitment
        assert!(manager.has_pending_commitments());
        assert_eq!(manager.pending_commitment_count(), 1);
    }

    #[test]
    fn test_commitment_prevents_duplicate() {
        let (manager, _temp) = create_test_manager();

        // Record first commitment
        let commitment = ContributionCommitment::new("node1", [0u8; 32], [0u8; 32]).unwrap();
        let hash = manager.record_commitment(commitment.clone()).unwrap();

        // Try to record same commitment again - should fail
        let result = manager.record_commitment(commitment);
        assert!(matches!(result, Err(MpcError::DuplicateContribution(_))));

        // Should still have only one pending
        assert_eq!(manager.pending_commitment_count(), 1);

        // Use the hash
        let _ = hash;
    }

    #[test]
    fn test_verify_all_commitments_honored_fails_with_pending() {
        let (manager, _temp) = create_test_manager();

        // Record a commitment
        let commitment = ContributionCommitment::new("node1", [0u8; 32], [0u8; 32]).unwrap();
        manager.record_commitment(commitment).unwrap();

        // Verification should fail because commitment is not fulfilled
        let result = manager.verify_all_commitments_honored();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("SECURITY ALERT"),
            "Should report security alert for unfulfilled commitments"
        );
    }

    #[test]
    fn test_verify_all_commitments_honored_passes_when_empty() {
        let (manager, _temp) = create_test_manager();

        // No commitments, so verification should pass
        let result = manager.verify_all_commitments_honored();
        assert!(result.is_ok());
    }

    #[test]
    fn test_ossified_ceremony_rejects_commitments() {
        let (manager, _temp) = create_test_manager();
        manager.ossify().unwrap();

        let commitment = ContributionCommitment::new("node1", [0u8; 32], [0u8; 32]).unwrap();
        let result = manager.record_commitment(commitment);
        assert!(matches!(result, Err(MpcError::CeremonyOssified(_))));
    }
}

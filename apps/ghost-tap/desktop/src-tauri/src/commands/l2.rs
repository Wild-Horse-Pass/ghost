use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ghost_tap_core::l2::prover::{ConsolidationResult, TransferResult, UnshieldResult};
use ghost_tap_core::network::ghost_pay::{
    ConsolidateRequest, GhostPayClient, PayConfig, ShieldRequest, TransferRequest,
    UnshieldRequest,
};
use serde::Serialize;
use tauri::State;

// =============================================================================
// Response types
// =============================================================================

#[derive(Serialize)]
pub struct L2BalanceResponse {
    pub confirmed: u64,
    pub note_count: u32,
}

#[derive(Serialize)]
pub struct L2NoteResponse {
    pub index: u64,
    pub value: u64,
    pub epoch: u64,
    pub spent: bool,
}

#[derive(Serialize)]
pub struct L2SyncStatusResponse {
    pub last_synced_height: u64,
    pub current_epoch: u64,
    pub tree_root: String,
    pub has_params: bool,
}

#[derive(Serialize)]
pub struct L2TransferResultResponse {
    pub status: String,
    pub nullifier: String,
}

// =============================================================================
// Helper — build a GhostPayClient from AppState
// =============================================================================

fn ghost_pay_client(state: &AppState) -> AppResult<GhostPayClient> {
    let config = PayConfig {
        base_url: state
            .ghost_pay_url
            .lock()
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:8800".into()),
        timeout_ms: 30_000,
        api_secret: state.ghost_pay_secret.lock().clone(),
    };
    Ok(GhostPayClient::with_client(config, state.http_client.clone()))
}

// =============================================================================
// Tauri Commands
// =============================================================================

/// Get the L2 confidential balance.
#[tauri::command]
pub fn l2_balance(state: State<'_, AppState>) -> AppResult<L2BalanceResponse> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let mut wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let balance = wallet
        .l2_balance()
        .map_err(|e| AppError::from(e.to_string()))?;
    let count = wallet
        .l2_note_count()
        .map_err(|e| AppError::from(e.to_string()))?;

    Ok(L2BalanceResponse {
        confirmed: balance,
        note_count: count as u32,
    })
}

/// List all owned L2 notes.
#[tauri::command]
pub fn l2_notes(state: State<'_, AppState>) -> AppResult<Vec<L2NoteResponse>> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let mut wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    wallet
        .ensure_note_store()
        .map_err(|e| AppError::from(e.to_string()))?;

    let notes: Vec<L2NoteResponse> = wallet
        .note_store()
        .map(|store| {
            store
                .unspent_notes()
                .iter()
                .map(|n| L2NoteResponse {
                    index: n.index,
                    value: n.value,
                    epoch: n.epoch,
                    spent: n.spent,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(notes)
}

/// Scan for new L2 notes. Returns the count of newly discovered notes.
#[tauri::command]
pub async fn l2_scan(state: State<'_, AppState>) -> AppResult<u32> {
    let client = ghost_pay_client(&state)?;

    // Extract keys (sync block — guards dropped before await)
    let (scan_secret, last_height) = {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let scan_secret = wallet
            .l2_scan_secret()
            .map_err(|e| AppError::from(e.to_string()))?
            .clone();
        let height = wallet
            .tree_sync()
            .map(|ts| ts.last_synced_height())
            .unwrap_or(0);
        (scan_secret, height)
    };
    // guards dropped here

    // Fetch transactions from server (async)
    let txs = client
        .get_l2_transactions(0)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    // Scan transactions (sync, no wallet lock needed)
    let mut scanner =
        ghost_tap_core::l2::NoteScanner::new_from_height(scan_secret, last_height);
    let discovered = scanner.scan_transactions(&txs);
    let count = discovered.len() as u32;
    let last_seen_epoch = scanner.last_seen_epoch();

    // Sync tree and add discovered notes (sync block)
    if !discovered.is_empty() {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let store = wallet
            .note_store_mut()
            .map_err(|e| AppError::from(e.to_string()))?;
        for note in discovered {
            store.add_note(note.note);
        }

        if last_seen_epoch > store.current_epoch() {
            store.handle_epoch_transition(last_seen_epoch);
        }
    }

    Ok(count)
}

/// Get L2 sync status.
#[tauri::command]
pub fn l2_sync_status(state: State<'_, AppState>) -> AppResult<L2SyncStatusResponse> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let (height, root) = wallet
        .tree_sync()
        .map(|ts| {
            let root = ts.root().map(|r| hex::encode(r)).unwrap_or_default();
            (ts.last_synced_height(), root)
        })
        .unwrap_or((0, String::new()));

    let has_params = wallet
        .params_cache()
        .map(|pc| pc.has_cached_params())
        .unwrap_or(false);

    let epoch = wallet
        .note_store()
        .map(|ns| ns.current_epoch())
        .unwrap_or(0);

    Ok(L2SyncStatusResponse {
        last_synced_height: height,
        current_epoch: epoch,
        tree_root: root,
        has_params,
    })
}

/// Submit an L2 transfer.
#[tauri::command]
pub async fn l2_transfer(
    state: State<'_, AppState>,
    amount: u64,
    recipient_pubkey: String,
) -> AppResult<L2TransferResultResponse> {
    let client = ghost_pay_client(&state)?;

    // Parse recipient pubkey (no wallet lock needed)
    let recipient_pk_bytes = hex::decode(&recipient_pubkey)
        .map_err(|e| AppError::from(format!("Invalid recipient pubkey hex: {}", e)))?;
    let recipient_pk = secp256k1::PublicKey::from_slice(&recipient_pk_bytes)
        .map_err(|e| AppError::from(format!("Invalid recipient pubkey: {}", e)))?;

    // Get tree state from server (async, no wallet lock)
    let tree_state = client
        .get_tree_state()
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    // Generate proof (sync block — all wallet access happens here)
    let (result, sender_index): (TransferResult, u64) = {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        // Ensure prover is loaded
        let params_dir = wallet
            .params_cache()
            .map(|pc| pc.cache_dir().clone())
            .ok_or_else(|| AppError::from("L2 params not cached — sync first"))?;
        wallet
            .ensure_l2_prover(&params_dir)
            .map_err(|e| AppError::from(e.to_string()))?;

        // Get owner pubkey (needs &mut self)
        let sender_pubkey = wallet
            .l2_owner_pubkey()
            .map_err(|e| AppError::from(e.to_string()))?;

        // Select note
        let sender_index = {
            let note_store = wallet
                .note_store()
                .ok_or_else(|| AppError::from("Note store not initialized"))?;
            let selection = note_store
                .select_notes_for_transfer(amount)
                .map_err(|e| AppError::from(e.to_string()))?;
            match selection {
                ghost_tap_core::l2::NoteSelection::Direct { note_index } => note_index,
                ghost_tap_core::l2::NoteSelection::NeedsConsolidation { .. } => {
                    return Err("Notes need consolidation first — call l2_consolidate".into());
                }
            }
        };

        // Generate proof
        let note_store = wallet
            .note_store()
            .ok_or_else(|| AppError::from("Note store not initialized"))?;
        let prover = wallet
            .l2_prover()
            .ok_or_else(|| AppError::from("L2 prover not loaded"))?;
        let tree = wallet
            .tree_sync()
            .ok_or_else(|| AppError::from("Tree not synced"))?
            .tree();

        let result = prover
            .create_transfer(
                tree,
                note_store,
                sender_index,
                amount,
                tree_state.current_epoch,
                tree_state.next_index,
                &sender_pubkey,
                &recipient_pk,
            )
            .map_err(|e| AppError::from(e.to_string()))?;

        (result, sender_index)
    };
    // guards dropped here

    // Submit to ghost-pay (async)
    let req = TransferRequest {
        proof_hex: result.proof_hex.clone(),
        commitment_root: result.commitment_root.clone(),
        nullifier: result.nullifier.clone(),
        change_commitment: result.change_commitment.clone(),
        recipient_commitment: result.recipient_commitment.clone(),
        sender_index,
        recipient_index: 0,
        recipient_owner_pubkey: recipient_pubkey,
        epoch: result.epoch,
        encrypted_change: hex::encode(&result.encrypted_change),
        encrypted_recipient: hex::encode(&result.encrypted_recipient),
    };

    let resp = client
        .submit_transfer(&req)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    // Update local state (sync block)
    {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let store = wallet
            .note_store_mut()
            .map_err(|e| AppError::from(e.to_string()))?;
        store.mark_spent(sender_index);
        store.add_note(result.change_note);
    }

    Ok(L2TransferResultResponse {
        status: resp.status,
        nullifier: result.nullifier,
    })
}

/// Consolidate notes (merge up to 4 into 1).
#[tauri::command]
pub async fn l2_consolidate(state: State<'_, AppState>) -> AppResult<String> {
    let client = ghost_pay_client(&state)?;

    // Get tree state (async, no lock)
    let tree_state = client
        .get_tree_state()
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    // Generate proof (sync block)
    let (result, unspent): (ConsolidationResult, Vec<u64>) = {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let params_dir = wallet
            .params_cache()
            .map(|pc| pc.cache_dir().clone())
            .ok_or_else(|| AppError::from("L2 params not cached"))?;
        wallet
            .ensure_l2_prover(&params_dir)
            .map_err(|e| AppError::from(e.to_string()))?;

        // Get owner pubkey (needs &mut self)
        let owner_pubkey = wallet
            .l2_owner_pubkey()
            .map_err(|e| AppError::from(e.to_string()))?;

        // Collect indices
        let mut indices: Vec<u64> = {
            let note_store = wallet
                .note_store()
                .ok_or_else(|| AppError::from("Note store not initialized"))?;
            note_store
                .unspent_notes()
                .iter()
                .map(|n| n.index)
                .collect()
        };
        indices.truncate(4);

        if indices.len() < 2 {
            return Err("Need at least 2 notes to consolidate".into());
        }

        let note_store = wallet
            .note_store()
            .ok_or_else(|| AppError::from("Note store not initialized"))?;
        let prover = wallet
            .l2_prover()
            .ok_or_else(|| AppError::from("L2 prover not loaded"))?;
        let tree = wallet
            .tree_sync()
            .ok_or_else(|| AppError::from("Tree not synced"))?
            .tree();

        let result = prover
            .create_consolidation(
                tree,
                note_store,
                &indices,
                tree_state.current_epoch,
                tree_state.next_index,
                &owner_pubkey,
            )
            .map_err(|e| AppError::from(e.to_string()))?;

        (result, indices)
    };
    // guards dropped here

    // Submit (async)
    let req = ConsolidateRequest {
        proof_hex: result.proof_hex.clone(),
        commitment_root: result.commitment_root.clone(),
        nullifiers: result.nullifiers.clone(),
        output_commitment: result.output_commitment.clone(),
        encrypted_output: hex::encode(&result.encrypted_output),
        epoch: result.epoch,
    };

    let resp = client
        .submit_consolidation(&req)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    // Update local state (sync block)
    {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let store = wallet
            .note_store_mut()
            .map_err(|e| AppError::from(e.to_string()))?;
        for &idx in &unspent {
            store.mark_spent(idx);
        }
        store.add_note(result.output_note);
    }

    Ok(resp.status)
}

/// Unshield (withdraw L2 to L1).
#[tauri::command]
pub async fn l2_unshield(
    state: State<'_, AppState>,
    destination: String,
) -> AppResult<String> {
    let client = ghost_pay_client(&state)?;

    // Get tree state (async, no lock)
    let tree_state = client
        .get_tree_state()
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    // Generate proof (sync block)
    let (result, note_index): (UnshieldResult, u64) = {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let params_dir = wallet
            .params_cache()
            .map(|pc| pc.cache_dir().clone())
            .ok_or_else(|| AppError::from("L2 params not cached"))?;
        wallet
            .ensure_l2_prover(&params_dir)
            .map_err(|e| AppError::from(e.to_string()))?;

        // Find largest unspent note
        let note_index = {
            let note_store = wallet
                .note_store()
                .ok_or_else(|| AppError::from("Note store not initialized"))?;
            note_store
                .unspent_notes()
                .iter()
                .max_by_key(|n| n.value)
                .map(|n| n.index)
                .ok_or_else(|| AppError::from("No unspent L2 notes"))?
        };

        let note_store = wallet
            .note_store()
            .ok_or_else(|| AppError::from("Note store not initialized"))?;
        let prover = wallet
            .l2_prover()
            .ok_or_else(|| AppError::from("L2 prover not loaded"))?;
        let tree = wallet
            .tree_sync()
            .ok_or_else(|| AppError::from("Tree not synced"))?
            .tree();

        let result = prover
            .create_unshield(tree, note_store, note_index, tree_state.current_epoch)
            .map_err(|e| AppError::from(e.to_string()))?;

        (result, note_index)
    };
    // guards dropped here

    // Submit (async)
    let req = UnshieldRequest {
        proof_hex: result.proof_hex,
        commitment_root: result.commitment_root,
        nullifier: result.nullifier,
        withdrawal_amount_sats: result.withdrawal_amount_sats,
        destination_address: destination,
    };

    let resp = client
        .submit_unshield(&req)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    // Update local state (sync block)
    {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let store = wallet
            .note_store_mut()
            .map_err(|e| AppError::from(e.to_string()))?;
        store.mark_spent(note_index);
    }

    Ok(resp.status)
}

/// Shield L1 balance into L2.
#[tauri::command]
pub async fn l2_shield(state: State<'_, AppState>, amount: u64) -> AppResult<String> {
    let client = ghost_pay_client(&state)?;

    // Prepare request (sync block)
    let (req, blinding) = {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let owner_pubkey = wallet
            .l2_owner_pubkey()
            .map_err(|e| AppError::from(e.to_string()))?;

        let mut blinding = [0u8; 32];
        getrandom::getrandom(&mut blinding)
            .map_err(|e| AppError::from(format!("RNG error: {}", e)))?;
        blinding[31] &= 0x3F; // BLS12-381 safe

        let req = ShieldRequest {
            amount_sats: amount,
            blinding_hex: hex::encode(blinding),
            owner_pubkey: hex::encode(owner_pubkey.serialize()),
        };

        (req, blinding)
    };
    // guards dropped here

    // Submit (async)
    let resp = client
        .shield_balance(&req)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    // Add note to local store (sync block)
    if let Some(note_index) = resp.note_index {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let mut wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let store = wallet
            .note_store_mut()
            .map_err(|e| AppError::from(e.to_string()))?;
        store.add_note(ghost_tap_core::l2::OwnedNote {
            index: note_index,
            value: amount,
            blinding,
            spent: false,
            created_height: 0,
            epoch: 0,
        });
    }

    Ok(resp.status)
}

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ghost_tap_core::transaction::{FeePriority, TransactionBuilder, TransactionSigner, UnsignedTransaction};
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct UnsignedTxResponse {
    pub inputs_count: usize,
    pub outputs_count: usize,
    pub fee: u64,
    pub tx_json: String,
}

#[derive(Serialize)]
pub struct BroadcastResponse {
    pub txid: String,
    pub size: usize,
    pub fee: u64,
}

#[tauri::command]
pub fn build_transaction(
    state: State<'_, AppState>,
    to: String,
    amount: u64,
    fee_priority: u8,
) -> AppResult<UnsignedTxResponse> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let mut wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let priority = match fee_priority {
        0 => FeePriority::Low,
        2 => FeePriority::High,
        _ => FeePriority::Medium,
    };

    let change_addr = wallet.new_change_address()?;
    let balance = wallet.balance_details();

    let unsigned = TransactionBuilder::new()
        .add_output(to, amount)
        .fee_priority(priority)
        .change_address(change_addr)
        .build(wallet.get_utxos(), &balance)?;

    let tx_json = serde_json::to_string(&unsigned)
        .map_err(|e| AppError::from(format!("Serialization error: {e}")))?;

    Ok(UnsignedTxResponse {
        inputs_count: unsigned.inputs.len(),
        outputs_count: unsigned.outputs.len(),
        fee: unsigned.fee,
        tx_json,
    })
}

#[tauri::command]
pub async fn sign_and_broadcast(
    state: State<'_, AppState>,
    unsigned_tx_json: String,
) -> AppResult<BroadcastResponse> {
    let unsigned: UnsignedTransaction = serde_json::from_str(&unsigned_tx_json)
        .map_err(|e| AppError::from(format!("Invalid transaction JSON: {e}")))?;

    let signed = {
        let guard = state.wallet.lock();
        let instance = guard.as_ref().ok_or("No wallet loaded")?;
        let wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        let signer = TransactionSigner::new();
        signer.sign(&unsigned, |change, idx| {
            wallet
                .get_private_key(change, idx)
                .map_err(|e| ghost_tap_core::transaction::TransactionError::SigningFailed(e.to_string()))
        })?
    };

    let txid = state.connection.send_payment(&signed.raw_tx).await?;

    Ok(BroadcastResponse {
        txid,
        size: signed.size,
        fee: signed.fee,
    })
}

#[tauri::command]
pub async fn estimate_fee(
    state: State<'_, AppState>,
    conf_target: u32,
) -> AppResult<Option<u64>> {
    let fee = state.connection.estimate_fee(conf_target).await?;
    Ok(fee)
}

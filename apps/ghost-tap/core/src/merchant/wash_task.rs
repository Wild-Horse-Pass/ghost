//! Background processor for driving Wraith wash state machine.
//!
//! Spawns a tokio task that polls the WraithWasher queue at a fixed
//! interval and drives each ready request through the wash cycle:
//!   1. Get stealth address
//!   2. Send public -> private (enter Wraith)
//!   3. Get fresh public address
//!   4. Send private -> public (exit Wraith)
//!   5. Mark completed

use crate::merchant::wraith::WraithWasher;
use crate::network::connection::ConnectionManager;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

/// How often the processor checks for ready items.
const POLL_INTERVAL_SECS: u64 = 30;

/// Maximum retry attempts before giving up on a wash request.
const MAX_RETRIES: u32 = 5;

/// How long an InProgress item can be stuck before we attempt recovery (1 hour).
const STUCK_TIMEOUT_SECS: u64 = 3600;

/// Minimum amount (sats) below which a wash exit leg is not viable after fees.
const DUST_THRESHOLD_SATS: u64 = 546;

/// Handle for controlling the background wash processor.
pub struct WashProcessorHandle {
    stop_tx: watch::Sender<bool>,
}

impl WashProcessorHandle {
    /// Signal the background task to stop.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }
}

/// Spawn the background wash processor.
///
/// Returns a handle that can be used to stop the task.
pub fn spawn_wash_processor(
    washer: Arc<Mutex<WraithWasher>>,
    connection: Arc<ConnectionManager>,
) -> WashProcessorHandle {
    let (stop_tx, stop_rx) = watch::channel(false);

    tokio::spawn(wash_processor_loop(washer, connection, stop_rx));

    WashProcessorHandle { stop_tx }
}

async fn wash_processor_loop(
    washer: Arc<Mutex<WraithWasher>>,
    connection: Arc<ConnectionManager>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    tracing::info!("Wash processor stopping");
                    return;
                }
            }
        }

        // Prune completed/failed items older than 24 hours
        let now = now_unix();
        if let Ok(mut w) = washer.lock() {
            w.prune(now, 86_400);
        }

        // Get ready items (respects concurrency limit)
        type TxAmountList = Vec<(String, u64)>;
        let (ready, stuck): (TxAmountList, TxAmountList) = match washer.lock() {
            Ok(w) => {
                let ready = w
                    .get_ready()
                    .iter()
                    .filter(|r| r.retry_count < MAX_RETRIES)
                    .map(|r| (r.txid.clone(), r.amount))
                    .collect();
                // H-5: Find InProgress items stuck longer than STUCK_TIMEOUT_SECS
                let stuck = w
                    .get_queue()
                    .iter()
                    .filter(|r| {
                        r.status == crate::merchant::wraith::WashStatus::InProgress
                            && now.saturating_sub(r.updated_at) > STUCK_TIMEOUT_SECS
                            && r.retry_count < MAX_RETRIES
                    })
                    .map(|r| (r.txid.clone(), r.amount))
                    .collect();
                (ready, stuck)
            }
            Err(_) => continue,
        };

        if ready.is_empty() && stuck.is_empty() {
            continue;
        }

        for (txid, amount) in ready {
            process_one_wash(&washer, &connection, &txid, amount).await;
        }

        // H-5: Recover stuck InProgress items
        for (txid, amount) in stuck {
            recover_stuck_wash(&washer, &connection, &txid, amount).await;
        }
    }
}

async fn process_one_wash(
    washer: &Arc<Mutex<WraithWasher>>,
    connection: &Arc<ConnectionManager>,
    txid: &str,
    amount: u64,
) {
    // Step 1: Get a stealth address
    let stealth_addr = match connection.get_stealth_address().await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::warn!("Wash {txid}: failed to get stealth address: {e}");
            if let Ok(mut w) = washer.lock() {
                w.mark_failed(txid, now_unix());
            }
            return;
        }
    };

    // Step 2: Send public -> private
    let wraith_in_txid = match connection.send_public_to_private(&stealth_addr, amount).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("Wash {txid}: public->private failed: {e}");
            if let Ok(mut w) = washer.lock() {
                w.mark_failed(txid, now_unix());
            }
            return;
        }
    };

    // Mark in-progress (funds are now in private pool)
    if let Ok(mut w) = washer.lock() {
        w.mark_in_progress(txid, &wraith_in_txid, now_unix());
    }

    // H-6: Estimate fees for exit leg
    let estimated_fee = connection.estimate_fee(6).await
        .ok()
        .flatten()
        .unwrap_or(1000); // conservative 1000 sat/kB fallback
    // Account for both legs of the wash (in + out)
    let exit_amount = amount.saturating_sub(estimated_fee * 2);
    if exit_amount < DUST_THRESHOLD_SATS {
        tracing::warn!("Wash {txid}: amount after fees ({exit_amount}) below dust threshold, marking failed");
        if let Ok(mut w) = washer.lock() {
            w.mark_failed(txid, now_unix());
        }
        return;
    }

    // Step 3: Get a fresh public address for the exit leg
    let exit_addr = match connection.get_new_address().await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::warn!("Wash {txid}: failed to get exit address: {e}");
            // Funds are in private — leave as InProgress for later retry
            return;
        }
    };

    // Step 4: Send private -> public (fee-adjusted amount)
    let wraith_out_txid = match connection.send_private_to_public(&exit_addr, exit_amount).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("Wash {txid}: private->public failed: {e}");
            // Funds are in private — leave as InProgress for later retry
            return;
        }
    };

    // Step 5: Mark completed
    if let Ok(mut w) = washer.lock() {
        w.mark_completed(txid, &wraith_out_txid, now_unix());
    }

    tracing::info!("Wash {txid}: completed (in={wraith_in_txid}, out={wraith_out_txid})");
}

/// H-5: Attempt to recover a stuck InProgress wash (retry the exit leg).
async fn recover_stuck_wash(
    washer: &Arc<Mutex<WraithWasher>>,
    connection: &Arc<ConnectionManager>,
    txid: &str,
    amount: u64,
) {
    tracing::info!("Wash {txid}: recovering stuck InProgress item");

    // Estimate fees for exit leg
    let estimated_fee = connection.estimate_fee(6).await
        .ok()
        .flatten()
        .unwrap_or(1000);
    let exit_amount = amount.saturating_sub(estimated_fee * 2);
    if exit_amount < DUST_THRESHOLD_SATS {
        tracing::warn!("Wash {txid}: recovery amount after fees ({exit_amount}) below dust, marking failed");
        if let Ok(mut w) = washer.lock() {
            w.mark_failed(txid, now_unix());
        }
        return;
    }

    let exit_addr = match connection.get_new_address().await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::warn!("Wash {txid}: recovery failed to get exit address: {e}");
            if let Ok(mut w) = washer.lock() {
                w.mark_failed(txid, now_unix());
            }
            return;
        }
    };

    match connection.send_private_to_public(&exit_addr, exit_amount).await {
        Ok(wraith_out_txid) => {
            if let Ok(mut w) = washer.lock() {
                w.mark_completed(txid, &wraith_out_txid, now_unix());
            }
            tracing::info!("Wash {txid}: recovery completed (out={wraith_out_txid})");
        }
        Err(e) => {
            tracing::warn!("Wash {txid}: recovery private->public failed: {e}");
            if let Ok(mut w) = washer.lock() {
                w.mark_failed(txid, now_unix());
            }
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_unix_is_reasonable() {
        let now = now_unix();
        // Should be after 2024-01-01 and before 2100-01-01
        assert!(now > 1_704_067_200);
        assert!(now < 4_102_444_800);
    }

    #[test]
    fn test_wash_processor_handle_stop() {
        let (stop_tx, _stop_rx) = watch::channel(false);
        let handle = WashProcessorHandle { stop_tx };
        // Should not panic
        handle.stop();
    }
}

//! Pluggable transaction-broadcast backend.
//!
//! Same shape as the `BondLedger` trait elsewhere — production wires a
//! real `bitcoind` RPC client (phase D); tests inject `StubBroadcaster`
//! which just records the call. The coordinator's broadcast path is
//! deliberately decoupled from the network layer so the tx-merge logic
//! can be unit-tested without a full node, and so a malfunctioning
//! broadcaster doesn't poison the round-state machine.

use std::sync::{Arc, Mutex};

use bitcoin::Transaction;

/// Errors any [`Broadcaster`] implementation may surface to the
/// coordinator. The state machine in `/witness` decides whether to
/// retry or fail the round based on which variant comes back.
#[derive(Debug, thiserror::Error)]
pub enum BroadcastError {
    /// Broadcaster backend isn't configured. Until phase D wires the
    /// bitcoind RPC client, the production `new()` constructor leaves
    /// this as `None` and `/witness` returns 503 on the final submit.
    #[error("broadcast backend not configured")]
    NotConfigured,
    /// The backend rejected the transaction (e.g. bitcoind returned
    /// `bad-txns-inputs-missingorspent`). The round can't recover —
    /// transition to Failed.
    #[error("backend rejected transaction: {0}")]
    Rejected(String),
    /// The backend was unreachable (network error, RPC timeout). The
    /// round may be retryable; for v1 we fail-fast, future iterations
    /// can add retry logic.
    #[error("backend unreachable: {0}")]
    Unreachable(String),
}

/// Trait the coordinator calls once all witnesses are merged. Send +
/// Sync so the state can hold an `Arc<dyn Broadcaster>`. The
/// implementation is responsible for any network I/O — synchronous
/// signature because broadcast is rare (once per round) and the
/// coordinator's HTTP handler is happy to block briefly on it.
pub trait Broadcaster: Send + Sync {
    /// Submit `tx` to the network. Returns the txid the network sees,
    /// which the coordinator cross-checks against the txid it
    /// computed from the assembled round (if they don't match, the
    /// backend is buggy or compromised — surface as `Rejected`).
    fn broadcast(&self, tx: &Transaction) -> Result<bitcoin::Txid, BroadcastError>;
}

/// Test broadcaster — records every call into a shared `Vec` so tests
/// can assert "yes, the round transaction did get broadcast" without
/// running a real bitcoind. Returns the tx's own computed txid as the
/// "network" txid (matches what an honest backend would do).
#[derive(Debug, Default, Clone)]
pub struct StubBroadcaster {
    pub broadcasted: Arc<Mutex<Vec<Transaction>>>,
}

impl StubBroadcaster {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self) -> usize {
        self.broadcasted.lock().expect("stub poisoned").len()
    }

    pub fn last(&self) -> Option<Transaction> {
        self.broadcasted
            .lock()
            .expect("stub poisoned")
            .last()
            .cloned()
    }
}

impl Broadcaster for StubBroadcaster {
    fn broadcast(&self, tx: &Transaction) -> Result<bitcoin::Txid, BroadcastError> {
        let txid = tx.compute_txid();
        self.broadcasted
            .lock()
            .expect("stub poisoned")
            .push(tx.clone());
        Ok(txid)
    }
}

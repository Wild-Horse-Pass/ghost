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
//| FILE: proxy/pay_node.rs                                                                                              |
//|======================================================================================================================|

//! Proxy client for ghost-pay-node

use ghost_gsp_proto::{GhostLockInfo, TransactionInfo, UtxoInfo};

use crate::error::{GspError, GspResult};

/// Wallet balance
pub struct WalletBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub locked: u64,
}

/// Proxy to ghost-pay-node REST API
pub struct PayNodeProxy {
    base_url: String,
}

impl PayNodeProxy {
    /// Create a new pay node proxy
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Health check - returns true if pay node is responding
    pub async fn health_check(&self) -> GspResult<bool> {
        let url = format!("{}/health", self.base_url);

        let response = reqwest::get(&url)
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        Ok(response.status().is_success())
    }

    /// Get balance for a wallet (by ghost_id)
    pub async fn get_balance(&self, ghost_id: &str) -> GspResult<WalletBalance> {
        // In production, this would call the pay node API
        // For now, return mock data
        let _ = ghost_id;

        // TODO: Implement actual API call
        // let url = format!("{}/api/v1/balance?ghost_id={}", self.base_url, ghost_id);
        // let response = reqwest::get(&url).await?;

        Ok(WalletBalance {
            confirmed: 0,
            unconfirmed: 0,
            locked: 0,
        })
    }

    /// Get UTXOs for a wallet
    pub async fn get_utxos(
        &self,
        ghost_id: &str,
        min_confirmations: u32,
    ) -> GspResult<Vec<UtxoInfo>> {
        let _ = (ghost_id, min_confirmations);

        // TODO: Implement actual API call
        Ok(vec![])
    }

    /// Get Ghost Locks for a wallet
    pub async fn get_ghost_locks(&self, ghost_id: &str) -> GspResult<Vec<GhostLockInfo>> {
        let _ = ghost_id;

        // TODO: Implement actual API call
        Ok(vec![])
    }

    /// Get transaction history
    pub async fn get_transactions(
        &self,
        ghost_id: &str,
        limit: u32,
        offset: u32,
    ) -> GspResult<(Vec<TransactionInfo>, u32)> {
        let _ = (ghost_id, limit, offset);

        // TODO: Implement actual API call
        Ok((vec![], 0))
    }

    /// Prepare a payment
    pub async fn prepare_payment(
        &self,
        ghost_id: &str,
        recipient: &str,
        amount_sats: u64,
    ) -> GspResult<serde_json::Value> {
        let _ = (ghost_id, recipient, amount_sats);

        // TODO: Implement actual API call
        Err(GspError::Internal("Not implemented".to_string()))
    }

    /// Submit a signed payment
    pub async fn submit_payment(
        &self,
        payment_id: &str,
        signature: &str,
        public_key: &str,
    ) -> GspResult<serde_json::Value> {
        let _ = (payment_id, signature, public_key);

        // TODO: Implement actual API call
        Err(GspError::Internal("Not implemented".to_string()))
    }

    /// Create a ghost lock
    pub async fn create_lock(
        &self,
        ghost_id: &str,
        amount_sats: u64,
        timelock_tier: Option<&str>,
    ) -> GspResult<GhostLockInfo> {
        let _ = (ghost_id, amount_sats, timelock_tier);

        // TODO: Implement actual API call
        Err(GspError::Internal("Not implemented".to_string()))
    }

    /// Request a jump for a lock
    pub async fn request_jump(
        &self,
        lock_id: &str,
        target_address: &str,
        priority: &str,
    ) -> GspResult<serde_json::Value> {
        let _ = (lock_id, target_address, priority);

        // TODO: Implement actual API call
        Err(GspError::Internal("Not implemented".to_string()))
    }

    /// Get payment status
    pub async fn get_payment_status(&self, payment_id: &str) -> GspResult<serde_json::Value> {
        let _ = payment_id;

        // TODO: Implement actual API call
        Err(GspError::Internal("Not implemented".to_string()))
    }

    /// Cancel a pending payment
    pub async fn cancel_payment(&self, payment_id: &str) -> GspResult<bool> {
        let _ = payment_id;

        // TODO: Implement actual API call
        Err(GspError::Internal("Not implemented".to_string()))
    }

    /// Confirm lock funding (after funding tx is broadcast)
    pub async fn confirm_lock_funding(
        &self,
        lock_id: &str,
        funding_txid: &str,
        funding_vout: u32,
    ) -> GspResult<serde_json::Value> {
        let _ = (lock_id, funding_txid, funding_vout);

        // TODO: Implement actual API call
        Err(GspError::Internal("Not implemented".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_creation() {
        let proxy = PayNodeProxy::new("http://localhost:8800");
        assert_eq!(proxy.base_url, "http://localhost:8800");

        // Should strip trailing slash
        let proxy2 = PayNodeProxy::new("http://localhost:8800/");
        assert_eq!(proxy2.base_url, "http://localhost:8800");
    }
}

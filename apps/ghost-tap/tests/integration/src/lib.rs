//! Integration tests for GhostTap

#[cfg(test)]
mod wallet_tests {
    use ghost_tap_core::wallet::{validate_mnemonic, WordCount, Wallet};
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn test_full_wallet_lifecycle() {
        // Generate wallet
        let (wallet, mnemonic) = Wallet::generate(WordCount::Words12).unwrap();

        // Validate mnemonic
        assert!(validate_mnemonic(mnemonic.expose_secret()));

        // Check initial state
        assert_eq!(wallet.balance(), 0);
        assert!(!wallet.is_locked());
    }

    #[test]
    fn test_wallet_recovery() {
        // Generate a wallet
        let (_, mnemonic) = Wallet::generate(WordCount::Words12).unwrap();

        // Recover from mnemonic
        let recovered = Wallet::from_mnemonic(&mnemonic, None).unwrap();

        // Should have same initial state
        assert_eq!(recovered.balance(), 0);
    }

    #[test]
    fn test_invalid_mnemonic_rejected() {
        let invalid = SecretString::new("invalid mnemonic phrase here".into());
        let result = Wallet::from_mnemonic(&invalid, None);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod crypto_tests {
    use ghost_tap_core::crypto::{encrypt_aes_gcm, decrypt_aes_gcm, random_bytes};

    #[test]
    fn test_encryption_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"Ghost Pay secret data";

        let ciphertext = encrypt_aes_gcm(plaintext, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&ciphertext, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let plaintext = b"secret";

        let ciphertext = encrypt_aes_gcm(plaintext, &key1).unwrap();
        let result = decrypt_aes_gcm(&ciphertext, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_random_bytes_unique() {
        let a = random_bytes(32).unwrap();
        let b = random_bytes(32).unwrap();
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod transaction_tests {
    use ghost_tap_core::wallet::{Utxo, UtxoSet};
    use ghost_tap_core::transaction::{TransactionBuilder, FeePriority};

    #[test]
    fn test_transaction_building() {
        let mut utxo_set = UtxoSet::new();
        utxo_set.add(Utxo {
            txid: "abc123".into(),
            vout: 0,
            amount: 100_000,
            confirmations: 6,
            address: "ghost1abc".into(),
            address_index: 0,
            change: 0,
        });

        let balance = utxo_set.balance();

        let result = TransactionBuilder::new()
            .add_output("ghost1recipient".into(), 50_000)
            .fee_priority(FeePriority::Medium)
            .change_address("ghost1change".into())
            .build(utxo_set.all(), &balance);

        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert!(tx.outputs.len() >= 1);
    }
}

#[cfg(test)]
mod network_tests {
    use ghost_tap_core::network::{NodeConfig, NodeClient};

    #[tokio::test]
    async fn test_node_client_creation() {
        let config = NodeConfig::default();
        let client = NodeClient::new(config);
        assert!(client.is_ok());
    }

    // Note: Live network tests would go here with a test node
}

#[cfg(test)]
mod connection_tests {
    use ghost_tap_core::network::connection::{ConnectionManager, ConnectionMode};
    use ghost_tap_core::network::NodeConfig;

    #[test]
    fn test_connection_mode_switching() {
        let cm = ConnectionManager::new();
        assert_eq!(cm.mode(), ConnectionMode::DirectRpc);

        cm.set_mode(ConnectionMode::Gsp);
        assert_eq!(cm.mode(), ConnectionMode::Gsp);

        cm.set_mode(ConnectionMode::DirectRpc);
        assert_eq!(cm.mode(), ConnectionMode::DirectRpc);
    }

    #[test]
    fn test_rpc_config_update() {
        let cm = ConnectionManager::new();
        let config = NodeConfig::testnet().with_auth("user", "pass");
        cm.set_rpc_config(config);
        // Config accepted without panic; no live node so still disconnected
        assert!(!cm.is_connected());
    }

    #[test]
    fn test_connection_not_connected_by_default() {
        let cm = ConnectionManager::new();
        assert!(!cm.is_connected());
    }
}

#[cfg(test)]
mod invoice_tests {
    use ghost_tap_core::merchant::invoice::{Invoice, InvoiceStatus};
    use ghost_tap_core::merchant::receipt::LineItem;
    use ghost_tap_core::storage::WalletStorage;

    #[test]
    fn test_invoice_creation_and_fields() {
        let inv = Invoice::new("INV-001", "Ghost Cafe", "123 Main St", 500_000, "ghost1abc", 1_700_000_000);
        assert_eq!(inv.invoice_id, "INV-001");
        assert_eq!(inv.business_name, "Ghost Cafe");
        assert_eq!(inv.amount, 500_000);
        assert_eq!(inv.ghost_address, "ghost1abc");
        assert_eq!(inv.status, InvoiceStatus::Draft);
        assert!(inv.payments.is_empty());
        assert!(inv.line_items.is_empty());
        assert!(inv.memo.is_none());
    }

    #[test]
    fn test_invoice_with_line_items() {
        let mut inv = Invoice::new("INV-002", "Ghost Cafe", "123 Main St", 300_000, "ghost1abc", 1_700_000_000)
            .with_memo("Thank you for your purchase");

        inv.add_item(LineItem::new("Espresso", 150_000));
        inv.add_item(LineItem::new("Croissant", 150_000));

        assert_eq!(inv.line_items.len(), 2);
        assert_eq!(inv.line_items[0].description, "Espresso");
        assert_eq!(inv.line_items[1].amount, 150_000);
        assert_eq!(inv.memo.as_deref(), Some("Thank you for your purchase"));
    }

    #[test]
    fn test_invoice_payment_tracking() {
        let mut inv = Invoice::new("INV-003", "Biz", "Addr", 100_000, "ghost1x", 0);
        assert_eq!(inv.amount_remaining(), 100_000);
        assert!(!inv.is_fully_paid());

        inv.add_payment("tx_pay1", 60_000, 1000);
        assert_eq!(inv.amount_paid(), 60_000);
        assert_eq!(inv.amount_remaining(), 40_000);
        assert!(!inv.is_fully_paid());
        assert_eq!(inv.status, InvoiceStatus::Draft); // not yet fully paid

        inv.add_payment("tx_pay2", 40_000, 2000);
        assert_eq!(inv.amount_paid(), 100_000);
        assert_eq!(inv.amount_remaining(), 0);
        assert!(inv.is_fully_paid());
        assert_eq!(inv.status, InvoiceStatus::Paid); // auto-transitioned
    }

    #[test]
    fn test_invoice_partial_payment() {
        let mut inv = Invoice::new("INV-004", "Biz", "Addr", 200_000, "ghost1x", 0);
        inv.add_payment("tx_partial", 50_000, 1000);

        assert_eq!(inv.amount_paid(), 50_000);
        assert_eq!(inv.amount_remaining(), 150_000);
        assert!(!inv.is_fully_paid());
        assert_eq!(inv.status, InvoiceStatus::Draft);
    }

    #[test]
    fn test_invoice_payment_uri_generation() {
        let inv = Invoice::new("INV-005", "Ghost Cafe", "Addr", 100_000, "ghost1recipient", 0);
        let uri = inv.to_payment_uri();
        assert!(uri.contains("ghost1recipient"));
        assert!(uri.contains("100000"));
    }

    #[test]
    fn test_invoice_persistence_roundtrip() {
        let key = [42u8; 32];
        let storage = WalletStorage::open(":memory:", &key).unwrap();

        let mut inv = Invoice::new("INV-006", "Ghost Cafe", "123 Main St", 750_000, "ghost1abc", 1_700_000_000)
            .with_memo("Roundtrip test");
        inv.add_item(LineItem::new("Widget", 750_000));
        inv.add_payment("tx_rt", 750_000, 5000);

        let json = serde_json::to_vec(&inv).unwrap();
        storage.set("invoice:INV-006", &json).unwrap();

        let loaded_json = storage.get("invoice:INV-006").unwrap();
        let loaded: Invoice = serde_json::from_slice(&loaded_json).unwrap();

        assert_eq!(loaded.invoice_id, "INV-006");
        assert_eq!(loaded.business_name, "Ghost Cafe");
        assert_eq!(loaded.amount, 750_000);
        assert_eq!(loaded.memo.as_deref(), Some("Roundtrip test"));
        assert_eq!(loaded.line_items.len(), 1);
        assert_eq!(loaded.payments.len(), 1);
        assert_eq!(loaded.status, InvoiceStatus::Paid);
    }

    #[test]
    fn test_invoice_list_and_delete() {
        let key = [42u8; 32];
        let storage = WalletStorage::open(":memory:", &key).unwrap();

        for i in 1..=3 {
            let inv = Invoice::new(format!("INV-{i}"), "Biz", "Addr", 1000 * i as u64, "ghost1x", 0);
            let json = serde_json::to_vec(&inv).unwrap();
            storage.set(&format!("invoice:INV-{i}"), &json).unwrap();
        }

        let keys = storage.list_keys("invoice:").unwrap();
        assert_eq!(keys.len(), 3);

        storage.delete("invoice:INV-2").unwrap();

        let keys = storage.list_keys("invoice:").unwrap();
        assert_eq!(keys.len(), 2);
        assert!(!keys.contains(&"invoice:INV-2".to_string()));
    }
}

#[cfg(test)]
mod wraith_tests {
    use ghost_tap_core::merchant::wraith::{WraithWasher, WashStatus};
    use ghost_tap_core::merchant::wash_task::spawn_wash_processor;
    use ghost_tap_core::network::connection::ConnectionManager;
    use ghost_tap_core::storage::WalletStorage;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_wash_queue_lifecycle() {
        let mut washer = WraithWasher::new();
        let req = washer.wash_payment("tx_a", 50_000, 100);
        assert_eq!(req.status, WashStatus::Queued);
        assert_eq!(req.amount, 50_000);

        assert!(washer.mark_in_progress("tx_a", "wraith_in_1", 200));
        assert_eq!(washer.get_queue()[0].status, WashStatus::InProgress);

        assert!(washer.mark_completed("tx_a", "wraith_out_1", 300));
        assert_eq!(washer.get_queue()[0].status, WashStatus::Completed);
        assert_eq!(washer.get_queue()[0].wraith_out_txid.as_deref(), Some("wraith_out_1"));
    }

    #[test]
    fn test_wash_failure_and_retry() {
        let mut washer = WraithWasher::new();
        washer.wash_payment("tx_b", 30_000, 100);

        assert!(washer.mark_failed("tx_b", 200));
        assert_eq!(washer.get_queue()[0].status, WashStatus::Failed);
        assert_eq!(washer.get_queue()[0].retry_count, 1);

        assert!(washer.retry_failed("tx_b", 300));
        assert_eq!(washer.get_queue()[0].status, WashStatus::Queued);
        // retry_count stays at 1 (mark_failed increments, retry_failed does not)
        assert_eq!(washer.get_queue()[0].retry_count, 1);
    }

    #[test]
    fn test_wash_concurrency_limit() {
        let mut washer = WraithWasher::with_max_concurrent(2);
        for i in 0..5 {
            washer.wash_payment(format!("tx_{i}"), 10_000, 100);
        }
        // All 5 are queued, none in progress → get_ready returns up to 2
        let ready = washer.get_ready();
        assert_eq!(ready.len(), 2);

        // Mark those 2 in progress
        washer.mark_in_progress("tx_0", "w_in_0", 200);
        washer.mark_in_progress("tx_1", "w_in_1", 200);

        // Now at capacity → get_ready returns 0
        let ready = washer.get_ready();
        assert_eq!(ready.len(), 0);

        // Complete one → frees a slot
        washer.mark_completed("tx_0", "w_out_0", 300);
        let ready = washer.get_ready();
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn test_wash_stats_accuracy() {
        let mut washer = WraithWasher::new();
        washer.wash_payment("tx_q1", 10_000, 100);
        washer.wash_payment("tx_q2", 20_000, 100);
        washer.wash_payment("tx_ip", 30_000, 100);
        washer.wash_payment("tx_c", 40_000, 100);
        washer.wash_payment("tx_f", 50_000, 100);

        washer.mark_in_progress("tx_ip", "w_in", 200);
        washer.mark_in_progress("tx_c", "w_in2", 200);
        washer.mark_completed("tx_c", "w_out", 300);
        washer.mark_failed("tx_f", 300);

        let stats = washer.stats();
        assert_eq!(stats.queued, 2);
        assert_eq!(stats.queued_amount, 30_000);
        assert_eq!(stats.in_progress, 1);
        assert_eq!(stats.in_progress_amount, 30_000);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.completed_amount, 40_000);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.failed_amount, 50_000);
        assert_eq!(stats.total_count(), 5);
    }

    #[test]
    fn test_wash_persistence_roundtrip() {
        let key = [99u8; 32];
        let storage = Arc::new(Mutex::new(
            WalletStorage::open(":memory:", &key).unwrap(),
        ));

        // Create washer with storage, queue items
        {
            let mut washer = WraithWasher::with_storage(Arc::clone(&storage));
            washer.wash_payment("tx_p1", 100_000, 100);
            washer.wash_payment("tx_p2", 200_000, 200);
            washer.mark_in_progress("tx_p1", "w_in", 300);
        }

        // New washer loading from same storage
        let washer2 = WraithWasher::with_storage(Arc::clone(&storage));
        let queue = washer2.get_queue();
        assert_eq!(queue.len(), 2);

        let p1 = queue.iter().find(|r| r.txid == "tx_p1").unwrap();
        assert_eq!(p1.status, WashStatus::InProgress);
        assert_eq!(p1.wraith_in_txid.as_deref(), Some("w_in"));

        let p2 = queue.iter().find(|r| r.txid == "tx_p2").unwrap();
        assert_eq!(p2.status, WashStatus::Queued);
        assert_eq!(p2.amount, 200_000);
    }

    #[test]
    fn test_wash_prune() {
        let mut washer = WraithWasher::new();
        washer.wash_payment("tx_keep", 10_000, 100);
        washer.wash_payment("tx_old_done", 20_000, 100);
        washer.wash_payment("tx_old_fail", 30_000, 100);

        washer.mark_in_progress("tx_old_done", "w_in", 200);
        washer.mark_completed("tx_old_done", "w_out", 200);
        washer.mark_failed("tx_old_fail", 200);

        // Prune with max_age=0 at now=200 → all completed/failed removed
        washer.prune(200, 0);

        assert_eq!(washer.get_queue().len(), 1);
        assert_eq!(washer.get_queue()[0].txid, "tx_keep");
    }

    #[tokio::test]
    async fn test_wash_processor_start_stop() {
        let washer = Arc::new(Mutex::new(WraithWasher::new()));
        let connection = Arc::new(ConnectionManager::new());

        let handle = spawn_wash_processor(Arc::clone(&washer), connection);
        handle.stop();
        // Give the task a moment to exit cleanly
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // No panic = clean shutdown
    }
}

#[cfg(test)]
mod merchant_export_tests {
    use ghost_tap_core::merchant::export::TransactionExporter;
    use ghost_tap_core::merchant::receipt::{Receipt, LineItem};
    use ghost_tap_core::wallet::{HistoryEntry, TxDirection, TxStatus};

    fn make_entry(txid: &str, dir: TxDirection, amount: u64, fee: Option<u64>, ts: u64) -> HistoryEntry {
        HistoryEntry {
            txid: txid.to_string(),
            direction: dir,
            amount,
            fee,
            address: format!("ghost1_{txid}"),
            status: TxStatus::Confirmed(6),
            timestamp: ts,
            memo: None,
        }
    }

    #[test]
    fn test_csv_export_with_history() {
        let entries = vec![
            make_entry("tx1", TxDirection::Incoming, 100_000, None, 1000),
            make_entry("tx2", TxDirection::Outgoing, 50_000, Some(500), 2000),
        ];

        let csv = TransactionExporter::to_csv(&entries, 0, 5000);
        assert!(csv.starts_with("Date,TxID,Direction,Amount,Fee,Address,Status,Memo\n"));
        assert!(csv.contains("tx1"));
        assert!(csv.contains("tx2"));
        assert!(csv.contains("Received"));
        assert!(csv.contains("Sent"));
        // Check amounts formatted as GHOST
        assert!(csv.contains("0.00100000")); // 100_000 sats
        assert!(csv.contains("0.00050000")); // 50_000 sats
    }

    #[test]
    fn test_csv_export_date_filtering() {
        let entries = vec![
            make_entry("tx_100", TxDirection::Incoming, 10_000, None, 100),
            make_entry("tx_200", TxDirection::Incoming, 20_000, None, 200),
            make_entry("tx_300", TxDirection::Incoming, 30_000, None, 300),
        ];

        let csv = TransactionExporter::to_csv(&entries, 150, 250);
        assert!(csv.contains("tx_200"));
        assert!(!csv.contains("tx_100"));
        assert!(!csv.contains("tx_300"));
    }

    #[test]
    fn test_html_report_generation() {
        let entries = vec![
            make_entry("tx_h1", TxDirection::Incoming, 500_000, None, 1000),
            make_entry("tx_h2", TxDirection::Outgoing, 200_000, Some(1000), 2000),
        ];

        let html = TransactionExporter::to_html_report(&entries, 0, 5000, "Ghost Emporium");
        assert!(html.contains("Ghost Emporium"));
        assert!(html.contains("tx_h1"));
        assert!(html.contains("tx_h2"));
        assert!(html.contains("<table>"));
        assert!(html.contains("Transactions"));
        assert!(html.contains("Total Received"));
    }

    #[test]
    fn test_receipt_generation() {
        let mut receipt = Receipt::new("REC-001", "Ghost Cafe", "123 Main St", 250_000, "tx_receipt_1", 1_700_000_000);
        receipt.add_item(LineItem::new("Latte", 150_000));
        receipt.add_item(LineItem::new("Muffin", 100_000));

        let html = receipt.to_html();
        assert!(html.contains("REC-001"));
        assert!(html.contains("Latte"));
        assert!(html.contains("Muffin"));
        assert!(html.contains("tx_receipt_1"));
    }

    #[test]
    fn test_receipt_with_memo() {
        let receipt = Receipt::new("REC-002", "Ghost Cafe", "Addr", 100_000, "tx_r2", 0)
            .with_memo("Thanks for visiting!");

        let html = receipt.to_html();
        assert!(html.contains("Thanks for visiting!"));
    }
}

#[cfg(test)]
mod e2e_tests {
    use ghost_tap_core::wallet::{Wallet, WordCount, Utxo, HistoryEntry, TxDirection, TxStatus};
    use ghost_tap_core::transaction::{TransactionBuilder, FeePriority};
    use ghost_tap_core::merchant::invoice::Invoice;
    use ghost_tap_core::merchant::receipt::{Receipt, LineItem};
    use ghost_tap_core::merchant::export::TransactionExporter;
    use ghost_tap_core::merchant::wraith::WraithWasher;
    use ghost_tap_core::payment::qr::PaymentRequest;
    use ghost_tap_core::storage::WalletStorage;

    fn test_utxo(txid: &str, amount: u64) -> Utxo {
        Utxo {
            txid: txid.into(),
            vout: 0,
            amount,
            confirmations: 6,
            address: "ghost1test".into(),
            address_index: 0,
            change: 0,
        }
    }

    #[test]
    fn test_wallet_to_transaction_flow() {
        let (mut wallet, _mnemonic) = Wallet::generate(WordCount::Words12).unwrap();

        wallet.add_utxo(test_utxo("utxo_e2e_1", 200_000));
        assert_eq!(wallet.balance(), 200_000);

        let result = TransactionBuilder::new()
            .add_output("ghost1dest".into(), 80_000)
            .fee_priority(FeePriority::Medium)
            .change_address("ghost1change".into())
            .build(wallet.utxo_set().all(), &wallet.balance_details());

        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert!(tx.outputs.iter().any(|o| o.address == "ghost1dest" && o.amount == 80_000));
        assert!(tx.fee > 0);

        wallet.add_history(HistoryEntry {
            txid: "tx_sent_1".into(),
            direction: TxDirection::Outgoing,
            amount: 80_000,
            fee: Some(tx.fee),
            address: "ghost1dest".into(),
            status: TxStatus::Pending,
            timestamp: 1000,
            memo: None,
        });
        assert_eq!(wallet.get_history().len(), 1);
        assert_eq!(wallet.get_history()[0].direction, TxDirection::Outgoing);
    }

    #[test]
    fn test_receive_and_invoice_flow() {
        let (mut wallet, _mnemonic) = Wallet::generate(WordCount::Words12).unwrap();
        let addr = wallet.new_receive_address().unwrap();

        let inv = Invoice::new("INV-E2E", "Ghost Shop", "456 Elm", 100_000, &addr, 0);
        let uri = inv.to_payment_uri();

        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.address, addr);
        assert_eq!(parsed.amount, Some(100_000));

        let mut inv = inv;
        inv.add_payment("tx_e2e_pay", 100_000, 5000);
        assert!(inv.is_fully_paid());
        assert_eq!(inv.status, ghost_tap_core::merchant::invoice::InvoiceStatus::Paid);
    }

    #[test]
    fn test_payment_to_wash_flow() {
        let (mut wallet, _mnemonic) = Wallet::generate(WordCount::Words12).unwrap();
        wallet.add_utxo(test_utxo("utxo_wash", 500_000));

        wallet.add_history(HistoryEntry {
            txid: "tx_incoming".into(),
            direction: TxDirection::Incoming,
            amount: 500_000,
            fee: None,
            address: "ghost1me".into(),
            status: TxStatus::Confirmed(3),
            timestamp: 1000,
            memo: None,
        });

        let mut washer = WraithWasher::new();
        washer.wash_payment("tx_incoming", 500_000, 1000);
        assert_eq!(washer.get_queue().len(), 1);
        assert_eq!(washer.get_queue()[0].status, ghost_tap_core::merchant::wraith::WashStatus::Queued);

        washer.mark_in_progress("tx_incoming", "wraith_in_tx", 2000);
        washer.mark_completed("tx_incoming", "wraith_out_tx", 3000);

        let stats = washer.stats();
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.completed_amount, 500_000);
    }

    #[test]
    fn test_full_merchant_flow() {
        let (mut wallet, _mnemonic) = Wallet::generate(WordCount::Words12).unwrap();

        // Add history entries
        let entries = vec![
            HistoryEntry {
                txid: "tx_in1".into(),
                direction: TxDirection::Incoming,
                amount: 300_000,
                fee: None,
                address: "ghost1cust".into(),
                status: TxStatus::Confirmed(10),
                timestamp: 1000,
                memo: Some("Order #101".into()),
            },
            HistoryEntry {
                txid: "tx_in2".into(),
                direction: TxDirection::Incoming,
                amount: 200_000,
                fee: None,
                address: "ghost1cust2".into(),
                status: TxStatus::Confirmed(8),
                timestamp: 2000,
                memo: None,
            },
            HistoryEntry {
                txid: "tx_out1".into(),
                direction: TxDirection::Outgoing,
                amount: 100_000,
                fee: Some(500),
                address: "ghost1supplier".into(),
                status: TxStatus::Confirmed(5),
                timestamp: 3000,
                memo: None,
            },
        ];

        for e in &entries {
            wallet.add_history(e.clone());
        }

        // CSV export
        let csv = TransactionExporter::to_csv(&entries, 0, 5000);
        assert!(csv.contains("tx_in1"));
        assert!(csv.contains("tx_out1"));
        assert!(csv.contains("Order #101"));

        // Invoice
        let mut inv = Invoice::new("INV-MF", "Ghost Merchant", "Addr", 300_000, "ghost1pay", 0);
        inv.add_payment("tx_in1", 300_000, 1000);
        assert!(inv.is_fully_paid());

        // Receipt
        let mut receipt = Receipt::new("REC-MF", "Ghost Merchant", "Addr", 300_000, "tx_in1", 1000);
        receipt.add_item(LineItem::new("Product A", 200_000));
        receipt.add_item(LineItem::new("Product B", 100_000));
        let html = receipt.to_html();
        assert!(html.contains("tx_in1"));
        assert!(html.contains("Product A"));

        // Dashboard summary
        let total_in: u64 = entries.iter()
            .filter(|e| e.direction == TxDirection::Incoming)
            .map(|e| e.amount)
            .sum();
        let total_out: u64 = entries.iter()
            .filter(|e| e.direction == TxDirection::Outgoing)
            .map(|e| e.amount)
            .sum();
        let total_fees: u64 = entries.iter().filter_map(|e| e.fee).sum();

        assert_eq!(total_in, 500_000);
        assert_eq!(total_out, 100_000);
        assert_eq!(total_fees, 500);
    }

    #[test]
    fn test_wallet_persistence_roundtrip() {
        let key = [77u8; 32];
        let storage = WalletStorage::open(":memory:", &key).unwrap();

        let (mut wallet, _mnemonic) = Wallet::generate(WordCount::Words12).unwrap();

        let utxos = vec![test_utxo("utxo_persist_1", 100_000), test_utxo("utxo_persist_2", 200_000)];
        for u in &utxos {
            wallet.add_utxo(u.clone());
        }

        let entry = HistoryEntry {
            txid: "tx_persist".into(),
            direction: TxDirection::Incoming,
            amount: 100_000,
            fee: None,
            address: "ghost1addr".into(),
            status: TxStatus::Confirmed(6),
            timestamp: 5000,
            memo: Some("Persisted".into()),
        };
        wallet.add_history(entry.clone());

        // Save to storage
        storage.save_utxos(wallet.get_utxos()).unwrap();
        storage.save_history_entry(&entry).unwrap();

        // Load from storage
        let loaded_utxos = storage.load_utxos().unwrap();
        assert_eq!(loaded_utxos.len(), 2);
        assert!(loaded_utxos.iter().any(|u| u.txid == "utxo_persist_1"));
        assert!(loaded_utxos.iter().any(|u| u.txid == "utxo_persist_2"));

        let loaded_history = storage.load_all_history().unwrap();
        assert_eq!(loaded_history.len(), 1);
        assert_eq!(loaded_history[0].txid, "tx_persist");
        assert_eq!(loaded_history[0].memo.as_deref(), Some("Persisted"));
    }
}

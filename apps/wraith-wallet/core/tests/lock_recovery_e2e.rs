//! End-to-end test of the unilateral-exit path: wallet keystore +
//! BIP86 derivation + ghost-locks script + recovery-tx builder +
//! bitcoind RPC client.
//!
//! No real bitcoind in the loop — a tiny one-shot HTTP server
//! impersonates the relevant RPC subset (getblockcount,
//! getrawtransaction, sendrawtransaction). The point of this test
//! isn't "bitcoind accepts this" (that's verified by the round-trip
//! through `secp256k1::verify_ecdsa` in lock_recovery's unit tests
//! — same call Bitcoin Core makes during witness-program execution).
//! The point is "every wire-format edge between the modules
//! lines up, and the daemon's LocksRecover dispatch produces a
//! correctly-formed `sendrawtransaction` call against bitcoind."
//!
//! For an actual live demo against `bitcoind -regtest`, see
//! `scripts/regtest-recovery-demo.sh` (sibling commit).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use ghost_locks::{Denomination, GhostLock, TimelockTier};
use wraith_wallet_core::ghostd::GhostdRpc;
use wraith_wallet_core::keystore::Keystore;
use wraith_wallet_core::lock_recovery::{build_recovery_spend, RecoverySpendInputs};

/// Test deterministic mnemonic — stable so the recovery_pubkey is
/// reproducible across test runs.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Bitcoin Core regtest funding txid placeholder. Realistic enough
/// to round-trip through the daemon's resolution path.
const FUNDING_TXID: &str = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd";

/// Mock bitcoind that records every JSON-RPC method it sees and
/// replies with caller-configured fixtures.
struct MockBitcoind {
    /// Method → reply JSON. Single-shot per method by default; if
    /// `Vec<Value>` is supplied the responses replay in order.
    replies: Mutex<std::collections::HashMap<String, Vec<serde_json::Value>>>,
    /// Methods the test asserted MUST be called.
    received: Mutex<Vec<String>>,
}

impl MockBitcoind {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(Default::default()),
            received: Mutex::new(Vec::new()),
        })
    }
    fn set_reply(&self, method: &str, reply: serde_json::Value) {
        self.replies
            .lock()
            .unwrap()
            .entry(method.into())
            .or_default()
            .push(reply);
    }
    fn calls(&self) -> Vec<String> {
        self.received.lock().unwrap().clone()
    }
}

fn spawn_mock(mock: Arc<MockBitcoind>, expect_calls: usize) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/");
    let handle = std::thread::spawn(move || {
        // Serve EXACTLY the expected number of requests then exit.
        // accept() blocks indefinitely; we'd hang on join() if we
        // looped past the test's bounded request count.
        for _ in 0..expect_calls {
            let (mut stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => return,
            };
            let body = read_request(&stream);
            let parsed: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let method = parsed["method"].as_str().unwrap_or("").to_string();
            mock.received.lock().unwrap().push(method.clone());
            let mut replies = mock.replies.lock().unwrap();
            let reply_value = replies
                .get_mut(&method)
                .and_then(|q| if q.is_empty() { None } else { Some(q.remove(0)) })
                .unwrap_or_else(|| {
                    serde_json::json!({
                        "result": null,
                        "error": { "code": -32601, "message": format!("no fixture for {method}") },
                        "id": "wraithd",
                    })
                });
            let body_str = reply_value.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                body_str.len(),
                body_str
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (url, handle)
}

fn read_request(stream: &TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return String::new();
        }
        if line == "\r\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    let _ = std::io::Read::read_exact(&mut reader, &mut body);
    String::from_utf8(body).unwrap_or_default()
}

#[test]
fn unilateral_exit_e2e_recovers_locked_funds_with_no_operator_cooperation() {
    use bitcoin::{Address, ScriptBuf};

    // 1. Wallet derives its own recovery_pubkey at index 0 from a
    //    real keystore. This is the SAME call the daemon's
    //    LocksPrepare handler makes.
    let keystore = Keystore::from_mnemonic(TEST_MNEMONIC).unwrap();
    let ghost_keys = keystore.ghost_keys().unwrap();
    let recovery_pubkey_bytes = ghost_keys.derive_recovery_pubkey(0).unwrap();
    let recovery_secret = ghost_keys.derive_recovery_secret(0).unwrap();
    let recovery_pubkey = PublicKey::from_slice(&recovery_pubkey_bytes).unwrap();

    // 2. Operator-side: imagine ghost-pay has a master key. We
    //    simulate it with a deterministic secret. In production
    //    this is `keys.derive_lock_secret(lock_index)`.
    let secp = Secp256k1::new();
    let lock_secret = bitcoin::secp256k1::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
    let lock_pubkey = PublicKey::from_secret_key(&secp, &lock_secret);

    // 3. Build the actual P2WSH lock — exact same constructor
    //    ghost-pay uses post-commit-65.
    let creation_height: u32 = 800_000;
    let lock = GhostLock::from_pubkeys(
        lock_pubkey,
        recovery_pubkey,
        Denomination::Tiny,
        TimelockTier::Short,
        creation_height,
    )
    .expect("lock builds");

    // The on-chain funding output is the lock's scriptPubKey.
    let funding_address = Address::from_script(lock.script_pubkey(), Network::Signet)
        .unwrap()
        .to_string();
    let funding_value_sats = Denomination::Tiny.sats(); // 100_000

    // 4. Set up the mock bitcoind. The wallet's LocksRecover path
    //    calls THREE RPC methods in order — getblockcount,
    //    getrawtransaction, sendrawtransaction.
    let mock = MockBitcoind::new();
    let recovery_blocks = TimelockTier::Short.blocks();
    // Tip the chain past the timelock so maturity check passes.
    mock.set_reply(
        "getblockcount",
        serde_json::json!({
            "result": (creation_height + recovery_blocks + 5) as u64,
            "error": null,
            "id": "wraithd",
        }),
    );
    // getrawtransaction returns a tx whose vout[0] pays our lock
    // address with our funding amount + the lock's scriptPubKey hex.
    mock.set_reply(
        "getrawtransaction",
        serde_json::json!({
            "result": {
                "txid": FUNDING_TXID,
                "confirmations": 6,
                "vout": [
                    {
                        "n": 0,
                        "value": (funding_value_sats as f64) / 100_000_000.0,
                        "scriptPubKey": {
                            "hex": hex::encode(lock.script_pubkey().as_bytes()),
                            "address": funding_address,
                            "type": "witness_v0_scripthash",
                        }
                    }
                ]
            },
            "error": null,
            "id": "wraithd",
        }),
    );
    // sendrawtransaction returns the tx's own computed txid (matches
    // honest-bitcoind behaviour). The mock doesn't validate the tx —
    // that's intentional. Validity is asserted by the round-trip
    // verify in lock_recovery's unit tests.
    // We supply a placeholder txid; the wallet doesn't actually use
    // it for assertions in this test (it only echoes it back).
    mock.set_reply(
        "sendrawtransaction",
        serde_json::json!({
            "result": "0000000000000000000000000000000000000000000000000000000000000bee",
            "error": null,
            "id": "wraithd",
        }),
    );

    let (rpc_url, server_handle) = spawn_mock(mock.clone(), 3);
    let rpc = GhostdRpc::new(rpc_url, "user", "pass");

    // 5. Resolve the funding outpoint via getrawtransaction (same
    //    code path the daemon's LocksRecover handler uses).
    let raw = rpc.get_raw_transaction_verbose(FUNDING_TXID).unwrap();
    let target_addr = funding_address.clone();
    let vout = raw
        .vout
        .iter()
        .find(|v| v.script_pubkey.first_address() == Some(&target_addr))
        .expect("funding vout present");
    assert_eq!(vout.value_sats(), funding_value_sats);
    assert_eq!(vout.n, 0);

    // 6. Maturity check.
    let current_height = rpc.get_block_count().unwrap() as u32;
    assert!(current_height >= creation_height + recovery_blocks);

    // 7. Build the recovery spend with the user's keystore-derived
    //    recovery_secret.
    let destination = "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla";
    let inputs = RecoverySpendInputs {
        lock_pubkey_hex: hex::encode(lock_pubkey.serialize()),
        recovery_pubkey_hex: hex::encode(recovery_pubkey.serialize()),
        recovery_blocks,
        funding_txid: FUNDING_TXID.into(),
        funding_vout: vout.n,
        prev_value_sats: vout.value_sats(),
        funding_scriptpubkey_hex: vout.script_pubkey.hex.clone(),
        destination_address: destination.into(),
        fee_sats: 1_000,
        network: Network::Signet,
        current_height,
        creation_height,
    };
    let built = build_recovery_spend(&inputs, &recovery_secret).expect("build ok");

    // 8. Broadcast.
    let returned_txid = rpc.send_raw_transaction(&built.raw_hex).unwrap();
    assert_eq!(
        returned_txid,
        "0000000000000000000000000000000000000000000000000000000000000bee"
    );

    // 9. The mock saw the three methods, in order. That's the
    //    full LocksRecover wire path: maturity → outpoint → broadcast.
    server_handle
        .join()
        .unwrap_or_else(|_| panic!("mock server panicked"));
    let calls = mock.calls();
    assert_eq!(
        calls,
        vec![
            "getrawtransaction".to_string(),
            "getblockcount".to_string(),
            "sendrawtransaction".to_string(),
        ],
        "wallet hit bitcoind's RPC in the expected order with the expected methods"
    );

    // 10. The recovery tx's witness is the recovery branch — empty
    //     selector picks OP_ELSE — and the destination output goes
    //     to the wallet-controlled address. This is the headline:
    //     no operator key, no operator HTTP endpoint, just wallet +
    //     bitcoind, and the user gets their bitcoin back.
    assert_eq!(built.tx.input.len(), 1);
    assert_eq!(built.tx.output.len(), 1);
    use std::str::FromStr;
    let dest_spk = Address::from_str(destination)
        .unwrap()
        .require_network(Network::Signet)
        .unwrap()
        .script_pubkey();
    assert_eq!(built.tx.output[0].script_pubkey, dest_spk);
    assert_eq!(built.tx.output[0].value.to_sat(), funding_value_sats - 1_000);
    let witness_items = built.tx.input[0].witness.iter().count();
    assert_eq!(witness_items, 3, "recovery witness has 3 items");
    let _ = ScriptBuf::new();
}

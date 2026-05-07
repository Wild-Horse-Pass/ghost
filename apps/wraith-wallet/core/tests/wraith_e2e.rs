//! End-to-end integration test: real wallet client driving a real
//! `wraith-coordinator` over real HTTP.
//!
//! Sets up a coordinator with `MockBondLedger` + `StubBroadcaster`,
//! binds it to an ephemeral port via `axum::serve`, then spins up
//! five `WraithSessionClient` runs concurrently — one per ghost_id.
//! Each wallet drives the protocol on its own task; the test
//! coordinator-flips the session Filling → Locked mid-flight (since
//! the 5-min fill-window won't expire in test time and we don't have
//! 20 wallets to hit max_participants).

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{secp256k1::SecretKey, Address, Network, Witness};
use wraith_coordinator::broadcaster::{Broadcaster, StubBroadcaster};
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{
    BondLedger, LiteSessionState, MockBondLedger, SessionGossipEvent,
};
use wraith_wallet_core::wraith::{
    MixRequest, ParticipantUtxo, WraithClientError, WraithSessionClient,
};

const TIER_ID: &str = "100k_sats";
const TIER_DENOM: u64 = 100_000;
const TIER_BOND: u64 = 500;
const N: usize = 5;

/// Generate the i-th deterministic signet P2WPKH address. Same scheme
/// used by the coordinator's own router tests.
fn signet_addr(i: u8) -> String {
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::CompressedPublicKey;
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[i; 32]).unwrap();
    let cpk = CompressedPublicKey(sk.public_key(&secp));
    Address::p2wpkh(&cpk, Network::Signet).to_string()
}

#[tokio::test]
async fn five_wallets_complete_a_full_mix_round() {
    // 1. Stand up the coordinator.
    let ledger: Arc<MockBondLedger> = Arc::new(MockBondLedger::new());
    let stub_broadcaster = StubBroadcaster::new();
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        Arc::new(wraith_protocol::SystemClock),
        Arc::new(wraith_protocol::RandomSessionIdGenerator),
        Some(ledger.clone() as Arc<dyn BondLedger>),
        Some(signet_addr(99)),
        Some(Arc::new(stub_broadcaster.clone()) as Arc<dyn Broadcaster>),
    ));
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum serve");
    });
    let base_url = format!("http://127.0.0.1:{port}");

    // 2. Spawn 5 wallets concurrently. Each runs the full protocol
    //    on its own task. The shared MockBondLedger is the bond
    //    source; the test coordinator-side state advances Filling →
    //    Locked once all 5 have enrolled (see step 3).
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let ledger_for_task = ledger.clone();
        let base_url = base_url.clone();
        let handle = tokio::spawn(async move {
            let client = WraithSessionClient::new(base_url, Network::Signet);
            let ghost = format!("wallet-{i}");
            let utxo = ParticipantUtxo {
                txid: "11".repeat(32),
                vout: i as u32,
                value_sats: 200_000,
                scriptpubkey_hex: "deadbeef".into(),
            };
            let req = MixRequest {
                tier_id: TIER_ID.into(),
                ghost_id: ghost.clone(),
                bond_id_placeholder: format!("placeholder-{i}"),
                utxo,
                change_address: Some(signet_addr(50 + i as u8)),
                mix_output_address: signet_addr(i as u8 + 1),
            };
            let bond_setup = move |session_id: &str, expected: u64| {
                let ledger = ledger_for_task.clone();
                let ghost = ghost.clone();
                let session_id = session_id.to_string();
                async move {
                    assert_eq!(expected, TIER_BOND);
                    let _ = ledger.escrow(ghost, session_id, expected);
                    Ok::<(), WraithClientError>(())
                }
            };
            let signer = |_tx: &bitcoin::Transaction, _idx: usize, _amt: u64| {
                let mut w = Witness::new();
                w.push([0xde, 0xad, 0xbe, 0xef]);
                Ok::<Witness, WraithClientError>(w)
            };
            client.execute_mix(req, signer, bond_setup).await
        });
        handles.push(handle);
    }

    // 3. Flip the session to Locked once all 5 wallets have enrolled.
    //    We don't know the session_id ahead of time, so poll the
    //    state's session registry until exactly one session has
    //    `min_participants` slots filled. Bounded retry.
    let session_id = wait_for_quorum(&state).await;
    let _ = state.sessions.apply_event(SessionGossipEvent::StateChanged {
        session_id: session_id.clone(),
        new_state: LiteSessionState::Locked,
    });

    // 4. Wait for all 5 wallet tasks to finish.
    let mut outcomes = Vec::with_capacity(N);
    for h in handles {
        let outcome = h
            .await
            .expect("task join")
            .expect("execute_mix succeeded");
        outcomes.push(outcome);
    }

    // 5. All five outcomes refer to the same session and broadcast txid.
    let broadcast_txid = outcomes[0].broadcast_txid;
    for (i, o) in outcomes.iter().enumerate() {
        assert_eq!(o.session_id, session_id, "wallet-{i} different session");
        assert_eq!(o.broadcast_txid, broadcast_txid, "wallet-{i} different txid");
    }

    // 6. The broadcaster received exactly one tx with 5 inputs.
    assert_eq!(stub_broadcaster.count(), 1, "broadcast called once");
    let final_tx = stub_broadcaster.last().expect("tx was broadcast");
    assert_eq!(final_tx.compute_txid(), broadcast_txid);
    assert_eq!(final_tx.input.len(), N, "5 inputs");

    // 7. Each wallet's mixed output landed in the tx, all distinct
    //    indices, all the right amount + scriptPubKey.
    let mut seen_indices = std::collections::HashSet::new();
    for (i, o) in outcomes.iter().enumerate() {
        assert!(
            seen_indices.insert(o.mixed_output_tx_index),
            "wallet-{i} duplicate mixed_output_tx_index",
        );
        let txout = &final_tx.output[o.mixed_output_tx_index];
        assert_eq!(
            txout.value.to_sat(),
            TIER_DENOM,
            "wallet-{i} wrong amount"
        );
        let expected_addr = Address::from_str(&signet_addr(i as u8 + 1))
            .unwrap()
            .require_network(Network::Signet)
            .unwrap();
        assert_eq!(
            txout.script_pubkey,
            expected_addr.script_pubkey(),
            "wallet-{i} wrong scriptpubkey"
        );
    }

    // 8. All bonds resolved as Refund(RoundCompleted).
    let bonds = ledger.snapshot_all();
    assert_eq!(bonds.len(), N, "5 bonds");
    use wraith_protocol::{BondResolution, BondStatus, RefundReason};
    for b in &bonds {
        match &b.status {
            BondStatus::Resolved(BondResolution::Refund(RefundReason::RoundCompleted)) => {}
            other => panic!(
                "bond {} for {} not Refund(RoundCompleted): {:?}",
                b.bond_id, b.ghost_id, other
            ),
        }
    }
}

/// Block until the coordinator's session registry contains exactly
/// one session with N enrolled participants. Returns its session_id.
/// Bounded poll loop — gives up after a generous timeout so the test
/// fails fast on a wallet bug rather than hanging.
async fn wait_for_quorum(state: &CoordinatorState) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        // Walk every session once per loop — there's only ever 1 in
        // this test, so the cost is trivial.
        let mut found: Option<String> = None;
        for tier in state.supported_tiers() {
            for s in state.sessions.open_sessions_at(
                tier,
                wraith_protocol::SessionType::Mix,
                state.now(),
            ) {
                if s.participants.len() == N {
                    found = Some(s.session_id);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        if let Some(sid) = found {
            return sid;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for {N} wallets to enrol");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

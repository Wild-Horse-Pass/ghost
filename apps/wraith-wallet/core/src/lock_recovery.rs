//! Unilateral exit for Ghost Locks.
//!
//! Builds, signs, and produces a hex-encoded transaction that spends
//! a locked UTXO via the script's recovery branch (OP_ELSE: CSV +
//! recovery_pubkey OP_CHECKSIG). The wallet uses ITS OWN
//! recovery_secret (derived from `Keystore::ghost_keys()` at the
//! `recovery_index` it sent to ghost-pay at lock-prepare time). No
//! ghost-pay, no ghost-gsp, no operator cooperation. Just bitcoin.
//!
//! ## What this module does NOT do
//!
//! - **Broadcast.** The caller (daemon) hands the resulting raw tx
//!   hex to a `GhostdRpc::send_raw_transaction` call. Decoupling
//!   build-and-sign from broadcast means tests can assert tx shape
//!   without spinning up a node, and the daemon can dry-run an
//!   exit before sending.
//!
//! - **Funding outpoint discovery.** The caller passes the funding
//!   `(txid, vout, value_sats)` it has already resolved (e.g. via
//!   bitcoind's `getrawtransaction`). This module trusts those.
//!
//! - **Maturity check.** The caller asserts `current_height >=
//!   creation_height + recovery_blocks` before calling. Bitcoin
//!   itself rejects the spend if the CSV isn't satisfied, but
//!   surfacing a friendly error before broadcast is better UX.
//!
//! ## Witness shape
//!
//! For the recovery branch, the witness stack is exactly:
//!
//!   1. Schnorr-style ECDSA signature with sighash byte appended
//!      (P2WSH = ECDSA, NOT Schnorr — Schnorr is taproot only).
//!   2. The bytecode `0x` (empty / zero — selects OP_ELSE).
//!   3. The witness script (so the verifier can re-hash and check
//!      against the scriptPubKey's WSH).
//!
//! Per the script docstring in ghost-locks/src/script.rs:
//!   `Recovery: <signature> <0> <witness_script>`

use bitcoin::absolute::LockTime;
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use std::str::FromStr;

use ghost_locks::build_wsh_witness_script;

#[derive(Debug, thiserror::Error)]
pub enum LockRecoveryError {
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("bitcoin: {0}")]
    Bitcoin(String),
    #[error("ghost-locks: {0}")]
    GhostLocks(#[from] ghost_locks::GhostLockError),
    #[error("destination address is not valid for network {network:?}: {detail}")]
    BadDestinationAddress { network: Network, detail: String },
    #[error("insufficient input value: prev {prev_sats} sats, fee {fee_sats} sats — need fee < prev")]
    InsufficientInput { prev_sats: u64, fee_sats: u64 },
    #[error("timelock not yet matured: current {current}, required {required}")]
    TimelockNotMatured { current: u32, required: u32 },
    #[error("secp: {0}")]
    Secp(String),
}

/// Inputs to a recovery-spend transaction. All caller-supplied —
/// this module just pickles them into a signed tx.
#[derive(Debug, Clone)]
pub struct RecoverySpendInputs {
    /// The `lock_pubkey` (cooperative-path key) — needed to
    /// reconstruct the witness script.
    pub lock_pubkey_hex: String,
    /// The user's `recovery_pubkey`. Echoed back during prepare,
    /// stashed on the daemon. Goes into the witness script.
    pub recovery_pubkey_hex: String,
    /// CSV blocks the recovery branch waits on.
    pub recovery_blocks: u32,
    /// Funding txid (the on-chain tx that paid the lock's address).
    pub funding_txid: String,
    /// vout of the lock-funding output in `funding_txid`. Caller
    /// resolves via `getrawtransaction` + scriptPubKey match.
    pub funding_vout: u32,
    /// Value of the lock-funding output, in sats.
    pub prev_value_sats: u64,
    /// Hex-encoded scriptPubKey of the funding output (P2WSH).
    /// Used for the BIP-143 sighash's prevout commitment.
    pub funding_scriptpubkey_hex: String,
    /// Where the recovered funds go. Wallet-controlled.
    pub destination_address: String,
    /// Mining fee to pay, in sats. Subtracted from
    /// `prev_value_sats`. Caller picks based on bitcoind's fee
    /// estimate or a flat amount.
    pub fee_sats: u64,
    /// Network the destination address is parsed against.
    pub network: Network,
    /// Current block height. Used to verify maturity before signing.
    pub current_height: u32,
    /// Block height the lock was created at. Combined with
    /// `recovery_blocks` gives the maturity height.
    pub creation_height: u32,
}

/// Output of a successful recovery-spend build.
#[derive(Debug, Clone)]
pub struct BuiltRecoveryTx {
    /// Consensus-encoded raw tx, hex. Caller broadcasts via
    /// bitcoind's `sendrawtransaction`.
    pub raw_hex: String,
    /// The signed `bitcoin::Transaction`. Returned alongside the hex
    /// for tests / diagnostics.
    pub tx: Transaction,
    /// txid the eventual on-chain spend will commit to.
    pub txid: String,
}

/// Build, sign, and serialise a Ghost-Lock recovery-path spend
/// using the user's `recovery_secret`. Pure function — no I/O,
/// no mutable state.
pub fn build_recovery_spend(
    inputs: &RecoverySpendInputs,
    recovery_secret: &SecretKey,
) -> Result<BuiltRecoveryTx, LockRecoveryError> {
    // 0. Sanity: maturity. CSV is relative; the spend is valid
    //    only when current_height >= creation_height + recovery_blocks.
    let required = inputs
        .creation_height
        .saturating_add(inputs.recovery_blocks);
    if inputs.current_height < required {
        return Err(LockRecoveryError::TimelockNotMatured {
            current: inputs.current_height,
            required,
        });
    }

    // 1. Sanity: enough input value to pay the fee.
    if inputs.fee_sats >= inputs.prev_value_sats {
        return Err(LockRecoveryError::InsufficientInput {
            prev_sats: inputs.prev_value_sats,
            fee_sats: inputs.fee_sats,
        });
    }

    // 2. Reconstruct the witness script (P2WSH spends require
    //    revealing it). Both pubkeys come from the wallet's
    //    persisted prepare-lock metadata.
    let lock_pk_bytes = hex::decode(inputs.lock_pubkey_hex.trim())?;
    let recovery_pk_bytes = hex::decode(inputs.recovery_pubkey_hex.trim())?;
    let lock_pk = bitcoin::secp256k1::PublicKey::from_slice(&lock_pk_bytes)
        .map_err(|e| LockRecoveryError::Bitcoin(format!("lock_pubkey: {e}")))?;
    let recovery_pk = bitcoin::secp256k1::PublicKey::from_slice(&recovery_pk_bytes)
        .map_err(|e| LockRecoveryError::Bitcoin(format!("recovery_pubkey: {e}")))?;
    let witness_script = build_wsh_witness_script(&lock_pk, &recovery_pk, inputs.recovery_blocks)?;

    // 3. Parse destination + assemble outputs. Fee is implicit
    //    (in - out = fee).
    let dest_unchecked =
        Address::from_str(inputs.destination_address.trim()).map_err(|e| {
            LockRecoveryError::BadDestinationAddress {
                network: inputs.network,
                detail: format!("parse: {e}"),
            }
        })?;
    let dest = dest_unchecked
        .require_network(inputs.network)
        .map_err(|e| LockRecoveryError::BadDestinationAddress {
            network: inputs.network,
            detail: format!("network: {e}"),
        })?;
    let out_value = inputs.prev_value_sats - inputs.fee_sats;
    let txout = TxOut {
        value: Amount::from_sat(out_value),
        script_pubkey: dest.script_pubkey(),
    };

    // 4. Assemble the unsigned tx. CRITICAL: nSequence must encode
    //    the relative-locktime block count for BIP-68/112 to fire.
    //    Per BIP-112 the input's nSequence must:
    //      * have bit 31 (disable flag) CLEAR — otherwise relative
    //        locktime is disabled and CSV becomes a no-op-disabled
    //        check that REJECTS,
    //      * have bit 22 (time-flag) CLEAR — block-based encoding
    //        matching the script's `<n> OP_CSV`,
    //      * have a value ≥ the script's pushed `n`.
    //    Setting `nSequence = recovery_blocks` directly satisfies all
    //    three. The legacy `0xFFFFFFFE` constant looked correct (and
    //    is what BIP-125 RBF docs cite) but its bit 31 is SET,
    //    disabling relative locktime — so CSV always fails. See
    //    BIP-68/112 for the encoding rules.
    let funding_txid = Txid::from_str(inputs.funding_txid.trim())
        .map_err(|e| LockRecoveryError::Bitcoin(format!("funding_txid: {e}")))?;
    let txin = TxIn {
        previous_output: OutPoint {
            txid: funding_txid,
            vout: inputs.funding_vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_consensus(inputs.recovery_blocks),
        witness: Witness::new(),
    };
    let mut tx = Transaction {
        version: Version::TWO, // BIP-68 requires version 2 for CSV
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    // 5. Compute BIP-143 sighash for the P2WSH input.
    let prev_spk_bytes = hex::decode(inputs.funding_scriptpubkey_hex.trim())?;
    let _prev_spk = ScriptBuf::from_bytes(prev_spk_bytes); // not strictly needed for the sighash call
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wsh_signature_hash(
            0,
            &witness_script,
            Amount::from_sat(inputs.prev_value_sats),
            EcdsaSighashType::All,
        )
        .map_err(|e| LockRecoveryError::Bitcoin(format!("p2wsh sighash: {e}")))?;

    // 6. Sign with the user's recovery_secret.
    let secp = Secp256k1::new();
    use bitcoin::hashes::Hash as _;
    let msg = Message::from_digest(*sighash.as_byte_array());
    let raw_sig = secp.sign_ecdsa(&msg, recovery_secret);
    let ecdsa_sig = EcdsaSignature {
        signature: raw_sig,
        sighash_type: EcdsaSighashType::All,
    };

    // 7. Assemble the witness stack per the recovery branch:
    //      [<sig+sighash>, <empty for OP_ELSE>, <witness_script>]
    //    The empty-byte `OP_ELSE` selector is the second item.
    //    "Empty" on the witness stack is an empty bytestring; the
    //    script interpreter treats that as Bitcoin's OP_FALSE / 0,
    //    triggering the OP_ELSE branch.
    let mut witness = Witness::new();
    witness.push(ecdsa_sig.to_vec());
    witness.push([]); // empty stack item = OP_FALSE → OP_ELSE branch
    witness.push(witness_script.as_bytes());
    tx.input[0].witness = witness;

    // 8. Serialise.
    let raw_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    let txid = tx.compute_txid().to_string();
    Ok(BuiltRecoveryTx {
        raw_hex,
        tx,
        txid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, SecretKey};
    use ghost_locks::{Denomination, GhostLock, TimelockTier};

    fn make_keys() -> (SecretKey, SecretKey, PublicKey, PublicKey) {
        let secp = Secp256k1::new();
        let lock_sk = SecretKey::from_slice(&[1; 32]).unwrap();
        let rec_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let lock_pk = PublicKey::from_secret_key(&secp, &lock_sk);
        let rec_pk = PublicKey::from_secret_key(&secp, &rec_sk);
        (lock_sk, rec_sk, lock_pk, rec_pk)
    }

    fn fixture_lock() -> (GhostLock, SecretKey, SecretKey) {
        let secp = Secp256k1::new();
        let (lock_sk, rec_sk, _, _) = make_keys();
        let lock = GhostLock::new(
            &secp,
            &lock_sk,
            &rec_sk,
            Denomination::Tiny,
            TimelockTier::Short,
            800_000,
        )
        .unwrap();
        (lock, lock_sk, rec_sk)
    }

    fn fixture_inputs(lock: &GhostLock, mature: bool, fee_sats: u64) -> RecoverySpendInputs {
        let creation_height = lock.creation_height();
        let recovery_blocks = lock.timelock_tier().blocks();
        let current_height = if mature {
            creation_height + recovery_blocks
        } else {
            creation_height + recovery_blocks - 1
        };
        RecoverySpendInputs {
            lock_pubkey_hex: hex::encode(lock.lock_pubkey().serialize()),
            recovery_pubkey_hex: hex::encode(lock.recovery_pubkey().serialize()),
            recovery_blocks,
            funding_txid: "11".repeat(32),
            funding_vout: 0,
            prev_value_sats: lock.denomination().sats(),
            funding_scriptpubkey_hex: hex::encode(lock.script_pubkey().as_bytes()),
            destination_address: "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla".into(),
            fee_sats,
            network: Network::Signet,
            current_height,
            creation_height,
        }
    }

    #[test]
    fn refuses_spend_before_timelock_matures() {
        let (lock, _lock_sk, rec_sk) = fixture_lock();
        let inputs = fixture_inputs(&lock, false, 1_000);
        let err = build_recovery_spend(&inputs, &rec_sk).expect_err("should fail");
        match err {
            LockRecoveryError::TimelockNotMatured { current, required } => {
                assert!(current < required);
            }
            other => panic!("expected TimelockNotMatured; got {other:?}"),
        }
    }

    #[test]
    fn refuses_spend_when_fee_exceeds_input() {
        let (lock, _, rec_sk) = fixture_lock();
        // Tiny denomination is 100_000 sats.
        let inputs = fixture_inputs(&lock, true, 100_000);
        let err = build_recovery_spend(&inputs, &rec_sk).expect_err("should fail");
        match err {
            LockRecoveryError::InsufficientInput { .. } => {}
            other => panic!("expected InsufficientInput; got {other:?}"),
        }
    }

    #[test]
    fn produces_consensus_encodable_tx_with_recovery_witness_shape() {
        let (lock, _lock_sk, rec_sk) = fixture_lock();
        let inputs = fixture_inputs(&lock, true, 1_000);
        let built = build_recovery_spend(&inputs, &rec_sk).expect("should succeed");
        // Round-trip via the consensus deserializer.
        use bitcoin::consensus::encode::deserialize_hex;
        let decoded: Transaction = deserialize_hex(&built.raw_hex).unwrap();
        assert_eq!(decoded.input.len(), 1);
        assert_eq!(decoded.output.len(), 1);
        // CSV requires version >= 2.
        assert_eq!(decoded.version, Version::TWO);
        // nSequence must equal recovery_blocks so BIP-68/112 fires
        // (bit 31 cleared, value matches the script's pushed CSV).
        assert_eq!(
            decoded.input[0].sequence,
            Sequence::from_consensus(inputs.recovery_blocks)
        );
        // Witness stack: [sig, empty, witness_script]
        let w = &decoded.input[0].witness;
        assert_eq!(w.len(), 3, "witness has 3 items");
        let mut iter = w.iter();
        let sig_bytes = iter.next().unwrap();
        assert!(
            (71..=73).contains(&sig_bytes.len()),
            "ecdsa sig is 71-73 bytes including sighash byte"
        );
        let else_byte = iter.next().unwrap();
        assert_eq!(else_byte.len(), 0, "OP_ELSE selector is empty");
        let script = iter.next().unwrap();
        // The witness script length should match what build_wsh_witness_script produces.
        assert!(script.len() > 70 && script.len() < 200);
    }

    #[test]
    fn signature_verifies_against_recovery_pubkey() {
        // Round-trip — pull the sig out of the witness, recompute
        // the sighash, verify. This is the crux: it proves the
        // user's recovery_secret actually signs a valid spend.
        use bitcoin::ecdsa::Signature as EcdsaSig;
        let (lock, _, rec_sk) = fixture_lock();
        let inputs = fixture_inputs(&lock, true, 1_000);
        let built = build_recovery_spend(&inputs, &rec_sk).unwrap();

        let sig_bytes = built.tx.input[0].witness.iter().next().unwrap().to_vec();
        let parsed = EcdsaSig::from_slice(&sig_bytes).unwrap();

        // Recompute sighash.
        let lock_pk_bytes = hex::decode(&inputs.lock_pubkey_hex).unwrap();
        let rec_pk_bytes = hex::decode(&inputs.recovery_pubkey_hex).unwrap();
        let lock_pk = PublicKey::from_slice(&lock_pk_bytes).unwrap();
        let rec_pk = PublicKey::from_slice(&rec_pk_bytes).unwrap();
        let witness_script =
            build_wsh_witness_script(&lock_pk, &rec_pk, inputs.recovery_blocks).unwrap();
        let mut cache = SighashCache::new(&built.tx);
        let sighash = cache
            .p2wsh_signature_hash(
                0,
                &witness_script,
                Amount::from_sat(inputs.prev_value_sats),
                EcdsaSighashType::All,
            )
            .unwrap();
        use bitcoin::hashes::Hash as _;
        let msg = Message::from_digest(*sighash.as_byte_array());

        // Verify with secp.
        let secp = Secp256k1::new();
        secp.verify_ecdsa(&msg, &parsed.signature, &rec_pk).unwrap();
    }
}

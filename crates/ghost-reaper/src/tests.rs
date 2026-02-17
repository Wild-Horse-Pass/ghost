use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::config::{ReaperConfig, ReaperMode};
use crate::verdict::{DeadCodeType, Verdict};
use crate::{analyze, SpendType};

// ─── Test Helpers ───────────────────────────────────────────────────────────

fn non_coinbase_outpoint() -> OutPoint {
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[1u8]));
    OutPoint { txid, vout: 0 }
}

/// Build a P2WPKH output script: OP_0 OP_PUSHBYTES_20 <20 bytes>
fn p2wpkh_script() -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14]; // OP_0, PUSHBYTES_20
    bytes.extend([0xAA; 20]);
    ScriptBuf::from(bytes)
}

/// Build a transaction with a single P2TR script-path input.
/// The tapscript and control block are provided; other witness items
/// are optional (for signatures, etc).
fn tx_with_tapscript(tapscript: &[u8], extra_witness: &[&[u8]]) -> Transaction {
    let mut witness = Witness::new();
    for item in extra_witness {
        witness.push(item);
    }
    witness.push(tapscript);
    // Control block: 33 bytes, first byte 0xc0 (leaf version)
    let mut control_block = vec![0xc0];
    control_block.extend([0x11; 32]); // internal key
    witness.push(&control_block);

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    }
}

/// Build a transaction with P2WSH witness script.
fn tx_with_witness_script(witness_script: &[u8], extra_witness: &[&[u8]]) -> Transaction {
    let mut witness = Witness::new();
    for item in extra_witness {
        witness.push(item);
    }
    witness.push(witness_script);

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    }
}

/// Build a transaction with specific outputs.
fn tx_with_outputs(outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

/// Build a P2TR key-path spend (single 64-byte Schnorr sig).
fn tx_p2tr_keypath() -> Transaction {
    let mut witness = Witness::new();
    witness.push([0x30; 64]); // 64-byte Schnorr signature

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    }
}

/// Build a coinbase transaction.
fn coinbase_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0xFFFFFFFF,
            },
            script_sig: ScriptBuf::from(vec![0x03, 0x01, 0x02, 0x03]), // block height
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(312500000),
            script_pubkey: p2wpkh_script(),
        }],
    }
}

// ─── Spec Test Vectors ──────────────────────────────────────────────────────

/// Test 1: Standard inscription envelope → Corpse
#[test]
fn test_standard_inscription_envelope() {
    // Tapscript: OP_FALSE OP_IF OP_PUSH3 "ord" OP_1 OP_PUSH24 "text/plain;charset=utf-8"
    //            OP_0 OP_PUSH11 "Hello World" OP_ENDIF OP_CHECKSIG
    let mut script: Vec<u8> = Vec::new();
    // OP_FALSE OP_IF
    script.push(0x00);
    script.push(0x63);
    // OP_PUSH3 "ord"
    script.push(0x03);
    script.extend(b"ord");
    // OP_1 (content type marker)
    script.push(0x51);
    // OP_PUSH24 "text/plain;charset=utf-8"
    let content_type = b"text/plain;charset=utf-8";
    script.push(content_type.len() as u8);
    script.extend(content_type);
    // OP_0 (content marker)
    script.push(0x00);
    // OP_PUSH11 "Hello World"
    let content = b"Hello World";
    script.push(content.len() as u8);
    script.extend(content);
    // OP_ENDIF
    script.push(0x68);
    // OP_CHECKSIG (legitimate spend condition after envelope)
    script.push(0xac);

    let sig = [0x30; 64]; // Schnorr sig
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert!(!verdict.dead_regions.is_empty());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::InscriptionEnvelope
    );
}

/// Test 2: Large image inscription → Corpse
#[test]
fn test_large_image_inscription() {
    let mut script: Vec<u8> = Vec::new();
    // OP_FALSE OP_IF
    script.push(0x00);
    script.push(0x63);
    // OP_PUSH3 "ord"
    script.push(0x03);
    script.extend(b"ord");
    // Simulate large image data: multiple 520-byte pushes (max push per element)
    for _ in 0..10 {
        // OP_PUSHDATA2 with 520 bytes
        script.push(0x4d);
        script.extend(520u16.to_le_bytes());
        script.extend(vec![0xFF; 520]);
    }
    // OP_ENDIF
    script.push(0x68);
    // OP_CHECKSIG
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert!(verdict.total_dead_bytes > 5000);
}

/// Test 3: Legitimate HTLC → Accept
#[test]
fn test_legitimate_htlc() {
    // HTLC script: OP_IF <pubkey_hash> OP_ELSE <timeout> OP_CLTV OP_DROP <pubkey_hash> OP_ENDIF OP_CHECKSIG
    // All branches are reachable — no dead code
    let mut script: Vec<u8> = Vec::new();
    // OP_IF
    script.push(0x63);
    // OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // PUSH20
    script.extend([0xAA; 20]);
    script.push(0x88); // OP_EQUALVERIFY
    // OP_ELSE
    script.push(0x67);
    // <timeout> OP_CLTV OP_DROP
    script.push(0x04); // PUSH4
    script.extend(500000u32.to_le_bytes());
    script.push(0xb1); // OP_CLTV
    script.push(0x75); // OP_DROP (small push, below threshold)
    // <pubkey_hash>
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // PUSH20
    script.extend([0xBB; 20]);
    script.push(0x88); // OP_EQUALVERIFY
    // OP_ENDIF OP_CHECKSIG
    script.push(0x68);
    script.push(0xac);

    let sig = [0x30; 64];
    let preimage = [0xCC; 32];
    let tx = tx_with_tapscript(&script, &[&sig, &preimage]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert!(verdict.dead_regions.is_empty());
}

/// Test 4: P2TR key path → Accept
#[test]
fn test_p2tr_key_path() {
    let tx = tx_p2tr_keypath();
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert!(verdict.dead_regions.is_empty());
    assert_eq!(verdict.input_analyses[0].spend_type, "P2TR-keypath");
}

/// Test 5: OP_DROP data stuffing → Corpse
#[test]
fn test_op_drop_data_stuffing() {
    let mut script: Vec<u8> = Vec::new();
    // Push 100 bytes of junk data
    script.push(0x4c); // OP_PUSHDATA1
    script.push(100); // length
    script.extend(vec![0xDE; 100]);
    // OP_DROP
    script.push(0x75);
    // Legitimate spend condition
    script.push(0x51); // OP_1 (true)

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::DropStuffing
    );
}

/// Test 6: Bare multisig fake pubkeys → Corpse
#[test]
fn test_bare_multisig_fake_pubkeys() {
    // 1-of-3 multisig where 2 pubkeys have invalid prefixes (data carriers)
    let mut script_bytes = vec![0x51]; // OP_1

    // Valid pubkey
    script_bytes.push(0x21); // PUSHBYTES_33
    script_bytes.push(0x02);
    script_bytes.extend([0xAA; 32]);

    // Fake pubkey (0x04 prefix)
    script_bytes.push(0x21);
    script_bytes.push(0x04);
    script_bytes.extend([0xBB; 32]);

    // Fake pubkey (0x00 prefix)
    script_bytes.push(0x21);
    script_bytes.push(0x00);
    script_bytes.extend([0xCC; 32]);

    script_bytes.push(0x53); // OP_3
    script_bytes.push(0xae); // OP_CHECKMULTISIG

    let outputs = vec![TxOut {
        value: Amount::from_sat(50000),
        script_pubkey: ScriptBuf::from(script_bytes),
    }];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let fake_regions: Vec<_> = verdict
        .dead_regions
        .iter()
        .filter(|r| r.dead_code_type == DeadCodeType::FakePubkey)
        .collect();
    assert_eq!(fake_regions.len(), 2); // 2 fake pubkeys
}

/// Test 7: Small OP_RETURN → Accept
#[test]
fn test_small_op_return_accept() {
    // OP_RETURN with 40 bytes of data (well under 83 limit)
    let mut script_bytes = vec![0x6a]; // OP_RETURN
    script_bytes.push(40); // PUSHBYTES_40
    script_bytes.extend(vec![0xAA; 40]);

    let outputs = vec![
        TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from(script_bytes),
        },
    ];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
}

/// Test 8: Oversized OP_RETURN → Corpse
#[test]
fn test_oversized_op_return() {
    // OP_RETURN with 200 bytes (over 83 limit)
    let mut script_bytes = vec![0x6a]; // OP_RETURN
    script_bytes.push(0x4c); // OP_PUSHDATA1
    script_bytes.push(200); // length
    script_bytes.extend(vec![0xBB; 200]);

    let outputs = vec![
        TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from(script_bytes),
        },
    ];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::OversizedOpReturn
    );
}

/// Test 9: Witness annex → Corpse
#[test]
fn test_witness_annex() {
    let mut witness = Witness::new();
    // Signature
    witness.push([0x30; 64]);
    // Tapscript (just OP_CHECKSIG)
    witness.push([0xac]);
    // Control block
    let mut cb = vec![0xc0];
    cb.extend([0x11; 32]);
    witness.push(&cb);
    // Annex: starts with 0x50
    let mut annex = vec![0x50];
    annex.extend(vec![0xDD; 99]);
    witness.push(&annex);

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    };
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let annex_regions: Vec<_> = verdict
        .dead_regions
        .iter()
        .filter(|r| r.dead_code_type == DeadCodeType::AnnexPresent)
        .collect();
    assert!(!annex_regions.is_empty());
}

/// Test 10: Encrypted inscription in envelope → Corpse
#[test]
fn test_encrypted_inscription() {
    // Same envelope structure but with encrypted/binary content
    let mut script: Vec<u8> = Vec::new();
    script.push(0x00); // OP_FALSE
    script.push(0x63); // OP_IF
    script.push(0x03); // PUSH3
    script.extend(b"ord");
    // Content type
    script.push(0x51); // OP_1
    let ct = b"application/octet-stream";
    script.push(ct.len() as u8);
    script.extend(ct);
    // Content: encrypted binary data
    script.push(0x00); // OP_0 (content marker)
    script.push(0x4c); // OP_PUSHDATA1
    script.push(128); // 128 bytes of encrypted data
    script.extend(vec![0xEE; 128]);
    script.push(0x68); // OP_ENDIF
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::InscriptionEnvelope
    );
}

/// Test 11: Legitimate conditional + dead envelope → Corpse
#[test]
fn test_legitimate_plus_dead_envelope() {
    // Script has a legitimate OP_IF branch followed by an inscription envelope
    let mut script: Vec<u8> = Vec::new();
    // Legitimate branch: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14);
    script.extend([0xAA; 20]);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    // Dead envelope after legitimate code
    script.push(0x00); // OP_FALSE
    script.push(0x63); // OP_IF
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68); // OP_ENDIF

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
}

/// Test 12: OP_PUSH(0x00) circumvention → Corpse
#[test]
fn test_push_0x00_circumvention() {
    // Instead of OP_0, attacker uses OP_PUSHBYTES_1 0x00 (which is also falsy)
    let mut script: Vec<u8> = Vec::new();
    script.push(0x01); // OP_PUSHBYTES_1
    script.push(0x00); // push value [0x00] — falsy
    script.push(0x63); // OP_IF
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68); // OP_ENDIF
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::InscriptionEnvelope
    );
}

// ─── Edge Cases ─────────────────────────────────────────────────────────────

/// Empty witness → Accept
#[test]
fn test_empty_witness() {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    };
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert_eq!(verdict.input_analyses[0].spend_type, "Empty");
}

/// Coinbase skip
#[test]
fn test_coinbase_skip() {
    let tx = coinbase_tx();
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert!(verdict.dead_regions.is_empty());
}

/// Moderate mode: under threshold → Accept
#[test]
fn test_moderate_under_threshold() {
    // Push 50 bytes + DROP (under moderate_max_dead_bytes=80)
    let mut script: Vec<u8> = Vec::new();
    // Small-ish data stuffing
    script.push(0x4c); // OP_PUSHDATA1
    script.push(50);
    script.extend(vec![0xAA; 50]);
    // Now we need a legitimate push + more code to lower the ratio
    // Actually, let's make a longer script so the ratio stays low
    for _ in 0..20 {
        script.push(0x51); // OP_1 (padding, legitimate nops basically)
    }
    // Now the data push is still there from before — wait, we need to ensure
    // we have a push >= min_drop_data_size. The default is 76, so 50 won't trigger.
    // Let's use 76.
    let mut script: Vec<u8> = Vec::new();
    script.push(0x4c); // OP_PUSHDATA1
    script.push(76);
    script.extend(vec![0xAA; 76]);
    script.push(0x75); // OP_DROP
    // Pad with legitimate code to keep ratio low
    for _ in 0..800 {
        script.push(0x51); // OP_1
    }
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::moderate();
    let verdict = analyze(&tx, &config);

    // Dead region = 78 bytes (76 data + pushdata1 opcode + length byte + DROP = 76+3 = 79... let me calculate)
    // The region is from push_offset to pos+1 (includes DROP).
    // push_offset = 0 (start of OP_PUSHDATA1), DROP is at 0+2+76=78, so region = 78-0+1 = 79
    // 79 < 80 (moderate_max_dead_bytes), AND ratio = 79/~879 ≈ 0.09 < 0.10
    assert!(verdict.is_accepted());
}

/// Moderate mode: over threshold → Corpse
#[test]
fn test_moderate_over_threshold() {
    // Push 100 bytes + DROP (over moderate_max_dead_bytes=80)
    let mut script: Vec<u8> = Vec::new();
    script.push(0x4c); // OP_PUSHDATA1
    script.push(100);
    script.extend(vec![0xAA; 100]);
    script.push(0x75); // OP_DROP
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::moderate();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
}

/// Monitor mode → MonitorOnly (never rejects)
#[test]
fn test_monitor_mode() {
    // Big inscription that would be Corpse in strict
    let mut script: Vec<u8> = Vec::new();
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68);
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::monitor();
    let verdict = analyze(&tx, &config);

    assert_eq!(verdict.verdict, Verdict::MonitorOnly);
    assert!(!verdict.dead_regions.is_empty()); // still detects, just doesn't reject
}

/// Nested IF depth tracking
#[test]
fn test_nested_if_depth() {
    // OP_FALSE OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_CHECKSIG
    let script = vec![0x00, 0x63, 0x63, 0x63, 0x68, 0x68, 0x68, 0xac];
    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    // Envelope should span from OP_FALSE to last OP_ENDIF (7 bytes)
    assert_eq!(verdict.dead_regions[0].size, 7);
}

/// Negative zero (0x80) circumvention
#[test]
fn test_negative_zero_circumvention() {
    // OP_PUSHBYTES_1 0x80 OP_IF ... — [0x80] is negative zero (falsy)
    let mut script: Vec<u8> = Vec::new();
    script.push(0x01); // OP_PUSHBYTES_1
    script.push(0x80); // negative zero
    script.push(0x63); // OP_IF
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68); // OP_ENDIF
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
}

/// Disabled config → Accept everything
#[test]
fn test_disabled_config() {
    let mut script: Vec<u8> = Vec::new();
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::disabled();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert!(verdict.dead_regions.is_empty());
}

/// P2WSH witness script detection
#[test]
fn test_p2wsh_dead_code() {
    // P2WSH with inscription envelope in witness script
    let mut ws: Vec<u8> = Vec::new();
    ws.push(0x00); // OP_FALSE
    ws.push(0x63); // OP_IF
    ws.push(0x03);
    ws.extend(b"ord");
    ws.push(0x68); // OP_ENDIF
    ws.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 72]; // DER signature
    let tx = tx_with_witness_script(&ws, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(verdict.input_analyses[0].spend_type, "P2WSH");
}

/// OP_2DROP data stuffing
#[test]
fn test_2drop_stuffing() {
    let mut script: Vec<u8> = Vec::new();
    // Push 100 bytes
    script.push(0x4c); // OP_PUSHDATA1
    script.push(100);
    script.extend(vec![0xDE; 100]);
    // OP_2DROP
    script.push(0x6d);
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::DropStuffing
    );
}

/// Config toggle: reject_inscription_envelope = false
#[test]
fn test_toggle_inscription_off() {
    let mut script: Vec<u8> = Vec::new();
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68);
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let mut config = ReaperConfig::strict();
    config.reject_inscription_envelope = false;
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
}

/// Config toggle: reject_drop_stuffing = false
#[test]
fn test_toggle_drop_off() {
    let mut script: Vec<u8> = Vec::new();
    script.push(0x4c);
    script.push(100);
    script.extend(vec![0xDE; 100]);
    script.push(0x75); // OP_DROP
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let mut config = ReaperConfig::strict();
    config.reject_drop_stuffing = false;
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
}

/// Verdict helper methods
#[test]
fn test_verdict_helpers() {
    let accept = ReaperVerdict::accept();
    assert!(accept.is_accepted());
    assert!(!accept.is_corpse());
}

/// Config serialization round-trip
#[test]
fn test_config_serde() {
    let config = ReaperConfig::strict();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: ReaperConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.mode, ReaperMode::Strict);
    assert!(deserialized.enabled);
}

/// ReaperVerdict serialization
#[test]
fn test_verdict_serde() {
    let verdict = ReaperVerdict::accept();
    let json = serde_json::to_string(&verdict).unwrap();
    assert!(json.contains("\"Accept\""));
}

/// SpendType display
#[test]
fn test_spend_type_display() {
    let keypath = SpendType::P2trKeyPath;
    assert_eq!(keypath.to_string(), "P2TR-keypath");

    let script_path = SpendType::P2trScriptPath {
        tapscript: vec![],
        control_block: vec![],
    };
    assert_eq!(script_path.to_string(), "P2TR-scriptpath");

    let wsh = SpendType::P2wsh {
        witness_script: vec![],
    };
    assert_eq!(wsh.to_string(), "P2WSH");
}

/// Multiple dead code regions in single transaction
#[test]
fn test_multiple_dead_regions() {
    // Script with both inscription envelope AND drop stuffing
    let mut script: Vec<u8> = Vec::new();
    // Drop stuffing first
    script.push(0x4c);
    script.push(80);
    script.extend(vec![0xAA; 80]);
    script.push(0x75); // OP_DROP
    // Then inscription envelope
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68);
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(verdict.dead_regions.len(), 2);
}

/// OP_NOTIF increases envelope depth
#[test]
fn test_notif_in_envelope() {
    // OP_FALSE OP_IF OP_NOTIF OP_ENDIF OP_ENDIF OP_CHECKSIG
    let script = vec![0x00, 0x63, 0x64, 0x68, 0x68, 0xac];
    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::strict();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(verdict.dead_regions[0].size, 5); // OP_FALSE through second OP_ENDIF
}

use crate::verdict::ReaperVerdict;

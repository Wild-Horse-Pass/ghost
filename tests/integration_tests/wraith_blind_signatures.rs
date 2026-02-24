//! Category 10b: Wraith Blind Signature System Tests (20 tests, 730-749)
//!
//! Tests for the Schnorr blind signature subsystem of wraith-protocol:
//! - CoordinatorSigner creation and key management
//! - Nonce lifecycle and rate limiting
//! - End-to-end blind signature flow
//! - Key rotation, cleanup, and participant isolation

use wraith_protocol::{
    BlindingContext, CoordinatorSigner, CoordinatorSignerConfig, TokenVerifier, UnblindedToken,
};

// =============================================================================
// SIGNER CREATION TESTS (Tests 730-734)
// =============================================================================

#[test]
fn test_730_coordinator_signer_new_succeeds_with_nonzero_key_id() {
    let session_id = [1u8; 32];
    let signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");

    // key_id should not be all zeros (it is a SHA-256 hash of session_id + pubkey)
    assert_ne!(signer.key_id(), &[0u8; 32], "key_id must not be all zeros");
}

#[test]
fn test_731_from_bytes_restores_signer_with_same_key_id() {
    let session_id = [3u8; 32];
    let key_bytes: [u8; 32] = [
        42, 17, 93, 55, 128, 7, 201, 64, 33, 88, 12, 77, 111, 254, 19, 200, 45, 66, 130, 91, 8,
        176, 215, 39, 101, 144, 58, 23, 187, 69, 243, 11,
    ];

    let signer1 =
        CoordinatorSigner::from_bytes(&key_bytes, &session_id).expect("from_bytes should succeed");
    let signer2 =
        CoordinatorSigner::from_bytes(&key_bytes, &session_id).expect("from_bytes should succeed");

    // Same key bytes + same session_id should produce same key_id
    assert_eq!(
        signer1.key_id(),
        signer2.key_id(),
        "from_bytes with same inputs must produce identical key_id"
    );
}

#[test]
fn test_732_different_sessions_produce_different_key_ids() {
    let session_a = [10u8; 32];
    let session_b = [20u8; 32];

    let signer_a = CoordinatorSigner::new(&session_a).expect("new() should succeed");
    let signer_b = CoordinatorSigner::new(&session_b).expect("new() should succeed");

    // Different sessions generate different random keys, so key_ids differ
    assert_ne!(
        signer_a.key_id(),
        signer_b.key_id(),
        "Different sessions should have different key_ids"
    );
}

#[test]
fn test_733_with_config_accepts_custom_grace_period() {
    let session_id = [4u8; 32];
    let config = CoordinatorSignerConfig {
        grace_period_secs: 3600, // 1 hour instead of default 7 days
    };

    let signer =
        CoordinatorSigner::with_config(&session_id, config).expect("with_config should succeed");

    // Signer should be functional with custom config
    assert_ne!(signer.key_id(), &[0u8; 32]);
    assert_eq!(signer.active_nonce_count(), 0);
}

#[test]
fn test_734_public_key_returns_valid_33_byte_compressed_key() {
    let session_id = [5u8; 32];
    let signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");

    let pubkey = signer.public_key();
    let serialized = pubkey.serialize();

    // Compressed public key must be exactly 33 bytes
    assert_eq!(serialized.len(), 33);

    // First byte of compressed key must be 0x02 or 0x03
    assert!(
        serialized[0] == 0x02 || serialized[0] == 0x03,
        "Compressed pubkey prefix must be 0x02 or 0x03, got 0x{:02x}",
        serialized[0]
    );
}

// =============================================================================
// NONCE MANAGEMENT TESTS (Tests 735-739)
// =============================================================================

#[test]
fn test_735_create_nonce_returns_public_nonce_with_session_id() {
    let session_id = [6u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");

    let nonce = signer
        .create_nonce_for_participant("ghost_1")
        .expect("create_nonce_for_participant should succeed");

    // The nonce should have a valid session_id (derived from nonce point + ghost_id)
    assert_ne!(
        nonce.session_id, [0u8; 32],
        "Nonce session_id must not be all zeros"
    );

    // The nonce_point should be a valid 33-byte compressed point
    assert_eq!(nonce.nonce_point.len(), 33);
    assert!(
        nonce.nonce_point[0] == 0x02 || nonce.nonce_point[0] == 0x03,
        "Nonce point prefix must be 0x02 or 0x03"
    );
}

#[test]
fn test_736_multiple_nonces_for_same_participant_have_different_points() {
    let session_id = [7u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");

    let nonce_a = signer
        .create_nonce_for_participant("ghost_1")
        .expect("first nonce should succeed");
    let nonce_b = signer
        .create_nonce_for_participant("ghost_1")
        .expect("second nonce should succeed");

    // Each nonce uses a fresh random k, so R = k*G must differ
    assert_ne!(
        nonce_a.nonce_point, nonce_b.nonce_point,
        "Multiple nonces for the same participant must have different nonce_points"
    );

    // Session IDs should also differ (each nonce gets unique session binding)
    assert_ne!(
        nonce_a.session_id, nonce_b.session_id,
        "Multiple nonces must have different session_ids"
    );
}

#[test]
fn test_737_active_nonce_count_increments() {
    let session_id = [8u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");

    assert_eq!(signer.active_nonce_count(), 0);

    signer
        .create_nonce_for_participant("ghost_a")
        .expect("nonce 1");
    assert_eq!(signer.active_nonce_count(), 1);

    signer
        .create_nonce_for_participant("ghost_b")
        .expect("nonce 2");
    assert_eq!(signer.active_nonce_count(), 2);

    signer
        .create_nonce_for_participant("ghost_a")
        .expect("nonce 3");
    assert_eq!(signer.active_nonce_count(), 3);
}

#[test]
fn test_738_nonces_per_participant_tracks_counts() {
    let session_id = [9u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");

    signer
        .create_nonce_for_participant("alice")
        .expect("alice nonce 1");
    signer
        .create_nonce_for_participant("alice")
        .expect("alice nonce 2");
    signer
        .create_nonce_for_participant("bob")
        .expect("bob nonce 1");

    let counts = signer.nonces_per_participant();
    assert_eq!(
        counts.get("alice").copied(),
        Some(2),
        "alice should have 2 nonces"
    );
    assert_eq!(
        counts.get("bob").copied(),
        Some(1),
        "bob should have 1 nonce"
    );
    assert_eq!(counts.get("charlie"), None, "charlie should have no nonces");
}

#[test]
fn test_739_clear_nonces_resets_to_zero() {
    let session_id = [10u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");

    signer
        .create_nonce_for_participant("ghost_1")
        .expect("nonce 1");
    signer
        .create_nonce_for_participant("ghost_2")
        .expect("nonce 2");
    assert_eq!(signer.active_nonce_count(), 2);

    signer.clear_nonces();

    assert_eq!(
        signer.active_nonce_count(),
        0,
        "active_nonce_count must be 0 after clear_nonces()"
    );
    assert!(
        signer.nonces_per_participant().is_empty(),
        "nonces_per_participant must be empty after clear_nonces()"
    );
}

// =============================================================================
// END-TO-END BLIND SIGNATURE TESTS (Tests 740-744)
// =============================================================================

#[test]
fn test_740_blinding_context_new_succeeds() {
    let session_id = [11u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");
    let nonce = signer
        .create_nonce_for_participant("participant_1")
        .expect("nonce should succeed");

    let message = b"test output address".to_vec();
    let context = BlindingContext::new(message, signer.public_key(), &nonce);
    assert!(
        context.is_ok(),
        "BlindingContext::new should succeed with valid inputs"
    );
}

#[test]
fn test_741_blinded_challenge_session_id_matches_nonce() {
    let session_id = [12u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");
    let nonce = signer
        .create_nonce_for_participant("participant_1")
        .expect("nonce should succeed");

    let nonce_session_id = nonce.session_id;

    let message = b"output address bytes".to_vec();
    let context =
        BlindingContext::new(message, signer.public_key(), &nonce).expect("context should succeed");

    let blinded_challenge = context
        .create_blinded_challenge()
        .expect("blinded challenge should succeed");

    assert_eq!(
        blinded_challenge.session_id, nonce_session_id,
        "Blinded challenge session_id must match the nonce session_id"
    );
}

#[test]
fn test_742_sign_blinded_challenge_returns_response() {
    let session_id = [13u8; 32];
    let participant = "ghost_signer_test";
    let mut signer = CoordinatorSigner::new(&session_id).expect("new() should succeed");
    let nonce = signer
        .create_nonce_for_participant(participant)
        .expect("nonce should succeed");

    let message = b"address to sign".to_vec();
    let context =
        BlindingContext::new(message, signer.public_key(), &nonce).expect("context should succeed");

    let blinded_challenge = context
        .create_blinded_challenge()
        .expect("blinded challenge should succeed");

    let response = signer.sign_blinded_challenge_for_participant(&blinded_challenge, participant);
    assert!(
        response.is_ok(),
        "sign_blinded_challenge_for_participant should succeed"
    );

    let response = response.unwrap();
    // Signature scalar should not be all zeros
    assert_ne!(
        response.signature_scalar, [0u8; 32],
        "Signature scalar must not be all zeros"
    );
    assert_eq!(
        response.session_id, blinded_challenge.session_id,
        "Response session_id must match challenge session_id"
    );
}

#[test]
fn test_743_full_blind_signature_flow_sign_unblind_verify() {
    let session_id = [14u8; 32];
    let participant = "full_flow_participant";
    let message = b"my secret output address for wraith mixing".to_vec();

    // Step 1: Coordinator creates signer and issues nonce for participant
    let mut signer = CoordinatorSigner::new(&session_id).expect("signer creation");
    let coordinator_pubkey = *signer.public_key();
    let key_id = *signer.key_id();
    let nonce = signer
        .create_nonce_for_participant(participant)
        .expect("nonce creation");

    // Step 2: Participant creates blinding context and blinded challenge
    let context = BlindingContext::new(message.clone(), &coordinator_pubkey, &nonce)
        .expect("blinding context");
    let blinded_challenge = context
        .create_blinded_challenge()
        .expect("blinded challenge");

    // Step 3: Coordinator signs the blinded challenge
    let response = signer
        .sign_blinded_challenge_for_participant(&blinded_challenge, participant)
        .expect("signing");

    // Step 4: Participant unblinds the response
    let token = context.unblind(&response, key_id).expect("unblinding");

    // Step 5: Verify with the coordinator's own verify_signature
    assert!(
        signer.verify_signature(&token).expect("verification"),
        "Coordinator verify_signature must accept valid token"
    );

    // Step 6: Verify with an independent TokenVerifier (as another node would)
    let verifier = TokenVerifier::new(coordinator_pubkey, &session_id);
    assert!(
        verifier.verify(&token).expect("token verifier"),
        "TokenVerifier must accept valid token"
    );

    // Step 7: Confirm the message round-trips correctly
    assert_eq!(
        token.message, message,
        "Token message must match original message"
    );
}

#[test]
fn test_744_tampered_token_fails_verification() {
    let session_id = [15u8; 32];
    let participant = "tamper_test";
    let message = b"legitimate address".to_vec();

    // Full signing flow
    let mut signer = CoordinatorSigner::new(&session_id).expect("signer");
    let coordinator_pubkey = *signer.public_key();
    let key_id = *signer.key_id();
    let nonce = signer
        .create_nonce_for_participant(participant)
        .expect("nonce");
    let context =
        BlindingContext::new(message, &coordinator_pubkey, &nonce).expect("blinding context");
    let blinded_challenge = context.create_blinded_challenge().expect("challenge");
    let response = signer
        .sign_blinded_challenge_for_participant(&blinded_challenge, participant)
        .expect("signing");
    let token = context.unblind(&response, key_id).expect("unblind");

    // Verify it works first
    let schnorr_bytes = token.to_schnorr_bytes().expect("schnorr conversion");
    assert_eq!(schnorr_bytes.len(), 64);

    // Tamper with the signature scalar
    let mut tampered_token = UnblindedToken {
        message: token.message.clone(),
        nonce_point: token.nonce_point,
        signature_scalar: token.signature_scalar,
        session_key_id: token.session_key_id,
    };
    // Flip a byte in the signature scalar
    tampered_token.signature_scalar[0] ^= 0xFF;

    // Verification should fail or reject the tampered token
    let verifier = TokenVerifier::new(coordinator_pubkey, &session_id);
    let result = verifier.verify(&tampered_token);
    match result {
        Ok(valid) => assert!(!valid, "Tampered token must not verify as valid"),
        Err(_) => {
            // An error (e.g., invalid scalar) is also acceptable for tampered data
        }
    }
}

// =============================================================================
// KEY ROTATION & CLEANUP TESTS (Tests 745-749)
// =============================================================================

#[test]
fn test_745_rotate_key_produces_new_key_id_preserves_old() {
    let session_id = [16u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("signer");

    let original_key_id = *signer.key_id();
    let original_pubkey = *signer.public_key();

    let new_pubkey = signer.rotate_key().expect("rotation should succeed");

    // New key ID must differ from original
    assert_ne!(
        signer.key_id(),
        &original_key_id,
        "key_id must change after rotation"
    );

    // New public key must differ from original
    assert_ne!(
        new_pubkey, original_pubkey,
        "public_key must change after rotation"
    );

    // Previous key should be preserved in grace period
    assert!(
        signer.previous_key_count() > 0,
        "Old key must be preserved after rotation"
    );
}

#[test]
fn test_746_previous_key_count_increments_after_rotation() {
    let session_id = [17u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("signer");

    assert_eq!(signer.previous_key_count(), 0, "No previous keys initially");

    signer.rotate_key().expect("first rotation");
    assert_eq!(
        signer.previous_key_count(),
        1,
        "One previous key after first rotation"
    );

    signer.rotate_key().expect("second rotation");
    assert_eq!(
        signer.previous_key_count(),
        2,
        "Two previous keys after second rotation"
    );

    signer.rotate_key().expect("third rotation");
    assert_eq!(
        signer.previous_key_count(),
        3,
        "Three previous keys after third rotation"
    );
}

#[test]
fn test_747_cleanup_expired_nonces_returns_count() {
    let session_id = [18u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("signer");

    // Create some nonces
    signer
        .create_nonce_for_participant("ghost_a")
        .expect("nonce a");
    signer
        .create_nonce_for_participant("ghost_b")
        .expect("nonce b");
    assert_eq!(signer.active_nonce_count(), 2);

    // Freshly created nonces should not be expired (nonce expiry is 1 hour)
    let cleaned = signer.cleanup_expired_nonces();
    assert_eq!(
        cleaned, 0,
        "Freshly created nonces should not be cleaned up"
    );

    // Nonce count should remain the same
    assert_eq!(
        signer.active_nonce_count(),
        2,
        "Non-expired nonces must remain"
    );
}

#[test]
fn test_748_nonce_bound_to_participant_a_rejects_signing_by_participant_b() {
    let session_id = [19u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("signer");

    // Create nonce bound to alice
    let nonce = signer
        .create_nonce_for_participant("alice")
        .expect("nonce for alice");

    // Build blinding context (any participant can create one from the public nonce)
    let message = b"alice output address".to_vec();
    let context =
        BlindingContext::new(message, signer.public_key(), &nonce).expect("blinding context");
    let blinded_challenge = context.create_blinded_challenge().expect("challenge");

    // Bob tries to sign with alice's nonce - should be rejected
    let result = signer.sign_blinded_challenge_for_participant(&blinded_challenge, "bob");
    assert!(
        result.is_err(),
        "Signing with a nonce bound to a different participant must fail"
    );

    // Alice should still be able to sign (nonce was NOT consumed on Bob's failed attempt)
    let result = signer.sign_blinded_challenge_for_participant(&blinded_challenge, "alice");
    assert!(
        result.is_ok(),
        "Original bound participant should still be able to sign"
    );
}

#[test]
fn test_749_multiple_participants_get_independent_nonces_and_signatures() {
    let session_id = [20u8; 32];
    let mut signer = CoordinatorSigner::new(&session_id).expect("signer");
    let coordinator_pubkey = *signer.public_key();
    let key_id = *signer.key_id();

    let participants = ["alice", "bob", "charlie"];
    let messages: Vec<Vec<u8>> = vec![
        b"alice_output_address".to_vec(),
        b"bob_output_address".to_vec(),
        b"charlie_output_address".to_vec(),
    ];

    // Issue nonces for all participants
    let nonces: Vec<_> = participants
        .iter()
        .map(|p| {
            signer
                .create_nonce_for_participant(p)
                .expect("nonce creation")
        })
        .collect();

    assert_eq!(signer.active_nonce_count(), 3);

    // Each participant creates blinding context and challenge
    let contexts: Vec<_> = messages
        .iter()
        .zip(nonces.iter())
        .map(|(msg, nonce)| {
            BlindingContext::new(msg.clone(), &coordinator_pubkey, nonce).expect("blinding context")
        })
        .collect();

    let challenges: Vec<_> = contexts
        .iter()
        .map(|ctx| ctx.create_blinded_challenge().expect("challenge"))
        .collect();

    // Coordinator signs each challenge for the correct participant
    let responses: Vec<_> = challenges
        .iter()
        .zip(participants.iter())
        .map(|(challenge, participant)| {
            signer
                .sign_blinded_challenge_for_participant(challenge, participant)
                .expect("signing")
        })
        .collect();

    // All nonces should be consumed
    assert_eq!(
        signer.active_nonce_count(),
        0,
        "All nonces should be consumed after signing"
    );

    // Each participant unblinds and gets a valid token
    let tokens: Vec<_> = contexts
        .iter()
        .zip(responses.iter())
        .map(|(ctx, resp)| ctx.unblind(resp, key_id).expect("unblind"))
        .collect();

    // Verify each token independently
    let verifier = TokenVerifier::new(coordinator_pubkey, &session_id);
    for (i, token) in tokens.iter().enumerate() {
        assert!(
            verifier.verify(token).expect("verification"),
            "Token for participant {} must verify",
            participants[i]
        );
        assert_eq!(
            token.message, messages[i],
            "Token message for participant {} must match",
            participants[i]
        );
    }

    // Signatures should all be distinct (unlinkability)
    assert_ne!(
        tokens[0].signature_scalar, tokens[1].signature_scalar,
        "alice and bob signatures must differ"
    );
    assert_ne!(
        tokens[1].signature_scalar, tokens[2].signature_scalar,
        "bob and charlie signatures must differ"
    );
    assert_ne!(
        tokens[0].nonce_point, tokens[1].nonce_point,
        "alice and bob nonce points must differ"
    );
}

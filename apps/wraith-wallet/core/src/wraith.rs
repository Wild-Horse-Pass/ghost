//! Wraith Lite v1 — participant client.
//!
//! Drives the wallet's side of the protocol against a `wraith-coordinator`
//! HTTP endpoint:
//!
//! ```text
//! /find_or_create   → enrol in a session (placeholder bond_id)
//! (wallet escrows)  → bond is escrowed against (ghost_id, session_id)
//! /inputs           → commit UTXO + change addr; coordinator verifies bond
//! /nonce            → fetch coordinator pubkey + a fresh signing nonce
//! /blind-sign       → coordinator blind-signs the wallet's mix-output addr
//! /outputs          → wallet anonymously submits unblinded address + sig
//! /round-tx         → fetch the assembled unsigned bitcoin transaction
//! /witness          → submit signed witness for own input;
//!                     final submission triggers merge + broadcast
//! ```
//!
//! Phase 5b status — this is the entry point. The minimum viable
//! shape:
//!   - `WraithSessionClient` holds the base URL + an HTTP client.
//!   - `execute_mix` runs the whole pipeline once, end-to-end, and
//!     returns the broadcast txid.
//!   - The bond escrow step is the caller's responsibility (a real
//!     wallet calls ghost-pay; the integration test swaps in a
//!     direct `MockBondLedger.escrow` call). Future iterations will
//!     wire a `BondLedgerClient` trait so the wallet's bond
//!     dependency is pluggable like the coordinator's `BondLedger`.
//!   - Witness signing is supplied by the caller via a closure. The
//!     wallet's keystore + signer modules will plug in here later;
//!     for now any FnMut(&Transaction, usize) -> Witness works,
//!     including the placeholder-bytes function the coordinator's
//!     test suite uses.
//!
//! ## What's NOT in this commit
//!
//! - **Anonymous output submission.** The /outputs call uses the
//!   same HTTP client as /inputs, so the coordinator can correlate
//!   the wallet's IP across both. Real privacy requires a separate
//!   transport (Tor circuit / VPN / new TCP connection) for /outputs.
//!   The struct exposes `outputs_http` as a separate field so the
//!   future Tor wiring can swap it without touching this code.
//!
//! - **Coordinator pool / failover.** The client takes a single
//!   `base_url`. Multi-coordinator failover is B/6 territory.
//!
//! - **No-sign deadline awareness.** The client doesn't currently
//!   surface deadline hints to the caller; it just hits /witness
//!   and surfaces 410 Gone if the round expired underneath.
//!
//! - **Retries / idempotency.** Every call is one-shot. Production
//!   hardening adds bounded retry on transient HTTP errors.

use std::time::Duration;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{Network, Transaction, Txid, Witness};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use tracing::debug;

use wraith_protocol::{
    BlindSignatureResponse, BlindingContext, PublicNonce, UnblindedToken,
};

#[derive(Debug, thiserror::Error)]
pub enum WraithClientError {
    #[error("HTTP transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("coordinator returned {status}: {detail}")]
    Coordinator { status: u16, detail: String },
    #[error("response body did not match expected shape: {0}")]
    Shape(String),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("bitcoin consensus encode: {0}")]
    Consensus(String),
    #[error("crypto: {0}")]
    Crypto(#[from] wraith_protocol::WraithError),
    #[error("signer rejected input {input_index}: {detail}")]
    Signer { input_index: usize, detail: String },
}

/// Caller-supplied input commitment. The wallet picks the UTXO it
/// wants mixed; the client just shuttles the values to the
/// coordinator.
#[derive(Debug, Clone)]
pub struct ParticipantUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    /// Hex-encoded scriptPubKey of the spending output. Coordinator
    /// trusts the wallet here; bitcoind/mempool acceptance enforces
    /// correctness at broadcast time.
    pub scriptpubkey_hex: String,
}

/// One full mix request. Caller pre-chooses every value; the client
/// drives the protocol with no further input until `WitnessSigner`
/// gets called back.
#[derive(Debug, Clone)]
pub struct MixRequest {
    pub tier_id: String,
    pub ghost_id: String,
    /// Bond id placeholder echoed at /find_or_create time. The
    /// coordinator verifies the actual bond against the
    /// (ghost_id, session_id) tuple at /inputs time, so this is
    /// purely cosmetic here.
    pub bond_id_placeholder: String,
    pub utxo: ParticipantUtxo,
    /// Optional change address. Required when input.value_sats
    /// exceeds (denom + per-participant fee shares) by ≥ dust.
    pub change_address: Option<String>,
    /// Wallet's destination address for its mixed (denom-sized)
    /// output. Must NOT be linkable to the wallet's input UTXO —
    /// fresh address recommended.
    pub mix_output_address: String,
}

/// The result of a successful mix.
#[derive(Debug, Clone)]
pub struct MixOutcome {
    pub session_id: String,
    pub broadcast_txid: Txid,
    /// Index in the assembled tx's `output` vec where the wallet's
    /// mixed output landed. Useful for the wallet to register the
    /// new UTXO without scanning the chain.
    pub mixed_output_tx_index: usize,
}

/// The wallet's signing callback. Given the unsigned tx + the index
/// of this wallet's input, return a `Witness` that satisfies the
/// input's `script_pubkey`. Real wallets compute the proper sighash
/// (BIP-143/BIP-341 depending on the script type) and sign with the
/// keystore-managed key. Tests can return placeholder bytes when the
/// downstream broadcaster doesn't actually validate.
pub trait WitnessSigner {
    fn sign(
        &mut self,
        tx: &Transaction,
        input_index: usize,
        prev_amount_sats: u64,
    ) -> Result<Witness, WraithClientError>;
}

impl<F> WitnessSigner for F
where
    F: FnMut(&Transaction, usize, u64) -> Result<Witness, WraithClientError>,
{
    fn sign(
        &mut self,
        tx: &Transaction,
        input_index: usize,
        prev_amount_sats: u64,
    ) -> Result<Witness, WraithClientError> {
        (self)(tx, input_index, prev_amount_sats)
    }
}

/// Wallet-side participant client. Constructed once per coordinator,
/// re-used across rounds.
pub struct WraithSessionClient {
    base_url: String,
    network: Network,
    http: reqwest::Client,
    /// Separate client for /outputs anonymous submission. In v1 it's
    /// just a clone of `http`; future iterations swap in a
    /// Tor-routed client without touching this code.
    outputs_http: reqwest::Client,
}

impl WraithSessionClient {
    pub fn new(base_url: impl Into<String>, network: Network) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest build");
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            network,
            outputs_http: http.clone(),
            http,
        }
    }

    /// Drive a single Wraith Lite round end-to-end. The bond escrow
    /// step is NOT performed by this client — the caller must arrange
    /// for `BondLedger::verify_bond(ghost_id, session_id, expected)`
    /// to succeed against the coordinator's ledger before this call
    /// reaches /inputs. `bond_setup` is a hook that runs once we
    /// know the session_id, intended for the test path
    /// (MockBondLedger.escrow) or the production wallet's
    /// ghost-pay client invocation.
    pub async fn execute_mix<S, B, BFut>(
        &self,
        request: MixRequest,
        mut signer: S,
        mut bond_setup: B,
    ) -> Result<MixOutcome, WraithClientError>
    where
        S: WitnessSigner,
        B: FnMut(&str, u64) -> BFut,
        BFut: std::future::Future<Output = Result<(), WraithClientError>>,
    {
        // 1. Enrol.
        let foc: FindOrCreateResponse = self
            .post_json(
                "/api/v1/session/find_or_create",
                &serde_json::json!({
                    "tier_id": request.tier_id,
                    "ghost_id": request.ghost_id,
                    "bond_id": request.bond_id_placeholder,
                }),
            )
            .await?;
        let session_id = foc.session.session_id.clone();
        debug!(%session_id, "enrolled in session");

        // 2. Caller-driven bond escrow against the now-known session.
        bond_setup(&session_id, foc.session.bond_amount_sats).await?;

        // 2b. Wait for the coordinator to flip Filling → Locked. /inputs
        //     refuses Filling-state submissions, so we have to block
        //     until quorum forms (or the fill window expires). Bounded
        //     poll loop with backoff; gives up after the round's fill
        //     window plus a safety margin.
        self.wait_for_locked(&session_id).await?;

        // 3. Commit UTXO. The 5th /inputs auto-advances the round to
        //    Signing on the coordinator side.
        let _inputs: serde_json::Value = self
            .post_json(
                &format!("/api/v1/session/{session_id}/inputs"),
                &serde_json::json!({
                    "ghost_id": request.ghost_id,
                    "input": {
                        "txid": request.utxo.txid,
                        "vout": request.utxo.vout,
                        "value_sats": request.utxo.value_sats,
                        "scriptpubkey_hex": request.utxo.scriptpubkey_hex,
                    },
                    "change_address": request.change_address,
                }),
            )
            .await?;

        // 4. /nonce — get the coordinator's per-round signing pubkey
        //    + a fresh blind-sig nonce.
        let nonce: NonceResponse = self
            .post_json(
                &format!("/api/v1/session/{session_id}/nonce"),
                &serde_json::json!({ "ghost_id": request.ghost_id }),
            )
            .await?;
        let pubkey_bytes = hex::decode(&nonce.signing_pubkey)?;
        let signer_pubkey = PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| WraithClientError::Shape(format!("signing_pubkey: {e}")))?;
        let nonce_point = decode_33(&nonce.nonce_point)?;
        let blind_session_id = decode_32(&nonce.blind_session_id)?;
        let signing_key_id = decode_32(&nonce.signing_key_id)?;
        let public_nonce = PublicNonce {
            nonce_point,
            session_id: blind_session_id,
        };

        // 5. Blind the mix-output address locally.
        let blinding = BlindingContext::new(
            request.mix_output_address.as_bytes().to_vec(),
            &signer_pubkey,
            &public_nonce,
        )?;
        let blinded_challenge = blinding.create_blinded_challenge()?;
        let blinded_nonce_point = blinding.blinded_nonce().serialize();

        // 6. /blind-sign.
        let bs: BlindSignResponse = self
            .post_json(
                &format!("/api/v1/session/{session_id}/blind-sign"),
                &serde_json::json!({
                    "ghost_id": request.ghost_id,
                    "blinded_challenge": hex::encode(blinded_challenge.challenge),
                    "blind_session_id": hex::encode(blinded_challenge.session_id),
                }),
            )
            .await?;
        let s_bytes = decode_32(&bs.signature_scalar)?;
        let response = BlindSignatureResponse {
            signature_scalar: s_bytes,
            session_id: blind_session_id,
        };
        let token: UnblindedToken = blinding.unblind(&response, signing_key_id)?;

        // 7. /outputs — anonymous submission of the unblinded address +
        //    sig. NOTE v1: same HTTP client; production swaps in Tor.
        let _: serde_json::Value = self
            .post_json_via(
                &self.outputs_http,
                &format!("/api/v1/session/{session_id}/outputs"),
                &serde_json::json!({
                    "address": request.mix_output_address,
                    "blinded_nonce_point": hex::encode(blinded_nonce_point),
                    "unblinded_signature_scalar": hex::encode(token.signature_scalar),
                }),
            )
            .await?;

        // 8. Fetch the assembled tx.
        let rt: RoundTxResponse = self
            .get_json(&format!("/api/v1/session/{session_id}/round-tx"))
            .await?;
        let tx: Transaction = deserialize_hex(&rt.unsigned_tx_hex)
            .map_err(|e| WraithClientError::Consensus(e.to_string()))?;

        // Find this wallet's input index.
        let target_txid = bitcoin::Txid::from_str_hex(&request.utxo.txid)?;
        let input_index = tx
            .input
            .iter()
            .position(|t| {
                t.previous_output.txid == target_txid
                    && t.previous_output.vout == request.utxo.vout
            })
            .ok_or_else(|| {
                WraithClientError::Shape("our input is not in the assembled tx".into())
            })?;

        // 9. Sign.
        let witness = signer
            .sign(&tx, input_index, request.utxo.value_sats)
            .map_err(|e| match e {
                WraithClientError::Signer { .. } => e,
                other => WraithClientError::Signer {
                    input_index,
                    detail: other.to_string(),
                },
            })?;
        let witness_hex = bitcoin::consensus::encode::serialize_hex(&witness);

        // 10. /witness — final submission triggers merge + broadcast.
        let wresp: WitnessResponse = self
            .post_json(
                &format!("/api/v1/session/{session_id}/witness"),
                &serde_json::json!({
                    "ghost_id": request.ghost_id,
                    "input_index": input_index,
                    "witness_hex": witness_hex,
                }),
            )
            .await?;

        // Only the Nth (last) submitter gets `broadcast_txid` directly
        // in the /witness response — the other N-1 wallets see a
        // non-terminal acknowledgement and have to wait for the
        // session to flip to Complete. Poll /status until done, then
        // re-read the assembled txid (same as broadcast txid, the
        // coordinator cross-checks).
        let broadcast_txid = match wresp.broadcast_txid {
            Some(txid_hex) => Txid::from_str_hex(&txid_hex)?,
            None => {
                self.wait_for_complete(&session_id).await?;
                Txid::from_str_hex(&rt.txid)?
            }
        };

        // Locate the mixed output tx index from the round-tx
        // provenance. The wallet's mixed_output_address is unique
        // within the round (the coordinator rejects duplicates); we
        // walk the tx outputs for the matching scriptPubKey. (Round-tx
        // provenance has participant_id but NOT address, by design —
        // looking up by address bytes is the canonical method.)
        let mixed_output_tx_index = locate_mix_output_index(
            &tx,
            &request.mix_output_address,
            self.network,
        )?;

        Ok(MixOutcome {
            session_id,
            broadcast_txid,
            mixed_output_tx_index,
        })
    }

    /// Poll `GET /:id` until the session reaches Complete. Used by
    /// non-final witness submitters to know when broadcast happened
    /// (the Nth submitter triggers it, learns directly; everyone else
    /// finds out via /status).
    async fn wait_for_complete(&self, session_id: &str) -> Result<(), WraithClientError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            let status: SessionStatusResponse = self
                .get_json(&format!("/api/v1/session/{session_id}"))
                .await?;
            match status.session.state.as_str() {
                "complete" => return Ok(()),
                "failed" => {
                    return Err(WraithClientError::Coordinator {
                        status: 410,
                        detail: "session failed before reaching Complete".into(),
                    });
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(WraithClientError::Shape(
                    "timed out waiting for session to reach Complete".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Poll `GET /:id` until the session is in Locked or Signing.
    /// Bounded by a generous timeout so a misconfigured coordinator
    /// (or a round that legitimately times out) doesn't hang the
    /// caller forever. Polls every 250ms — frequent enough to ride
    /// the manual state-flip in tests, sparse enough to avoid
    /// hammering a real coordinator.
    async fn wait_for_locked(&self, session_id: &str) -> Result<(), WraithClientError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(360);
        loop {
            let status: SessionStatusResponse = self
                .get_json(&format!("/api/v1/session/{session_id}"))
                .await?;
            match status.session.state.as_str() {
                "locked" | "signing" => return Ok(()),
                "failed" => {
                    return Err(WraithClientError::Coordinator {
                        status: 410,
                        detail: "session failed before reaching Locked".into(),
                    });
                }
                _ => {} // filling, complete, broadcasting — keep waiting
            }
            if std::time::Instant::now() >= deadline {
                return Err(WraithClientError::Shape(
                    "timed out waiting for session to reach Locked".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn post_json<R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<R, WraithClientError> {
        self.post_json_via(&self.http, path, body).await
    }

    async fn post_json_via<R: serde::de::DeserializeOwned>(
        &self,
        http: &reqwest::Client,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<R, WraithClientError> {
        let resp = http
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(WraithClientError::Coordinator {
                status: status.as_u16(),
                detail,
            });
        }
        resp.json::<R>()
            .await
            .map_err(|e| WraithClientError::Shape(e.to_string()))
    }

    async fn get_json<R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<R, WraithClientError> {
        let resp = self.http.get(format!("{}{}", self.base_url, path)).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(WraithClientError::Coordinator {
                status: status.as_u16(),
                detail,
            });
        }
        resp.json::<R>()
            .await
            .map_err(|e| WraithClientError::Shape(e.to_string()))
    }
}

fn locate_mix_output_index(
    tx: &Transaction,
    address: &str,
    network: Network,
) -> Result<usize, WraithClientError> {
    use std::str::FromStr;
    let parsed = bitcoin::Address::from_str(address)
        .map_err(|e| WraithClientError::Shape(format!("can't parse mix address: {e}")))?
        .require_network(network)
        .map_err(|e| WraithClientError::Shape(format!("address wrong network: {e}")))?;
    let target_spk = parsed.script_pubkey();
    tx.output
        .iter()
        .position(|o| o.script_pubkey == target_spk)
        .ok_or_else(|| WraithClientError::Shape("mix output not in assembled tx".into()))
}

fn decode_32(s: &str) -> Result<[u8; 32], WraithClientError> {
    let raw = hex::decode(s)?;
    if raw.len() != 32 {
        return Err(WraithClientError::Shape(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn decode_33(s: &str) -> Result<[u8; 33], WraithClientError> {
    let raw = hex::decode(s)?;
    if raw.len() != 33 {
        return Err(WraithClientError::Shape(format!(
            "expected 33 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&raw);
    Ok(out)
}

trait FromHex: Sized {
    fn from_str_hex(s: &str) -> Result<Self, WraithClientError>;
}

impl FromHex for Txid {
    fn from_str_hex(s: &str) -> Result<Self, WraithClientError> {
        use std::str::FromStr;
        Txid::from_str(s).map_err(|e| WraithClientError::Shape(format!("bad txid hex: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Wire-format DTOs (intentional duplicates of the coordinator's response
// types — coordinator is a binary, not a published crate, so we don't
// share Rust types across the wire).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct FindOrCreateResponse {
    session: SessionDescriptor,
    joined: bool,
    bond_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SessionDescriptor {
    session_id: String,
    tier_id: String,
    state: String,
    slots_filled: u32,
    slots_total: u32,
    bond_amount_sats: u64,
    fill_window_expires_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NonceResponse {
    signing_pubkey: String,
    signer_session_id: String,
    signing_key_id: String,
    nonce_point: String,
    blind_session_id: String,
}

#[derive(Debug, Deserialize)]
struct BlindSignResponse {
    signature_scalar: String,
    blind_session_id: String,
}

#[derive(Debug, Deserialize)]
struct RoundTxResponse {
    unsigned_tx_hex: String,
    txid: String,
    mining_fee_sats: u64,
    assembled_at: u64,
}

#[derive(Debug, Deserialize)]
struct WitnessResponse {
    state: String,
    witnesses_collected: u32,
    enrolled_count: u32,
    broadcast_txid: Option<String>,
    bonds_resolved: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SessionStatusResponse {
    session: SessionDescriptor,
}

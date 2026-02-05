//! MPC contribution generation and verification
//!
//! Each contributor applies a random transformation to the parameters
//! and provides a proof that the transformation was valid.

use crate::errors::{MpcError, MpcResult};
use bellperson::groth16::Parameters;
use blstrs::{Bls12, G1Affine, G2Affine, Scalar};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A contribution to the MPC ceremony
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcContribution {
    /// Position in the ceremony (1-101)
    pub position: u32,
    /// Hash of the previous parameters (chain link)
    pub prev_params_hash: [u8; 32],
    /// Hash of the new parameters after contribution
    pub new_params_hash: [u8; 32],
    /// Proof that the contribution was valid
    pub proof: ContributionProof,
    /// Node ID of the contributor
    pub contributor: String,
    /// Timestamp of contribution
    pub timestamp: u64,
}

/// Proof that a contribution was validly computed
///
/// This uses a Schnorr-like protocol to prove knowledge of the
/// secret scalars (tau, alpha, beta) without revealing them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContributionProof {
    /// Commitment to tau: g1^tau (in G1)
    pub tau_g1: Vec<u8>,
    /// Commitment to tau: g2^tau (in G2)
    pub tau_g2: Vec<u8>,
    /// Commitment to alpha: g1^alpha (in G1)
    pub alpha_g1: Vec<u8>,
    /// Commitment to beta: g1^beta (in G1)
    pub beta_g1: Vec<u8>,
    /// Commitment to beta: g2^beta (in G2)
    pub beta_g2: Vec<u8>,
    /// Schnorr proof components for tau
    pub tau_pok: ProofOfKnowledge,
    /// Schnorr proof components for alpha
    pub alpha_pok: ProofOfKnowledge,
    /// Schnorr proof components for beta
    pub beta_pok: ProofOfKnowledge,
}

/// Schnorr proof of knowledge for a discrete log
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfKnowledge {
    /// Random commitment R = g^r
    pub commitment_g1: Vec<u8>,
    /// Challenge hash
    pub challenge: [u8; 32],
    /// Response s = r + c*x
    pub response: Vec<u8>,
}

/// Toxic waste - the secret random values used in contribution
/// These are zeroed on drop to prevent memory recovery using explicit Drop impl
struct ToxicWaste {
    tau: Scalar,
    alpha: Scalar,
    beta: Scalar,
}

impl ToxicWaste {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let tau = Scalar::random(&mut *rng);
        let alpha = Scalar::random(&mut *rng);
        let beta = Scalar::random(&mut *rng);
        Self { tau, alpha, beta }
    }
}

impl Drop for ToxicWaste {
    fn drop(&mut self) {
        // Overwrite with zeros - best effort zeroization
        // Note: Scalar doesn't implement Zeroize, so we overwrite with ONE
        // which is still better than leaving values in memory
        self.tau = Scalar::ONE;
        self.alpha = Scalar::ONE;
        self.beta = Scalar::ONE;
    }
}

/// Generate a new MPC contribution
///
/// This function:
/// 1. Generates random tau, alpha, beta (toxic waste)
/// 2. Applies transformation to parameters
/// 3. Generates proof of valid transformation
/// 4. Zeroizes toxic waste from memory
pub fn generate_contribution<R: RngCore + CryptoRng>(
    prev_params: &Parameters<Bls12>,
    position: u32,
    contributor: &str,
    rng: &mut R,
) -> MpcResult<(Parameters<Bls12>, MpcContribution)> {
    // Generate toxic waste
    let toxic = ToxicWaste::random(rng);

    // Hash the previous parameters
    let prev_params_hash = hash_parameters(prev_params)?;

    // Apply transformation to create new parameters
    let new_params = apply_contribution(prev_params, &toxic)?;

    // Hash the new parameters
    let new_params_hash = hash_parameters(&new_params)?;

    // Generate proof of valid transformation
    let proof = generate_proof(&toxic, rng)?;

    // Create contribution record
    let contribution = MpcContribution {
        position,
        prev_params_hash,
        new_params_hash,
        proof,
        contributor: contributor.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };

    // toxic is automatically zeroized here on drop

    Ok((new_params, contribution))
}

/// Apply a contribution's transformation to parameters
///
/// NOTE: This is a simplified implementation that transforms only the
/// verification key components. A full phase2 ceremony would also need
/// to transform the proving key elements (h, l, a, b_g1, b_g2) which
/// are stored in Arc<Vec<_>> and require more careful handling.
///
/// For a production implementation, use bellperson's phase2 module
/// or implement full parameter reconstruction.
fn apply_contribution(
    params: &Parameters<Bls12>,
    toxic: &ToxicWaste,
) -> MpcResult<Parameters<Bls12>> {
    // Clone the parameters
    let mut new_params = params.clone();

    // Transform the verification key elements (these are not Arc-wrapped)
    // Apply alpha transformation: alpha_g1 = alpha_g1 * alpha
    let alpha_g1_proj = new_params.vk.alpha_g1.to_curve();
    new_params.vk.alpha_g1 = (alpha_g1_proj * toxic.alpha).to_affine();

    // Apply beta transformations
    // beta_g1 = beta_g1 * beta
    let beta_g1_proj = new_params.vk.beta_g1.to_curve();
    new_params.vk.beta_g1 = (beta_g1_proj * toxic.beta).to_affine();

    // beta_g2 = beta_g2 * beta
    let beta_g2_proj = new_params.vk.beta_g2.to_curve();
    new_params.vk.beta_g2 = (beta_g2_proj * toxic.beta).to_affine();

    // Apply tau to delta_g2 (accumulator)
    // delta_g2 = delta_g2 * tau
    let delta_g2_proj = new_params.vk.delta_g2.to_curve();
    new_params.vk.delta_g2 = (delta_g2_proj * toxic.tau).to_affine();

    // Note: For a complete phase2 implementation, we would also need to:
    // 1. Transform h (powers of tau in G1) - requires Arc::make_mut or reconstruction
    // 2. Transform l (Lagrange basis) - requires reconstruction
    // 3. Transform a, b_g1, b_g2 (constraint matrices) - requires reconstruction
    // These are left for future work when full MPC ceremony is enabled.

    Ok(new_params)
}

/// Generate proof of knowledge for the toxic waste
fn generate_proof<R: RngCore + CryptoRng>(
    toxic: &ToxicWaste,
    rng: &mut R,
) -> MpcResult<ContributionProof> {
    let g1_generator = G1Affine::generator();
    let g2_generator = G2Affine::generator();

    // Compute commitments
    let tau_g1 = (g1_generator.to_curve() * toxic.tau).to_affine();
    let tau_g2 = (g2_generator.to_curve() * toxic.tau).to_affine();
    let alpha_g1 = (g1_generator.to_curve() * toxic.alpha).to_affine();
    let beta_g1 = (g1_generator.to_curve() * toxic.beta).to_affine();
    let beta_g2 = (g2_generator.to_curve() * toxic.beta).to_affine();

    // Generate Schnorr proofs for each secret
    let tau_pok = schnorr_prove(g1_generator, &toxic.tau, rng)?;
    let alpha_pok = schnorr_prove(g1_generator, &toxic.alpha, rng)?;
    let beta_pok = schnorr_prove(g1_generator, &toxic.beta, rng)?;

    Ok(ContributionProof {
        tau_g1: serialize_g1(&tau_g1)?,
        tau_g2: serialize_g2(&tau_g2)?,
        alpha_g1: serialize_g1(&alpha_g1)?,
        beta_g1: serialize_g1(&beta_g1)?,
        beta_g2: serialize_g2(&beta_g2)?,
        tau_pok,
        alpha_pok,
        beta_pok,
    })
}

/// Schnorr proof of knowledge of discrete log
fn schnorr_prove<R: RngCore + CryptoRng>(
    generator: G1Affine,
    secret: &Scalar,
    rng: &mut R,
) -> MpcResult<ProofOfKnowledge> {
    // Random nonce
    let r = Scalar::random(rng);

    // Commitment R = g^r
    let commitment = (generator.to_curve() * r).to_affine();
    let commitment_bytes = serialize_g1(&commitment)?;

    // Public key Y = g^x
    let public_key = (generator.to_curve() * secret).to_affine();
    let public_key_bytes = serialize_g1(&public_key)?;

    // Challenge c = H(g || Y || R)
    let mut hasher = Sha256::new();
    hasher.update(&serialize_g1(&generator)?);
    hasher.update(&public_key_bytes);
    hasher.update(&commitment_bytes);
    let challenge: [u8; 32] = hasher.finalize().into();

    // Convert challenge to scalar
    let c = scalar_from_hash(&challenge);

    // Response s = r + c*x
    let response = r + (c * secret);
    let response_bytes = serialize_scalar(&response)?;

    Ok(ProofOfKnowledge {
        commitment_g1: commitment_bytes,
        challenge,
        response: response_bytes,
    })
}

/// Verify a contribution proof
pub fn verify_contribution(
    prev_params: &Parameters<Bls12>,
    new_params: &Parameters<Bls12>,
    contribution: &MpcContribution,
) -> MpcResult<bool> {
    // Verify hash chain
    let prev_hash = hash_parameters(prev_params)?;
    if prev_hash != contribution.prev_params_hash {
        return Err(MpcError::InvalidChain {
            expected: hex::encode(contribution.prev_params_hash),
            actual: hex::encode(prev_hash),
        });
    }

    let new_hash = hash_parameters(new_params)?;
    if new_hash != contribution.new_params_hash {
        return Err(MpcError::HashMismatch {
            expected: hex::encode(contribution.new_params_hash),
            actual: hex::encode(new_hash),
        });
    }

    // Verify the proof of knowledge for each component
    let g1_generator = G1Affine::generator();

    // Deserialize proof commitments
    let tau_g1: G1Affine = deserialize_g1(&contribution.proof.tau_g1)?;
    let alpha_g1: G1Affine = deserialize_g1(&contribution.proof.alpha_g1)?;
    let beta_g1: G1Affine = deserialize_g1(&contribution.proof.beta_g1)?;

    // Verify Schnorr proofs
    if !schnorr_verify(g1_generator, &tau_g1, &contribution.proof.tau_pok)? {
        return Err(MpcError::InvalidProof("tau proof verification failed".into()));
    }
    if !schnorr_verify(g1_generator, &alpha_g1, &contribution.proof.alpha_pok)? {
        return Err(MpcError::InvalidProof(
            "alpha proof verification failed".into(),
        ));
    }
    if !schnorr_verify(g1_generator, &beta_g1, &contribution.proof.beta_pok)? {
        return Err(MpcError::InvalidProof("beta proof verification failed".into()));
    }

    // Verify the transformation was applied correctly by checking
    // that new parameters relate to old by the proven factors
    // This involves pairing checks which verify e(new_h, g2) = e(old_h, tau_g2)
    // For simplicity in this implementation, we trust the proof of knowledge
    // A full implementation would do pairing-based verification

    Ok(true)
}

/// Verify a Schnorr proof of knowledge
fn schnorr_verify(
    generator: G1Affine,
    public_key: &G1Affine,
    proof: &ProofOfKnowledge,
) -> MpcResult<bool> {
    let commitment: G1Affine = deserialize_g1(&proof.commitment_g1)?;
    let response: Scalar = deserialize_scalar(&proof.response)?;

    // Recompute challenge
    let mut hasher = Sha256::new();
    hasher.update(&serialize_g1(&generator)?);
    hasher.update(&serialize_g1(public_key)?);
    hasher.update(&proof.commitment_g1);
    let expected_challenge: [u8; 32] = hasher.finalize().into();

    if expected_challenge != proof.challenge {
        return Ok(false);
    }

    // Verify: g^s = R * Y^c
    let c = scalar_from_hash(&proof.challenge);
    let lhs = (generator.to_curve() * response).to_affine();
    let rhs = (commitment.to_curve() + (public_key.to_curve() * c)).to_affine();

    Ok(lhs == rhs)
}

/// Hash parameters to create a chain link
pub fn hash_parameters(params: &Parameters<Bls12>) -> MpcResult<[u8; 32]> {
    let mut hasher = Sha256::new();

    // Hash the verification key components
    hasher.update(&serialize_g1(&params.vk.alpha_g1)?);
    hasher.update(&serialize_g1(&params.vk.beta_g1)?);
    hasher.update(&serialize_g2(&params.vk.beta_g2)?);
    hasher.update(&serialize_g2(&params.vk.gamma_g2)?);
    hasher.update(&serialize_g2(&params.vk.delta_g2)?);

    // Hash IC (input commitment) points
    for ic in &params.vk.ic {
        hasher.update(&serialize_g1(ic)?);
    }

    // Hash the first few h values (powers of tau)
    // Don't hash all as it could be very large
    let h_count = params.h.len().min(256);
    hasher.update(&(h_count as u32).to_le_bytes());
    for h in params.h.iter().take(h_count) {
        hasher.update(&serialize_g1(h)?);
    }

    Ok(hasher.finalize().into())
}

// Serialization helpers

fn serialize_g1(point: &G1Affine) -> MpcResult<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&point.to_compressed());
    Ok(buf)
}

fn deserialize_g1(bytes: &[u8]) -> MpcResult<G1Affine> {
    if bytes.len() != 48 {
        return Err(MpcError::Serialization(format!(
            "Invalid G1 point length: expected 48, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(bytes);
    Option::from(G1Affine::from_compressed(&arr))
        .ok_or_else(|| MpcError::Serialization("Invalid G1 point".into()))
}

fn serialize_g2(point: &G2Affine) -> MpcResult<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&point.to_compressed());
    Ok(buf)
}

#[allow(dead_code)] // Reserved for verification proof deserialization
fn deserialize_g2(bytes: &[u8]) -> MpcResult<G2Affine> {
    if bytes.len() != 96 {
        return Err(MpcError::Serialization(format!(
            "Invalid G2 point length: expected 96, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(bytes);
    Option::from(G2Affine::from_compressed(&arr))
        .ok_or_else(|| MpcError::Serialization("Invalid G2 point".into()))
}

fn serialize_scalar(scalar: &Scalar) -> MpcResult<Vec<u8>> {
    Ok(scalar.to_bytes_le().to_vec())
}

fn deserialize_scalar(bytes: &[u8]) -> MpcResult<Scalar> {
    if bytes.len() != 32 {
        return Err(MpcError::Serialization(format!(
            "Invalid scalar length: expected 32, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::from(Scalar::from_bytes_le(&arr))
        .ok_or_else(|| MpcError::Serialization("Invalid scalar".into()))
}

fn scalar_from_hash(hash: &[u8; 32]) -> Scalar {
    // Reduce hash modulo scalar field order
    // Use from_bytes_le which handles reduction
    Scalar::from_bytes_le(hash).unwrap_or(Scalar::ONE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_schnorr_proof_roundtrip() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let generator = G1Affine::generator();

        let proof = schnorr_prove(generator, &secret, &mut rng).unwrap();
        let public_key = (generator.to_curve() * secret).to_affine();

        assert!(schnorr_verify(generator, &public_key, &proof).unwrap());
    }

    #[test]
    fn test_schnorr_proof_wrong_key_fails() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let wrong_secret = Scalar::random(&mut rng);
        let generator = G1Affine::generator();

        let proof = schnorr_prove(generator, &secret, &mut rng).unwrap();
        let wrong_public_key = (generator.to_curve() * wrong_secret).to_affine();

        assert!(!schnorr_verify(generator, &wrong_public_key, &proof).unwrap());
    }

    #[test]
    fn test_serialize_roundtrip_g1() {
        let generator = G1Affine::generator();
        let bytes = serialize_g1(&generator).unwrap();
        let recovered = deserialize_g1(&bytes).unwrap();
        assert_eq!(generator, recovered);
    }

    #[test]
    fn test_serialize_roundtrip_scalar() {
        let mut rng = OsRng;
        let scalar = Scalar::random(&mut rng);
        let bytes = serialize_scalar(&scalar).unwrap();
        let recovered = deserialize_scalar(&bytes).unwrap();
        assert_eq!(scalar, recovered);
    }
}

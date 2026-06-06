//! TLS configuration helpers for HTTP servers
//!
//! Provides `build_server_config` which returns an `Arc<rustls::ServerConfig>` suitable
//! for wrapping TCP listeners with TLS.
//!
//! Three cert sources, in priority order:
//! 1. Operator-provided PEM files (`tls.cert_path` + `tls.key_path` set)
//! 2. Identity-derived: cert signed with the node's existing Ed25519 identity key
//!    so the cert's public key IS the node_id. Allowed on mainnet — peers pin
//!    against the registered node_id. No CA, no DNS, zero ops cost.
//! 3. Random self-signed (testnets/dev only — mainnet rejects this path)

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::config::TlsConfig;

/// Algorithm identifier prefix for an Ed25519 SubjectPublicKeyInfo: the OID
/// `1.3.101.112` (RFC 8410) wrapped in the AlgorithmIdentifier SEQUENCE. We
/// scan certificate DER for this byte pattern; whatever immediately follows is
/// the 33-byte BIT STRING wrapping the 32-byte public key.
const ED25519_OID_DER: [u8; 9] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21];

/// Extract the 32-byte Ed25519 public key from an X.509 certificate's DER
/// encoding. Returns `None` if the cert isn't Ed25519 or is malformed.
pub fn extract_ed25519_pubkey(cert_der: &[u8]) -> Option<[u8; 32]> {
    // Find the algorithm-identifier + BIT STRING tag prefix
    let pos = cert_der
        .windows(ED25519_OID_DER.len())
        .position(|w| w == ED25519_OID_DER)?;
    // After the prefix: 1 unused-bits byte (0x00) then 32 key bytes
    let key_start = pos + ED25519_OID_DER.len() + 1;
    let key_end = key_start + 32;
    if key_end > cert_der.len() {
        return None;
    }
    if cert_der.get(pos + ED25519_OID_DER.len()) != Some(&0x00) {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&cert_der[key_start..key_end]);
    Some(out)
}

/// Build a `rustls::ServerConfig` for HTTPS.
///
/// * If `tls.cert_path` and `tls.key_path` are both set, the PEM files are loaded.
/// * Otherwise a self-signed Ed25519 certificate is generated on the fly
///   (development/testnets only).
///
/// When `is_mainnet` is true, self-signed certificate generation is rejected.
/// Mainnet nodes MUST provide operator-managed TLS certificates.
///
/// # Errors
///
/// Returns an error if:
/// - PEM files are missing / malformed
/// - rustls rejects the certificate / key combination
/// - `is_mainnet` is true and no cert/key paths are provided
pub fn build_server_config(
    tls: &TlsConfig,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    build_server_config_for_network(tls, false)
}

/// Build a `rustls::ServerConfig` with mainnet enforcement.
///
/// Resolution order:
/// 1. Operator PEM files (`cert_path` + `key_path`)
/// 2. Random self-signed (mainnet rejects this — fall through to error)
///
/// For identity-derived certs (the mainnet-allowed default), use
/// [`build_server_config_with_identity`].
pub fn build_server_config_for_network(
    tls: &TlsConfig,
    is_mainnet: bool,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let (certs, key) = if let (Some(cert_path), Some(key_path)) = (&tls.cert_path, &tls.key_path) {
        load_pem_files(cert_path, key_path)?
    } else if is_mainnet {
        return Err("Mainnet requires operator-provided TLS certificates. \
             Self-signed certificates are not allowed on mainnet. \
             Set tls.cert_path and tls.key_path in your configuration, \
             or use build_server_config_with_identity for identity-derived certs."
            .into());
    } else {
        generate_self_signed()?
    };

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Build a `rustls::ServerConfig` using an identity-derived cert.
///
/// The 32-byte Ed25519 secret seed (from `LocalSigner::signing_key_bytes()`)
/// is used to sign a self-signed X.509 certificate. The cert's public key
/// is exactly the node's Ed25519 identity public key, so peers can pin
/// against the registered `node_id` without trusting any CA.
///
/// Resolution order (when this function is called):
/// 1. Operator PEM files (if explicitly configured) — operator override wins
/// 2. Identity-derived cert (mainnet-allowed)
///
/// Subject Alternative Names (SANs) include `localhost`, `127.0.0.1`, and
/// the supplied `public_address` (if any). Peers don't validate hostnames —
/// they pin on the certificate's public key — but well-formed SANs prevent
/// rustls from rejecting the handshake on the server-name check.
pub fn build_server_config_with_identity(
    tls: &TlsConfig,
    ed25519_secret: &[u8; 32],
    public_address: Option<&str>,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let (certs, key) = if let (Some(cert_path), Some(key_path)) = (&tls.cert_path, &tls.key_path) {
        load_pem_files(cert_path, key_path)?
    } else {
        derive_cert_from_ed25519(ed25519_secret, public_address)?
    };

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Load PEM-encoded certificate chain and private key from disk.
fn load_pem_files(
    cert_path: &Path,
    key_path: &Path,
) -> Result<
    (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    use rustls::pki_types::pem::PemObject;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| {
            format!(
                "Failed to read TLS certificate from {}: {}",
                cert_path.display(),
                e
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse PEM certificates: {}", e))?;

    if certs.is_empty() {
        return Err("No certificates found in PEM file".into());
    }

    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
        format!(
            "Failed to read/parse TLS private key from {}: {}",
            key_path.display(),
            e
        )
    })?;

    Ok((certs, key))
}

/// Generate a self-signed Ed25519 certificate (for development / testnets).
fn generate_self_signed() -> Result<
    (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;

    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ghost Node");

    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der().to_vec()));

    tracing::info!("TLS: Generated self-signed Ed25519 certificate for development use");

    Ok((vec![cert_der], key_der))
}

/// PKCS#8 v1 prefix for an Ed25519 private key (RFC 8410). The trailing 32
/// bytes are the raw seed, yielding a 48-byte DER blob in total.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Wrap a 32-byte Ed25519 secret seed in PKCS#8 v1 DER (RFC 8410).
fn ed25519_secret_to_pkcs8_der(secret: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32);
    der.extend_from_slice(&ED25519_PKCS8_PREFIX);
    der.extend_from_slice(secret);
    der
}

/// Derive a self-signed X.509 cert from a 32-byte Ed25519 secret seed.
///
/// The cert's subject public key is the Ed25519 verifying key derived from
/// `secret`, which (in this codebase) equals the node's `node_id`.
fn derive_cert_from_ed25519(
    secret: &[u8; 32],
    public_address: Option<&str>,
) -> Result<
    (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    let pkcs8_der = ed25519_secret_to_pkcs8_der(secret);
    let pkcs8_key = PrivatePkcs8KeyDer::from(pkcs8_der.clone());
    let private_key_der = PrivateKeyDer::Pkcs8(pkcs8_key);

    let key_pair = KeyPair::from_der_and_sign_algo(&private_key_der, &PKCS_ED25519)
        .map_err(|e| format!("Failed to import Ed25519 key into rcgen: {}", e))?;

    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    if let Some(addr) = public_address {
        let host = addr.split(':').next().unwrap_or(addr).trim();
        if !host.is_empty()
            && host != "localhost"
            && host != "127.0.0.1"
            && !sans.iter().any(|s| s == host)
        {
            sans.push(host.to_string());
        }
    }

    let mut params = CertificateParams::new(sans)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ghost Node (identity-derived)");

    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

    tracing::info!("TLS: Derived identity-bound Ed25519 certificate (cert pubkey = node_id)");

    Ok((vec![cert_der], key_der))
}

// ─── client-side cert pinning ──────────────────────────────────────────────

/// A predicate over Ed25519 public keys. Returns true iff the supplied 32-byte
/// public key belongs to a registered peer that this client is willing to
/// trust.
pub type PubkeyAllowList = Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>;

/// rustls [`ServerCertVerifier`] that pins on Ed25519 cert public keys instead
/// of validating a CA chain.
///
/// The verifier:
/// 1. Extracts the Ed25519 SubjectPublicKey from the presented cert.
/// 2. Calls the supplied [`PubkeyAllowList`] to decide whether to trust it.
/// 3. Verifies TLS handshake signatures using the cert's own public key
///    (Ed25519 only).
///
/// CA chains, hostname matching, and OCSP responses are all ignored — pinning
/// against a known node_id is the trust anchor.
///
/// [`ServerCertVerifier`]: rustls::client::danger::ServerCertVerifier
#[derive(Clone)]
pub struct IdentityPinningVerifier {
    allow: PubkeyAllowList,
}

impl IdentityPinningVerifier {
    pub fn new(allow: PubkeyAllowList) -> Self {
        Self { allow }
    }
}

impl std::fmt::Debug for IdentityPinningVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityPinningVerifier").finish()
    }
}

impl rustls::client::danger::ServerCertVerifier for IdentityPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let pubkey = extract_ed25519_pubkey(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if (self.allow)(&pubkey) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            tracing::warn!(
                pubkey_prefix = %hex::encode(&pubkey[..4]),
                "Rejected unpinned cert: presented Ed25519 key is not a known peer"
            );
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_ed25519_handshake(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_ed25519_handshake(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

fn verify_ed25519_handshake(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if dss.scheme != rustls::SignatureScheme::ED25519 {
        return Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::NoSignatureSchemesInCommon,
        ));
    }
    let pubkey_bytes = extract_ed25519_pubkey(cert.as_ref()).ok_or(
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
    )?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let sig_bytes: &[u8] = dss.signature();
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| rustls::Error::DecryptError)?;
    let signature = Signature::from_bytes(&sig_array);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| rustls::Error::DecryptError)?;
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[test]
    fn test_build_server_config_self_signed() {
        ensure_crypto_provider();
        // With no cert/key paths, should generate a self-signed cert and succeed
        let tls = TlsConfig::default();
        let result = build_server_config(&tls);
        assert!(
            result.is_ok(),
            "Self-signed TLS config should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_server_config_missing_cert_file() {
        let tls = TlsConfig {
            cert_path: Some("/nonexistent/cert.pem".into()),
            key_path: Some("/nonexistent/key.pem".into()),
        };
        let result = build_server_config(&tls);
        assert!(result.is_err(), "Should fail with missing cert file");
    }

    #[test]
    fn test_build_server_config_only_cert_no_key() {
        ensure_crypto_provider();
        // When only cert_path is set but key_path is None, should fall through
        // to self-signed generation (both must be Some to use PEM loading)
        let tls = TlsConfig {
            cert_path: Some("/some/cert.pem".into()),
            key_path: None,
        };
        let result = build_server_config(&tls);
        assert!(
            result.is_ok(),
            "With only cert_path, should fall back to self-signed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_generate_self_signed_produces_valid_config() {
        let (certs, _key) = generate_self_signed().expect("Self-signed generation should succeed");
        assert_eq!(certs.len(), 1, "Should produce exactly one certificate");
        assert!(!certs[0].is_empty(), "Certificate DER should not be empty");
    }

    #[test]
    fn test_mainnet_rejects_self_signed() {
        let tls = TlsConfig::default();
        let result = build_server_config_for_network(&tls, true);
        assert!(result.is_err(), "Mainnet must reject self-signed TLS");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Mainnet"),
            "Error should mention mainnet: {}",
            err
        );
    }

    #[test]
    fn test_non_mainnet_allows_self_signed() {
        ensure_crypto_provider();
        let tls = TlsConfig::default();
        let result = build_server_config_for_network(&tls, false);
        assert!(
            result.is_ok(),
            "Non-mainnet should allow self-signed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_identity_derived_cert_pubkey_matches_identity() {
        use ed25519_dalek::{SigningKey, VerifyingKey};

        // Deterministic seed for reproducibility
        let secret: [u8; 32] = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let expected_pubkey: VerifyingKey = signing_key.verifying_key();

        let (certs, _key) =
            derive_cert_from_ed25519(&secret, Some("203.0.113.7")).expect("derive cert");
        assert_eq!(certs.len(), 1, "Should produce exactly one certificate");

        // Parse the X.509 cert and confirm the SubjectPublicKeyInfo holds our Ed25519 key.
        // SPKI for Ed25519 is a fixed 12-byte prefix + 32-byte raw key.
        let cert_bytes = certs[0].as_ref();
        let needle = expected_pubkey.to_bytes();
        let found = cert_bytes
            .windows(needle.len())
            .any(|w| w == needle.as_slice());
        assert!(
            found,
            "Cert DER must embed the Ed25519 verifying key (cert pubkey == identity pubkey)"
        );
    }

    #[test]
    fn test_identity_derived_cert_builds_server_config() {
        ensure_crypto_provider();
        let tls = TlsConfig::default();
        let secret: [u8; 32] = [13u8; 32];
        let result = build_server_config_with_identity(&tls, &secret, Some("198.51.100.1"));
        assert!(
            result.is_ok(),
            "Identity-derived ServerConfig should build: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_identity_derived_cert_works_on_mainnet_path() {
        // The whole point: this path is allowed on mainnet without operator certs.
        // We don't need an `is_mainnet` argument because the identity provides the
        // trust anchor (cert pubkey == registered node_id).
        ensure_crypto_provider();
        let tls = TlsConfig::default();
        let secret: [u8; 32] = [42u8; 32];
        let result = build_server_config_with_identity(&tls, &secret, None);
        assert!(result.is_ok(), "Identity-derived path is mainnet-safe");
    }

    #[test]
    fn test_pkcs8_wrapper_is_48_bytes() {
        let der = ed25519_secret_to_pkcs8_der(&[0u8; 32]);
        assert_eq!(der.len(), 48, "PKCS#8 v1 Ed25519 DER must be 48 bytes");
        assert_eq!(&der[..16], &ED25519_PKCS8_PREFIX);
    }

    #[test]
    fn test_operator_pem_takes_priority_over_identity() {
        // If operator sets cert_path/key_path, we should try to load those even
        // when an identity secret is provided. (We test the priority by checking
        // that a missing PEM file produces an error rather than falling through
        // to identity-derived generation.)
        let tls = TlsConfig {
            cert_path: Some("/nonexistent/cert.pem".into()),
            key_path: Some("/nonexistent/key.pem".into()),
        };
        let secret: [u8; 32] = [99u8; 32];
        let result = build_server_config_with_identity(&tls, &secret, None);
        assert!(
            result.is_err(),
            "Operator PEM must take priority and surface its load error"
        );
    }

    #[test]
    fn test_extract_ed25519_pubkey_roundtrip() {
        use ed25519_dalek::{SigningKey, VerifyingKey};

        let secret: [u8; 32] = [11u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let expected: VerifyingKey = signing_key.verifying_key();

        let (certs, _) = derive_cert_from_ed25519(&secret, None).expect("derive cert");
        let extracted = extract_ed25519_pubkey(certs[0].as_ref())
            .expect("must extract pubkey from a valid Ed25519 cert");
        assert_eq!(
            extracted,
            expected.to_bytes(),
            "extracted cert pubkey must equal the identity verifying key"
        );
    }

    #[test]
    fn test_extract_ed25519_pubkey_rejects_random_bytes() {
        let garbage = [0xAAu8; 64];
        assert!(extract_ed25519_pubkey(&garbage).is_none());
    }

    #[test]
    fn test_pinning_verifier_accepts_known_pubkey() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};

        ensure_crypto_provider();
        let secret: [u8; 32] = [21u8; 32];
        let (certs, _) = derive_cert_from_ed25519(&secret, None).expect("derive");
        let cert = &certs[0];

        // Allow only this exact pubkey
        let allowed = ed25519_dalek::SigningKey::from_bytes(&secret)
            .verifying_key()
            .to_bytes();
        let verifier = IdentityPinningVerifier::new(Arc::new(move |k: &[u8; 32]| *k == allowed));

        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();
        verifier
            .verify_server_cert(cert, &[], &server_name, &[], now)
            .expect("known pubkey must be accepted");
    }

    #[test]
    fn test_pinning_verifier_rejects_unknown_pubkey() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};

        ensure_crypto_provider();
        let secret: [u8; 32] = [33u8; 32];
        let (certs, _) = derive_cert_from_ed25519(&secret, None).expect("derive");
        let cert = &certs[0];

        // Allow nothing — unconditional reject
        let verifier = IdentityPinningVerifier::new(Arc::new(|_: &[u8; 32]| false));

        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();
        let result = verifier.verify_server_cert(cert, &[], &server_name, &[], now);
        assert!(
            matches!(
                result,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                ))
            ),
            "unknown pubkey must be rejected with ApplicationVerificationFailure: {:?}",
            result
        );
    }
}

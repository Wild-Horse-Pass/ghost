//! TLS configuration helpers for HTTP servers
//!
//! Provides `build_server_config` which returns an `Arc<rustls::ServerConfig>` suitable
//! for wrapping TCP listeners with TLS.
//!
//! When operator-provided PEM cert/key files are present they are loaded; otherwise
//! a self-signed Ed25519 certificate is generated automatically (suitable for
//! development and testnets only -- mainnet validation rejects this path).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::config::TlsConfig;

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
/// Same as [`build_server_config`] but accepts `is_mainnet` to reject
/// self-signed certificates on mainnet.
pub fn build_server_config_for_network(
    tls: &TlsConfig,
    is_mainnet: bool,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let (certs, key) = if let (Some(cert_path), Some(key_path)) = (&tls.cert_path, &tls.key_path) {
        load_pem_files(cert_path, key_path)?
    } else if is_mainnet {
        return Err("Mainnet requires operator-provided TLS certificates. \
             Self-signed certificates are not allowed on mainnet. \
             Set tls.cert_path and tls.key_path in your configuration."
            .into());
    } else {
        generate_self_signed()?
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

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert_path)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_server_config_self_signed() {
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
        let tls = TlsConfig::default();
        let result = build_server_config_for_network(&tls, false);
        assert!(
            result.is_ok(),
            "Non-mainnet should allow self-signed: {:?}",
            result.err()
        );
    }
}

//! Integration test: a verification client with an identity-pinned TLS
//! verifier successfully completes a real TLS-1.3 handshake against a
//! ghost-pool-style server that serves an identity-derived certificate.
//!
//! Proves end-to-end that:
//!   1. The server cert pubkey == the node's Ed25519 identity pubkey.
//!   2. The client's pinning verifier accepts the cert iff the pubkey is
//!      in the allow list.
//!   3. A pinning verifier with an empty allow list rejects the handshake.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ghost_common::config::TlsConfig;
use ghost_common::tls::{
    build_server_config_with_identity, IdentityPinningVerifier, PubkeyAllowList,
};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[tokio::test]
async fn end_to_end_handshake_succeeds_when_pubkey_is_allowed() {
    ensure_crypto_provider();

    // Server identity
    let secret: [u8; 32] = [3u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let server_pubkey = signing_key.verifying_key().to_bytes();

    // Server: identity-derived TLS config
    let server_config = build_server_config_with_identity(&TlsConfig::default(), &secret, None)
        .expect("server config");

    // Bind and accept exactly one TLS connection
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("server tls accept");
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.expect("read");
        tls.write_all(b"PONG").await.expect("write");
        tls.shutdown().await.ok();
        buf
    });

    // Client: pinning verifier that allows ONLY the server's pubkey
    let allowed = server_pubkey;
    let allow: PubkeyAllowList = Arc::new(move |k: &[u8; 32]| *k == allowed);
    let verifier = Arc::new(IdentityPinningVerifier::new(allow));

    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .expect("handshake timeout")
        .expect("handshake error");

    tls.write_all(b"HELLO").await.expect("client write");
    let mut response = [0u8; 4];
    tls.read_exact(&mut response).await.expect("client read");
    assert_eq!(&response, b"PONG");

    let server_received = server_task.await.expect("server task");
    assert_eq!(&server_received, b"HELLO");
}

#[tokio::test]
async fn handshake_fails_when_pubkey_not_in_allow_list() {
    ensure_crypto_provider();

    let secret: [u8; 32] = [9u8; 32];
    let server_config = build_server_config_with_identity(&TlsConfig::default(), &secret, None)
        .expect("server config");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    // Server-side: accept the TCP, attempt handshake (it must fail)
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        // The handshake will fail when the client closes after rejecting cert.
        let _ = acceptor.accept(tcp).await;
    });

    // Client allow list is empty — pinning rejects everything
    let allow: PubkeyAllowList = Arc::new(|_: &[u8; 32]| false);
    let verifier = Arc::new(IdentityPinningVerifier::new(allow));
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let server_name = ServerName::try_from("localhost").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .expect("handshake timeout");
    assert!(
        result.is_err(),
        "Empty allow list must reject the handshake"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn handshake_fails_when_pubkey_does_not_match_cert() {
    // The cert presents a different pubkey than the one in the allow list.
    // Adversary scenario: an MITM substitutes their own self-signed cert.
    ensure_crypto_provider();

    let server_secret: [u8; 32] = [11u8; 32]; // server's actual key
    let attacker_secret: [u8; 32] = [22u8; 32]; // attacker's "fake" registration

    // Server runs its own identity
    let server_config =
        build_server_config_with_identity(&TlsConfig::default(), &server_secret, None)
            .expect("server config");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let _ = acceptor.accept(tcp).await; // expected to fail / be aborted
    });

    // Client only trusts the attacker_secret's pubkey, not the server's
    let attacker_pubkey = SigningKey::from_bytes(&attacker_secret)
        .verifying_key()
        .to_bytes();
    let allow: PubkeyAllowList = Arc::new(move |k: &[u8; 32]| *k == attacker_pubkey);
    let verifier = Arc::new(IdentityPinningVerifier::new(allow));
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let server_name = ServerName::try_from("localhost").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .expect("handshake timeout");
    assert!(
        result.is_err(),
        "MITM-substituted cert must be rejected when its pubkey is not pinned"
    );

    let _ = server_task.await;
}

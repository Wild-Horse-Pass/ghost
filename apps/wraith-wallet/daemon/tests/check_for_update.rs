//! Phase 15 integration test: CheckForUpdate fetches the manifest from a
//! configured URL, parses it, and returns the up-to-date / available shape.
//!
//! No GSP, no ghost-pay — just an in-process axum server that serves a
//! release manifest. Locks the daemon's HTTP fetch + JSON parse path so a
//! schema drift in `ReleaseManifest` blows up here, not in production.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use wraith_wallet_ipc::{Envelope, ManifestBinary, ReleaseManifest, Request, Response};

#[derive(Clone)]
struct ServeState {
    manifest: Arc<ReleaseManifest>,
}

async fn serve_manifest(State(s): State<ServeState>) -> impl IntoResponse {
    Json((*s.manifest).clone())
}

async fn spawn_manifest_server(manifest: ReleaseManifest) -> std::net::SocketAddr {
    let app = Router::new()
        .route("/manifest.json", get(serve_manifest))
        .with_state(ServeState {
            manifest: Arc::new(manifest),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    addr
}

fn wraithd_binary() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_wraithd") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let mut dir = exe.parent().expect("exe parent").to_path_buf();
    while dir.pop() {
        let candidate = dir.join("wraithd");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("wraithd binary not found")
}

async fn spawn_daemon(manifest_url: Option<&str>) -> (Child, PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join("wraithd.sock");
    let wallets = tmp.path().join("wallets");
    std::fs::create_dir_all(&wallets).expect("mkdir wallets");

    let mut cmd = Command::new(wraithd_binary());
    cmd.env("WRAITHD_SOCKET", &socket)
        .env("WRAITHD_WALLETS_DIR", &wallets)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(u) = manifest_url {
        cmd.env("WRAITHD_UPDATE_MANIFEST_URL", u);
    }
    let child = cmd.spawn().expect("spawn wraithd");

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            tokio::time::sleep(Duration::from_millis(40)).await;
            return (child, socket, tmp);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("wraithd socket never appeared");
}

async fn rpc(socket: &PathBuf, id: u64, request: Request) -> Response {
    let stream = UnixStream::connect(socket).await.expect("connect");
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json::to_string(&Envelope::new(id, request)).expect("serialise");
    line.push('\n');
    writer.write_all(line.as_bytes()).await.expect("write");
    writer.shutdown().await.expect("shutdown");
    let mut buf = String::new();
    BufReader::new(reader)
        .read_line(&mut buf)
        .await
        .expect("read");
    let env: Envelope<Response> = serde_json::from_str(&buf).expect("decode");
    assert_eq!(env.id, id);
    env.payload
}

fn make_manifest(version: &str) -> ReleaseManifest {
    let mut binaries = std::collections::BTreeMap::new();
    binaries.insert(
        "wraithd".into(),
        ManifestBinary {
            sha256: "0".repeat(64),
            size: 1234,
        },
    );
    ReleaseManifest {
        version: version.into(),
        triple: "x86_64-unknown-linux-gnu".into(),
        built: "2026-05-06T12:00:00Z".into(),
        commit: "abc".into(),
        rustc: "rustc 1.93.0".into(),
        tarball: format!("wraith-wallet-{version}-x86_64-unknown-linux-gnu.tar.gz"),
        tarball_sha256: "f".repeat(64),
        binaries,
    }
}

#[tokio::test]
async fn check_for_update_up_to_date() {
    // Manifest version matches the running daemon's CARGO_PKG_VERSION
    // (sourced from the workspace's version field).
    let current = env!("CARGO_PKG_VERSION");
    let addr = spawn_manifest_server(make_manifest(current)).await;
    let url = format!("http://{addr}/manifest.json");

    let (mut child, socket, _tmp) = spawn_daemon(Some(&url)).await;

    match rpc(&socket, 1, Request::CheckForUpdate { manifest_url: None }).await {
        Response::CheckForUpdate(c) => {
            assert_eq!(c.current_version, current);
            assert_eq!(c.latest_version.as_deref(), Some(current));
            assert!(c.up_to_date, "matching versions → up-to-date=true");
            assert_eq!(c.manifest_url, url);
        }
        other => panic!("expected CheckForUpdate, got {other:?}"),
    }

    child.kill().await.ok();
}

#[tokio::test]
async fn check_for_update_newer_available() {
    // Bump the manifest version a couple of patch levels so any future
    // workspace bump still keeps the test asserting "different".
    let bumped = format!("{}-newer", env!("CARGO_PKG_VERSION"));
    let addr = spawn_manifest_server(make_manifest(&bumped)).await;
    let url = format!("http://{addr}/manifest.json");

    let (mut child, socket, _tmp) = spawn_daemon(None).await;

    // Use the per-call override so we don't depend on the env var.
    match rpc(
        &socket,
        1,
        Request::CheckForUpdate {
            manifest_url: Some(url.clone()),
        },
    )
    .await
    {
        Response::CheckForUpdate(c) => {
            assert_eq!(c.current_version, env!("CARGO_PKG_VERSION"));
            assert_eq!(c.latest_version.as_deref(), Some(bumped.as_str()));
            assert!(!c.up_to_date, "versions differ → up-to-date=false");
            assert!(c.tarball.is_some(), "manifest tarball must round-trip");
            assert!(c.tarball_sha256.is_some());
        }
        other => panic!("expected CheckForUpdate, got {other:?}"),
    }

    child.kill().await.ok();
}

#[tokio::test]
async fn check_for_update_without_url_errors_cleanly() {
    // No env, no override → daemon must return a typed Error envelope, not
    // crash and not 200 with garbage.
    let (mut child, socket, _tmp) = spawn_daemon(None).await;

    match rpc(&socket, 1, Request::CheckForUpdate { manifest_url: None }).await {
        Response::Error(e) => {
            let lower = e.message.to_lowercase();
            assert!(
                lower.contains("manifest") || lower.contains("url"),
                "expected helpful error, got: {}",
                e.message
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    child.kill().await.ok();
}

//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: bins/wraith-coordinator/src/main.rs                                                                            |
//|======================================================================================================================|

//! Wraith Lite v1 single-round CoinJoin coordinator — binary entry.
//!
//! Most of the implementation lives in the lib target alongside this
//! file (`src/lib.rs`). This `main` is a thin shell: parse env-driven
//! CLI args, init logging, wire the configured backends into a
//! `CoordinatorState`, build the router, bind a TCP listener, run.
//!
//! ## Backend wiring
//!
//! The coordinator depends on three pluggable backends:
//!   - `BondLedger` — verifies and resolves L2 bonds. Real binding is
//!     phase C (ghost-pay RPC client).
//!   - `Broadcaster` — pushes the merged tx to the bitcoin network.
//!     Real binding is phase D (bitcoind RPC client).
//!   - `coordinator_fee_address` — destination for the per-Mix-round
//!     service-fee output. Operator-supplied.
//!
//! Until phases C/D land, the binary supports `--mock-bond-ledger` and
//! `--mock-broadcaster` flags that swap in `MockBondLedger` /
//! `StubBroadcaster`. These are explicitly refused on `mainnet` — a
//! mock ledger means no real bond escrow, a mock broadcaster means
//! no actual broadcast, both of which would be a security disaster
//! in production.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

use wraith_coordinator::bond_ledger_http::GhostPayBondLedger;
use wraith_coordinator::broadcaster::{GhostdBroadcaster, Broadcaster, StubBroadcaster};
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{BondLedger, MockBondLedger};

/// CLI surface. Configuration that varies between dev, signet, and
/// mainnet ships via env vars (`WRAITH_COORDINATOR_*`) just like
/// every other node binary in this workspace.
#[derive(Parser, Debug)]
#[command(
    name = "wraith-coordinator",
    about = "Wraith Lite v1 single-round CoinJoin coordinator",
    version
)]
struct Cli {
    /// Listen address. Defaults to `WRAITH_COORDINATOR_LISTEN` env var if
    /// set, falling back to `127.0.0.1:9100`. Production deployments bind
    /// to a public address and front it with a TLS-terminating proxy.
    #[arg(long, env = "WRAITH_COORDINATOR_LISTEN", default_value = "127.0.0.1:9100")]
    listen: SocketAddr,

    /// Bitcoin network (`mainnet` / `signet` / `testnet` / `regtest`).
    /// Defaults to signet so dev installs don't accidentally announce a
    /// mainnet coordinator. Mainnet operators set this explicitly via
    /// `WRAITH_COORDINATOR_NETWORK=mainnet`.
    #[arg(long, env = "WRAITH_COORDINATOR_NETWORK", default_value = "signet")]
    network: String,

    /// Coordinator fee-collection address. Mix rounds need this for
    /// the service-fee output; Jump rounds don't. If absent the
    /// binary still boots (Mix `/inputs` returns 503
    /// `fee_address_not_configured`); supply it for any non-trivial
    /// dev setup.
    #[arg(long, env = "WRAITH_COORDINATOR_FEE_ADDRESS")]
    fee_address: Option<String>,

    /// Use an in-memory MockBondLedger instead of a real backend.
    /// Refused on mainnet — a mock ledger holds no real escrows, so
    /// "verified" bonds aren't actually paid. Use only in dev /
    /// signet / regtest. Mutually exclusive with --bond-ledger-url.
    #[arg(long, env = "WRAITH_COORDINATOR_MOCK_BOND_LEDGER")]
    mock_bond_ledger: bool,

    /// Production ghost-pay BondLedger HTTP endpoint, e.g.
    /// `http://127.0.0.1:8800/`. Calls the `/api/v1/wraith/bond/*`
    /// endpoint set defined in `bond_ledger_http.rs`. Auth via the
    /// matching --bond-ledger-token (HTTP Bearer).
    #[arg(long, env = "WRAITH_COORDINATOR_BOND_LEDGER_URL")]
    bond_ledger_url: Option<String>,

    /// Bearer token sent to ghost-pay's BondLedger endpoints. The
    /// operator rotates this; the wraith-coordinator picks it up at
    /// boot. Required when --bond-ledger-url is set.
    #[arg(long, env = "WRAITH_COORDINATOR_BOND_LEDGER_TOKEN")]
    bond_ledger_token: Option<String>,

    /// Use an in-memory StubBroadcaster instead of a real backend.
    /// Refused on mainnet — a stub broadcaster doesn't actually push
    /// transactions to the network. Use only in dev / signet /
    /// regtest. Mutually exclusive with --ghostd-url.
    #[arg(long, env = "WRAITH_COORDINATOR_MOCK_BROADCASTER")]
    mock_broadcaster: bool,

    /// Production bitcoind RPC endpoint (e.g.
    /// `http://127.0.0.1:8332/`). The coordinator will POST a
    /// `sendrawtransaction` call here on the round-completing
    /// `/witness` submission. Auth comes from either
    /// --ghostd-cookie or --ghostd-user/--ghostd-pass.
    #[arg(long, env = "WRAITH_COORDINATOR_GHOSTD_URL")]
    ghostd_url: Option<String>,

    /// Path to bitcoind's `.cookie` file. Mutually exclusive with
    /// --ghostd-user / --ghostd-pass.
    #[arg(long, env = "WRAITH_COORDINATOR_GHOSTD_COOKIE")]
    ghostd_cookie: Option<std::path::PathBuf>,

    /// bitcoind RPC username (from `bitcoin.conf` `rpcuser=`).
    #[arg(long, env = "WRAITH_COORDINATOR_GHOSTD_USER")]
    ghostd_user: Option<String>,

    /// bitcoind RPC password (from `bitcoin.conf` `rpcpassword=`).
    #[arg(long, env = "WRAITH_COORDINATOR_GHOSTD_PASS")]
    ghostd_pass: Option<String>,

    /// Comma-separated base URLs of every other coordinator in the
    /// pool. Each session-state change on this Active is POSTed to
    /// `<peer>/api/v1/internal/gossip` so Standbys mirror the
    /// in-flight session set. Empty (the default) runs as a
    /// solo coordinator with no replication.
    #[arg(long, env = "WRAITH_COORDINATOR_PEERS", value_delimiter = ',')]
    peers: Vec<String>,

    /// Shared HMAC key for the inter-coordinator gossip route. When
    /// set, every outbound gossip POST carries `X-Ghost-Signature` +
    /// `X-Ghost-Timestamp` headers and the receive route verifies
    /// them. Same secret on every coordinator in the pool. When
    /// unset, the route accepts unsigned requests — operators must
    /// firewall `/api/v1/internal/` to the pool's address range.
    /// Refused on mainnet without a value (see startup checks).
    #[arg(long, env = "WRAITH_COORDINATOR_PEER_SECRET")]
    peer_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    let network = parse_network(&cli.network)
        .with_context(|| format!("invalid network: {}", cli.network))?;

    // Mainnet refuses any mock backend. Both mocks compromise the
    // security model in different ways — refusing at boot beats
    // surfacing a vulnerability later.
    if matches!(network, bitcoin::Network::Bitcoin) {
        if cli.mock_bond_ledger {
            anyhow::bail!(
                "MAINNET REFUSAL: --mock-bond-ledger implies no real bond escrow; \
                 use the production ghost-pay BondLedger binding (phase C)."
            );
        }
        if cli.mock_broadcaster {
            anyhow::bail!(
                "MAINNET REFUSAL: --mock-broadcaster does not actually push \
                 transactions; use the production bitcoind broadcaster (phase D)."
            );
        }
    }

    if cli.mock_bond_ledger && cli.bond_ledger_url.is_some() {
        anyhow::bail!(
            "--mock-bond-ledger and --bond-ledger-url are mutually exclusive; pick one."
        );
    }
    let bond_ledger: Option<Arc<dyn BondLedger>> = if cli.mock_bond_ledger {
        warn!("using MockBondLedger — bonds are NOT escrowed against real funds");
        Some(Arc::new(MockBondLedger::new()))
    } else if let Some(url) = cli.bond_ledger_url.as_deref() {
        let token = cli.bond_ledger_token.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--bond-ledger-url requires --bond-ledger-token")
        })?;
        let ledger = GhostPayBondLedger::new(url, token)
            .map_err(|e| anyhow::anyhow!("ghost-pay bond ledger: {e}"))?;
        info!(endpoint = %url, "using GhostPayBondLedger");
        Some(Arc::new(ledger))
    } else {
        None
    };

    // Broadcaster: mock OR bitcoind, never both. Both absent → /witness
    // returns 503 broadcaster_not_configured on the round-completing
    // submission (same as before phase D landed).
    if cli.mock_broadcaster && cli.ghostd_url.is_some() {
        anyhow::bail!(
            "--mock-broadcaster and --ghostd-url are mutually exclusive; pick one."
        );
    }
    let broadcaster: Option<Arc<dyn Broadcaster>> = if cli.mock_broadcaster {
        warn!("using StubBroadcaster — round transactions are NOT actually broadcast");
        Some(Arc::new(StubBroadcaster::new()))
    } else if let Some(url) = cli.ghostd_url.as_deref() {
        let bb = match (
            cli.ghostd_cookie.as_ref(),
            cli.ghostd_user.as_deref(),
            cli.ghostd_pass.as_deref(),
        ) {
            (Some(cookie), None, None) => GhostdBroadcaster::from_cookie(url, cookie),
            (None, Some(u), Some(p)) => GhostdBroadcaster::new(url, u, p),
            (None, None, None) => anyhow::bail!(
                "--ghostd-url requires either --ghostd-cookie or \
                 --ghostd-user + --ghostd-pass for authentication"
            ),
            _ => anyhow::bail!(
                "--ghostd-cookie is mutually exclusive with \
                 --ghostd-user / --ghostd-pass"
            ),
        }
        .map_err(|e| anyhow::anyhow!("bitcoind broadcaster: {e}"))?;
        info!(endpoint = %url, "using GhostdBroadcaster");
        Some(Arc::new(bb))
    } else {
        None
    };

    // Mainnet refusal: if the operator configured peers without a
    // shared secret, the gossip route would accept unsigned writes
    // from any host that can reach `/api/v1/internal/`. That's only
    // OK if the operator firewalls the prefix; on mainnet we refuse
    // to start so misconfiguration can't silently expose it.
    if matches!(network, bitcoin::Network::Bitcoin)
        && !cli.peers.is_empty()
        && cli.peer_secret.is_none()
    {
        anyhow::bail!(
            "MAINNET REFUSAL: --peers without --peer-secret leaves \
             /api/v1/internal/gossip unauthenticated. Set \
             WRAITH_COORDINATOR_PEER_SECRET to the same value on \
             every coordinator in the pool."
        );
    }

    let mut state = CoordinatorState::with_components(
        network,
        Arc::new(wraith_protocol::SystemClock),
        Arc::new(wraith_protocol::RandomSessionIdGenerator),
        bond_ledger,
        cli.fee_address.clone(),
        broadcaster,
    );
    state.gossip_peer_secret = cli.peer_secret.clone();

    // Active/Standby state replication. When the operator supplies
    // peers, every session mutation publishes to all of them; the
    // peers' `/api/v1/internal/gossip` route applies the events.
    if !cli.peers.is_empty() {
        let runtime_handle = tokio::runtime::Handle::current();
        let sink = wraith_coordinator::gossip_http::HttpGossipSink::spawn(
            cli.peers.clone(),
            cli.peer_secret.clone(),
            &runtime_handle,
        );
        state.sessions.set_gossip_sink(Box::new(sink));
        info!(
            peers = ?cli.peers,
            authenticated = cli.peer_secret.is_some(),
            "gossip enabled — session state replicates to peer coordinators"
        );
    }

    let state = Arc::new(state);

    info!(
        listen = %cli.listen,
        network = ?network,
        bond_ledger = if cli.mock_bond_ledger {
            "mock"
        } else if cli.bond_ledger_url.is_some() {
            "ghost-pay"
        } else {
            "none"
        },
        broadcaster = if cli.mock_broadcaster {
            "stub"
        } else if cli.ghostd_url.is_some() {
            "bitcoind"
        } else {
            "none"
        },
        fee_address = ?cli.fee_address,
        "wraith-coordinator starting"
    );

    // Background tick: sweeps no-sign-deadline-expired sessions and
    // runs time-driven Filling-→-Locked / Filling-→-Failed transitions
    // even when no wallet is polling /status. Detached — terminates
    // when the runtime tears down.
    let _tick_handle = wraith_coordinator::tick::spawn_background_tick(state.clone());

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("failed to bind {}", cli.listen))?;
    axum::serve(listener, app)
        .await
        .context("axum serve loop terminated unexpectedly")?;
    Ok(())
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn parse_network(s: &str) -> Result<bitcoin::Network> {
    Ok(match s.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
        "signet" => bitcoin::Network::Signet,
        "testnet" => bitcoin::Network::Testnet,
        "regtest" => bitcoin::Network::Regtest,
        other => anyhow::bail!("unknown network '{other}'"),
    })
}

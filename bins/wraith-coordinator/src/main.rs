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

use wraith_coordinator::broadcaster::{Broadcaster, StubBroadcaster};
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
    /// signet / regtest until phase C wires the ghost-pay RPC client.
    #[arg(long, env = "WRAITH_COORDINATOR_MOCK_BOND_LEDGER")]
    mock_bond_ledger: bool,

    /// Use an in-memory StubBroadcaster instead of a real backend.
    /// Refused on mainnet — a stub broadcaster doesn't actually push
    /// transactions to the network. Use only in dev / signet /
    /// regtest until phase D wires the bitcoind RPC client.
    #[arg(long, env = "WRAITH_COORDINATOR_MOCK_BROADCASTER")]
    mock_broadcaster: bool,
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

    let bond_ledger: Option<Arc<dyn BondLedger>> = if cli.mock_bond_ledger {
        warn!("using MockBondLedger — bonds are NOT escrowed against real funds");
        Some(Arc::new(MockBondLedger::new()))
    } else {
        None
    };
    let broadcaster: Option<Arc<dyn Broadcaster>> = if cli.mock_broadcaster {
        warn!("using StubBroadcaster — round transactions are NOT actually broadcast");
        Some(Arc::new(StubBroadcaster::new()))
    } else {
        None
    };

    let state = Arc::new(CoordinatorState::with_components(
        network,
        Arc::new(wraith_protocol::SystemClock),
        Arc::new(wraith_protocol::RandomSessionIdGenerator),
        bond_ledger,
        cli.fee_address.clone(),
        broadcaster,
    ));

    info!(
        listen = %cli.listen,
        network = ?network,
        bond_ledger = if cli.mock_bond_ledger { "mock" } else { "none(phase-c)" },
        broadcaster = if cli.mock_broadcaster { "stub" } else { "none(phase-d)" },
        fee_address = ?cli.fee_address,
        "wraith-coordinator starting"
    );

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

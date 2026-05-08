import { useEffect, useMemo, useState } from "react";
import {
  lightL1Utxos,
  lightReceive,
  walletGhostId,
  wraithMixRun,
  type LightL1UtxoEntry,
  type WraithMixCompleted,
} from "../lib/tauri";

interface MixProps {
  activeWallet: string | null;
}

interface Tier {
  id: string;
  label: string;
  denom_sats: number;
  bond_sats: number;
}

// The hard-coded tiers that match the wraith-coordinator's defaults.
// In production we'd fetch these from `/api/v1/pool/discover`; the
// daemon doesn't proxy that yet so the screen lists the canonical
// four. Expand here if the coordinator config grows.
const TIERS: Tier[] = [
  { id: "100k_sats", label: "Tiny", denom_sats: 100_000, bond_sats: 500 },
  { id: "1m_sats", label: "Small", denom_sats: 1_000_000, bond_sats: 5_000 },
  { id: "10m_sats", label: "Medium", denom_sats: 10_000_000, bond_sats: 50_000 },
  { id: "100m_sats", label: "Large", denom_sats: 100_000_000, bond_sats: 500_000 },
];

const DEFAULT_COORDINATOR = "http://127.0.0.1:9100";

export function Mix({ activeWallet }: MixProps) {
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [coordinator, setCoordinator] = useState(DEFAULT_COORDINATOR);
  const [coordinatorPeersText, setCoordinatorPeersText] = useState("");
  const [tierId, setTierId] = useState(TIERS[0].id);

  const [utxoTxid, setUtxoTxid] = useState("");
  const [utxoVout, setUtxoVout] = useState("");
  const [utxoValue, setUtxoValue] = useState("");
  const [utxoScript, setUtxoScript] = useState("");
  const [bip86Index, setBip86Index] = useState("");
  const [mixOutAddr, setMixOutAddr] = useState("");
  const [changeAddr, setChangeAddr] = useState("");

  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<WraithMixCompleted | null>(null);

  const [utxos, setUtxos] = useState<LightL1UtxoEntry[]>([]);
  const [chainHeight, setChainHeight] = useState<number | null>(null);
  const [scanMax, setScanMax] = useState(32);

  const tier = useMemo(
    () => TIERS.find((t) => t.id === tierId) ?? TIERS[0],
    [tierId],
  );

  // On mount: pull ghost_id + auto-derive a fresh mix-output and
  // change address from the wallet's BIP86 keys. Indices 90 / 91
  // are arbitrary "high" gaps unlikely to collide with the user's
  // recent receive activity at index 0.
  useEffect(() => {
    if (!activeWallet) return;
    let alive = true;
    (async () => {
      try {
        const id = await walletGhostId();
        if (!alive) return;
        setGhostId(id.ghost_id);
        const mix = await lightReceive(90);
        const change = await lightReceive(91);
        if (!alive) return;
        if (!mixOutAddr) setMixOutAddr(mix.address);
        if (!changeAddr) setChangeAddr(change.address);
      } catch (e) {
        if (!alive) return;
        setErr((e as Error).message ?? String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [activeWallet]);

  const onRotateAddresses = async () => {
    setErr(null);
    setBusy(true);
    try {
      const baseIndex = 90 + Math.floor(Math.random() * 1000);
      const mix = await lightReceive(baseIndex);
      const change = await lightReceive(baseIndex + 1);
      setMixOutAddr(mix.address);
      setChangeAddr(change.address);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onScan = async () => {
    setErr(null);
    setScanning(true);
    try {
      const r = await lightL1Utxos(scanMax, 0);
      setUtxos(r.utxos);
      setChainHeight(r.chain_height);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setScanning(false);
    }
  };

  const onPick = (u: LightL1UtxoEntry) => {
    setUtxoTxid(u.txid);
    setUtxoVout(String(u.vout));
    setUtxoValue(String(u.amount_sats));
    setUtxoScript(u.scriptpubkey_hex);
    setBip86Index(String(u.bip86_index));
  };

  const onRun = async () => {
    setErr(null);
    setResult(null);

    if (!activeWallet) {
      setErr("No active wallet.");
      return;
    }
    if (!ghostId) {
      setErr("Ghost ID not loaded yet — try again in a second.");
      return;
    }
    const vout = Number(utxoVout);
    const value = Number(utxoValue);
    if (!utxoTxid || !Number.isInteger(vout) || vout < 0) {
      setErr("UTXO txid and a non-negative vout are required.");
      return;
    }
    if (!Number.isFinite(value) || value <= 0) {
      setErr("UTXO value (sats) must be positive.");
      return;
    }
    if (!utxoScript) {
      setErr("UTXO scriptPubKey (hex) is required for sighash.");
      return;
    }
    if (value < tier.denom_sats + tier.bond_sats) {
      setErr(
        `UTXO value (${value.toLocaleString()}) is below ` +
          `tier denom + bond (${(tier.denom_sats + tier.bond_sats).toLocaleString()}).`,
      );
      return;
    }
    if (!mixOutAddr) {
      setErr("Mix output address is required.");
      return;
    }

    const peers = coordinatorPeersText
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const idx = bip86Index.trim() ? Number(bip86Index) : undefined;
    if (idx !== undefined && (!Number.isInteger(idx) || idx < 0)) {
      setErr("BIP86 index must be a non-negative integer.");
      return;
    }

    setBusy(true);
    try {
      const r = await wraithMixRun({
        coordinator_url: coordinator.trim(),
        coordinator_peers: peers,
        tier_id: tierId,
        ghost_id: ghostId,
        utxo_txid: utxoTxid.trim(),
        utxo_vout: vout,
        utxo_value_sats: value,
        utxo_scriptpubkey_hex: utxoScript.trim(),
        change_address: changeAddr.trim() || undefined,
        mix_output_address: mixOutAddr.trim(),
        bip86_index: idx,
      });
      setResult(r);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!activeWallet) {
    return (
      <div className="screen">
        <h1>Mix</h1>
        <div className="card muted">
          Select and unlock a wallet first to run a Wraith CoinJoin.
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      <h1>Wraith CoinJoin</h1>

      {err && (
        <div className="card" style={{ borderColor: "var(--fail)" }}>
          {err}
        </div>
      )}

      {result && (
        <div className="card" style={{ borderColor: "var(--pass)" }}>
          <h2>Mix broadcast ✓</h2>
          <p className="muted" style={{ margin: 0 }}>
            The CoinJoin transaction hit the network. Once it
            confirms, your denom-sized output lands at the mix
            address — unlinked from the input UTXO.
          </p>
          <div className="kv">
            <div className="k">Session</div>
            <div className="v mono">{result.session_id}</div>
            <div className="k">Broadcast txid</div>
            <div className="v mono">{result.broadcast_txid}</div>
            <div className="k">Your output index</div>
            <div className="v">{result.mixed_output_tx_index}</div>
          </div>
        </div>
      )}

      <div className="card">
        <h2>Coordinator</h2>
        <div className="col">
          <label>Coordinator URL</label>
          <input
            className="mono"
            value={coordinator}
            onChange={(e) => setCoordinator(e.target.value)}
            disabled={busy}
            placeholder={DEFAULT_COORDINATOR}
          />
        </div>
        <div className="col">
          <label>
            Failover peer URLs (optional, comma- or space-separated)
          </label>
          <input
            className="mono"
            value={coordinatorPeersText}
            onChange={(e) => setCoordinatorPeersText(e.target.value)}
            disabled={busy}
            placeholder="http://standby-1.example:9100, http://standby-2.example:9100"
          />
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>
            Used in order if the primary is unreachable. HTTP errors
            from the primary do not trigger failover.
          </p>
        </div>
        <div className="col">
          <label>Tier</label>
          <select
            value={tierId}
            onChange={(e) => setTierId(e.target.value)}
            disabled={busy}
          >
            {TIERS.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label} — {t.denom_sats.toLocaleString()} sats (bond{" "}
                {t.bond_sats.toLocaleString()})
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Wallet UTXOs</h2>
          <div className="row">
            <label style={{ margin: 0 }}>Scan up to index</label>
            <input
              type="number"
              min={1}
              max={1024}
              value={scanMax}
              onChange={(e) =>
                setScanMax(Math.max(1, Math.min(1024, Number(e.target.value) || 32)))
              }
              style={{ width: 80 }}
              disabled={scanning || busy}
            />
            <button
              className="secondary"
              onClick={onScan}
              disabled={scanning || busy}
              title="Ask ghost-pay to run scantxoutset against this wallet's BIP86 receive addresses"
            >
              {scanning ? "Scanning…" : "Scan L1"}
            </button>
          </div>
        </div>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Unspent outputs at this wallet's BIP86 receive addresses
          0..{scanMax}. Backed by Bitcoin Core's{" "}
          <code>scantxoutset</code> via ghost-pay
          {chainHeight != null && (
            <> (chain height {chainHeight.toLocaleString()})</>
          )}
          . Mainnet scans take 5-15s; signet/regtest are sub-second.
        </p>
        {utxos.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Index</th>
                <th>Outpoint</th>
                <th>Amount (sats)</th>
                <th>Conf</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {utxos.map((u) => {
                const enough =
                  u.amount_sats >= tier.denom_sats + tier.bond_sats;
                return (
                  <tr key={`${u.txid}:${u.vout}`}>
                    <td className="mono">{u.bip86_index}</td>
                    <td className="mono muted">
                      {u.txid.slice(0, 12)}…:{u.vout}
                    </td>
                    <td>
                      {u.amount_sats.toLocaleString()}{" "}
                      {!enough && (
                        <span
                          className="pill warn"
                          title={`Needs ≥ ${(
                            tier.denom_sats + tier.bond_sats
                          ).toLocaleString()} for current tier`}
                        >
                          too small
                        </span>
                      )}
                    </td>
                    <td>{u.confirmations}</td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="secondary"
                        onClick={() => onPick(u)}
                        disabled={busy}
                      >
                        Use
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {!scanning && utxos.length === 0 && chainHeight !== null && (
          <p className="muted" style={{ margin: 0 }}>
            No unspent outputs found at indices 0..{scanMax}.
          </p>
        )}
      </div>

      <div className="card">
        <h2>Input UTXO</h2>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          The L1 UTXO to mix. Pick from the list above, or enter
          manually. Value must be at least denom + bond + dust.
        </p>
        <div className="row">
          <div className="col" style={{ flex: 3 }}>
            <label>txid</label>
            <input
              className="mono"
              value={utxoTxid}
              onChange={(e) => setUtxoTxid(e.target.value)}
              disabled={busy}
              placeholder="64-hex-char txid"
            />
          </div>
          <div className="col" style={{ flex: 1 }}>
            <label>vout</label>
            <input
              type="number"
              min={0}
              value={utxoVout}
              onChange={(e) => setUtxoVout(e.target.value)}
              disabled={busy}
            />
          </div>
        </div>
        <div className="row">
          <div className="col" style={{ flex: 1 }}>
            <label>value (sats)</label>
            <input
              type="number"
              min={1}
              value={utxoValue}
              onChange={(e) => setUtxoValue(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="col" style={{ flex: 1 }}>
            <label>BIP86 index (optional)</label>
            <input
              type="number"
              min={0}
              value={bip86Index}
              onChange={(e) => setBip86Index(e.target.value)}
              disabled={busy}
              placeholder="auto-scan if blank"
            />
          </div>
        </div>
        <div className="col">
          <label>scriptPubKey (hex)</label>
          <input
            className="mono"
            value={utxoScript}
            onChange={(e) => setUtxoScript(e.target.value)}
            disabled={busy}
            placeholder="P2TR scriptPubKey of the input"
          />
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Output addresses</h2>
          <button
            className="secondary"
            onClick={onRotateAddresses}
            disabled={busy}
            title="Re-derive a fresh mix-output and change address from the wallet's BIP86 keys"
          >
            Rotate
          </button>
        </div>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Auto-derived from this wallet's BIP86 keystore. The
          mix-output address receives the denom-sized output
          unlinked from your input. Change goes back to the wallet
          (if the input value exceeds denom + fees by more than
          dust).
        </p>
        <div className="col">
          <label>Mix output address</label>
          <input
            className="mono"
            value={mixOutAddr}
            onChange={(e) => setMixOutAddr(e.target.value)}
            disabled={busy}
          />
        </div>
        <div className="col">
          <label>Change address (optional)</label>
          <input
            className="mono"
            value={changeAddr}
            onChange={(e) => setChangeAddr(e.target.value)}
            disabled={busy}
          />
        </div>
      </div>

      <div className="row">
        <button className="primary" onClick={onRun} disabled={busy}>
          {busy ? "Running mix…" : "Run mix"}
        </button>
      </div>
    </div>
  );
}

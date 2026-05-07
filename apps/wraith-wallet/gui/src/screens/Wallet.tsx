import { useEffect, useState } from "react";
import {
  walletList,
  walletCreate,
  walletSelect,
  walletUnlock,
  walletGhostId,
  type WalletEntry,
} from "../lib/tauri";

export function Wallet() {
  const [wallets, setWallets] = useState<WalletEntry[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const refresh = async () => {
    setErr(null);
    try {
      const list = await walletList();
      setWallets(list.wallets);
      setActive(list.active);
      if (list.active) {
        try {
          const id = await walletGhostId();
          setGhostId(id.ghost_id);
        } catch {
          setGhostId(null);
        }
      } else {
        setGhostId(null);
      }
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const onCreate = async () => {
    const name = prompt("Wallet name:");
    if (!name) return;
    const passphrase = prompt(
      "Passphrase (used to encrypt the keystore at rest):",
    );
    if (!passphrase) return;
    setBusy(true);
    setErr(null);
    try {
      await walletCreate(name, passphrase);
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onSelect = async (name: string) => {
    setBusy(true);
    setErr(null);
    try {
      await walletSelect(name);
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onUnlock = async (name: string) => {
    const passphrase = prompt(`Passphrase for ${name}:`);
    if (!passphrase) return;
    setBusy(true);
    setErr(null);
    try {
      await walletUnlock(name, passphrase);
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="screen">
      <h1>Wallets</h1>

      {err && <div className="card" style={{ borderColor: "var(--fail)" }}>{err}</div>}

      <div className="card">
        <div className="card-header">
          <h2>{wallets.length === 0 ? "No wallets yet" : "Available wallets"}</h2>
          <button className="primary" onClick={onCreate} disabled={busy}>
            + New wallet
          </button>
        </div>
        {wallets.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>State</th>
                <th>Ghost ID</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {wallets.map((w) => (
                <tr key={w.name}>
                  <td>{w.name}</td>
                  <td>
                    {w.is_active && (
                      <span className="pill pass" style={{ marginRight: 6 }}>
                        active
                      </span>
                    )}
                    <span className={`pill ${w.is_unlocked ? "pass" : "mute"}`}>
                      {w.is_unlocked ? "unlocked" : "locked"}
                    </span>
                  </td>
                  <td className="mono muted">
                    {w.ghost_id ? `${w.ghost_id.slice(0, 18)}…` : "—"}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {!w.is_active && (
                      <button
                        className="secondary"
                        onClick={() => onSelect(w.name)}
                        disabled={busy}
                        style={{ marginRight: 6 }}
                      >
                        Select
                      </button>
                    )}
                    {!w.is_unlocked && (
                      <button
                        className="secondary"
                        onClick={() => onUnlock(w.name)}
                        disabled={busy}
                      >
                        Unlock
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {active && ghostId && (
        <div className="card">
          <h2>Active wallet identity</h2>
          <div className="kv">
            <div className="k">Name</div>
            <div className="v">{active}</div>
            <div className="k">Ghost ID</div>
            <div className="v">{ghostId}</div>
          </div>
        </div>
      )}
    </div>
  );
}

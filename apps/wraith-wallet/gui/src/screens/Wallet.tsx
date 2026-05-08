import { useEffect, useState } from "react";
import {
  daemonEnv,
  lightBalance,
  lightHistory,
  walletList,
  walletCreate,
  walletImport,
  walletSelect,
  walletShowMnemonic,
  walletUnlock,
  walletGhostId,
  type LightBalanceResponse,
  type LightHistoryEntry,
  type WalletEntry,
} from "../lib/tauri";

interface WalletProps {
  /// Bumped by App when the daemon pushes a `PaymentDetected`
  /// event. Used as a refetch trigger so the dashboard's balance
  /// + recent activity update immediately on a new receive.
  paymentTick?: number;
}

export function Wallet({ paymentTick = 0 }: WalletProps) {
  const [wallets, setWallets] = useState<WalletEntry[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [network, setNetwork] = useState<string | null>(null);
  const [balance, setBalance] = useState<LightBalanceResponse | null>(null);
  const [recent, setRecent] = useState<LightHistoryEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  /// Mnemonic to display once after create (or after a successful
  /// "show backup phrase" action). The user MUST acknowledge before
  /// the modal goes away — without writing this down, funds are
  /// unrecoverable on a daemon-state loss.
  const [mnemonicReveal, setMnemonicReveal] = useState<{
    name: string;
    mnemonic: string;
    reason: "freshly_created" | "backup_request";
  } | null>(null);

  const refresh = async () => {
    setErr(null);
    try {
      const list = await walletList();
      setWallets(list.wallets);
      setActive(list.active);
      try {
        const env = await daemonEnv();
        setNetwork(env.network);
      } catch {
        /* network is best-effort; keep prior value on transient failure */
      }
      if (list.active) {
        try {
          const id = await walletGhostId();
          setGhostId(id.ghost_id);
        } catch {
          setGhostId(null);
        }
      } else {
        setGhostId(null);
        setBalance(null);
        setRecent([]);
      }
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  // Refetch balance + recent activity when an active wallet is set
  // and on each `paymentTick` push from the daemon's watch loop. The
  // 6s interval is the top-up — pushes drive the immediate update.
  useEffect(() => {
    if (!active) return;
    let alive = true;
    const tick = async () => {
      try {
        const [b, h] = await Promise.all([
          lightBalance(),
          lightHistory(5, 0),
        ]);
        if (!alive) return;
        setBalance(b);
        setRecent(h.transactions);
      } catch {
        /* daemon may be transiently unavailable; keep prior values */
      }
    };
    tick();
    const id = setInterval(tick, 6000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [active, paymentTick]);

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
      const result = await walletCreate(name, passphrase);
      // Show the mnemonic ONCE, with a forcing acknowledgement. The
      // daemon doesn't keep this in plaintext anywhere — losing it
      // means losing the wallet. This is the single most important
      // piece of UX in the app.
      setMnemonicReveal({
        name: result.name,
        mnemonic: result.mnemonic,
        reason: "freshly_created",
      });
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onImport = async () => {
    const name = prompt("Wallet name:");
    if (!name) return;
    const mnemonic = prompt(
      "BIP-39 mnemonic (12 or 24 words, space-separated):",
    );
    if (!mnemonic) return;
    const passphrase = prompt(
      "Passphrase (used to encrypt the keystore at rest):",
    );
    if (!passphrase) return;
    setBusy(true);
    setErr(null);
    try {
      await walletImport(name, mnemonic.trim(), passphrase);
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onShowMnemonic = async (name: string) => {
    const passphrase = prompt(
      `Passphrase for ${name} (required to decrypt and show the backup phrase):`,
    );
    if (!passphrase) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await walletShowMnemonic(name, passphrase);
      setMnemonicReveal({
        name: r.name,
        mnemonic: r.mnemonic,
        reason: "backup_request",
      });
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

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable in some webview sandboxes */
    }
  };

  const fmtAmount = (sats: number) => {
    const sign = sats > 0 ? "+" : "";
    return `${sign}${sats.toLocaleString()}`;
  };
  const fmtTime = (unix: number) => new Date(unix * 1000).toLocaleString();

  return (
    <div className="screen">
      {err && <div className="card" style={{ borderColor: "var(--fail)" }}>{err}</div>}

      {mnemonicReveal && (
        <div
          className="card"
          style={{
            borderColor: "var(--warn, #d97706)",
            borderWidth: 2,
            background: "var(--bg)",
          }}
        >
          <h2 style={{ marginTop: 0 }}>
            {mnemonicReveal.reason === "freshly_created"
              ? `Backup phrase for "${mnemonicReveal.name}"`
              : `Backup phrase: ${mnemonicReveal.name}`}
          </h2>
          <p style={{ margin: 0 }}>
            <strong>Write these 12 words down on paper.</strong> Anyone
            with this phrase can spend funds in this wallet. The
            daemon does not keep it in plaintext — without it, fund
            recovery is impossible if the keystore file or its
            passphrase are lost.
          </p>
          <div
            className="mono"
            style={{
              marginTop: 12,
              padding: 16,
              background: "var(--bg-subtle, rgba(0,0,0,0.06))",
              border: "1px solid var(--border)",
              borderRadius: 6,
              wordSpacing: 4,
              lineHeight: 1.8,
              fontSize: 16,
              userSelect: "text",
            }}
          >
            {mnemonicReveal.mnemonic}
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <button
              className="secondary"
              onClick={() => copy(mnemonicReveal.mnemonic)}
              style={{ marginRight: 8 }}
            >
              {copied ? "copied" : "Copy to clipboard"}
            </button>
            <button
              className="primary"
              onClick={() => setMnemonicReveal(null)}
            >
              I have written it down
            </button>
          </div>
        </div>
      )}

      {/* Dashboard hero — only shown when a wallet is active. The
          big-balance, copy-id, recent-activity layout is the
          first-impression screen the user sees on app open. */}
      {active && ghostId && (
        <div className="card" style={{ paddingBottom: 8 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "baseline",
              marginBottom: 12,
            }}
          >
            <div>
              <div className="muted" style={{ fontSize: 13 }}>
                {active}
                {network && (
                  <span className="pill mute" style={{ marginLeft: 8 }}>
                    {network}
                  </span>
                )}
              </div>
              <div
                style={{
                  fontSize: 36,
                  fontWeight: 600,
                  letterSpacing: "-0.02em",
                  marginTop: 4,
                }}
              >
                {balance == null
                  ? "—"
                  : balance.spendable_sats.toLocaleString()}{" "}
                <span
                  className="muted"
                  style={{ fontSize: 18, fontWeight: 400 }}
                >
                  sats
                </span>
              </div>
              {balance != null && balance.pending_sats > 0 && (
                <div
                  className="muted"
                  style={{ fontSize: 13, marginTop: 2 }}
                >
                  +{balance.pending_sats.toLocaleString()} pending
                </div>
              )}
            </div>
          </div>

          <div className="kv">
            <div className="k">Ghost ID</div>
            <div
              className="v mono"
              style={{
                display: "flex",
                gap: 8,
                alignItems: "center",
                wordBreak: "break-all",
              }}
            >
              <span style={{ flex: 1 }}>{ghostId}</span>
              <button
                className="secondary"
                onClick={() => copy(ghostId)}
                style={{ flexShrink: 0 }}
              >
                {copied ? "copied" : "Copy"}
              </button>
            </div>
          </div>

          {recent.length > 0 && (
            <>
              <h2 style={{ marginTop: 18 }}>Recent activity</h2>
              <table className="table">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Type</th>
                    <th>Amount</th>
                    <th>Memo</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((e) => (
                    <tr key={e.txid + e.timestamp}>
                      <td className="muted">{fmtTime(e.timestamp)}</td>
                      <td>
                        <span
                          className={`pill ${
                            e.tx_type === "receive" ? "pass" : "mute"
                          }`}
                        >
                          {e.tx_type}
                        </span>
                      </td>
                      <td
                        className="mono"
                        style={{
                          color:
                            e.amount_sats > 0
                              ? "var(--pass)"
                              : e.amount_sats < 0
                                ? "var(--fail)"
                                : "var(--fg)",
                        }}
                      >
                        {fmtAmount(e.amount_sats)}
                      </td>
                      <td className="muted">{e.memo ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2>{wallets.length === 0 ? "No wallets yet" : "Wallets"}</h2>
          <div className="row">
            <button
              className="secondary"
              onClick={onImport}
              disabled={busy}
              style={{ marginRight: 6 }}
            >
              Import from mnemonic
            </button>
            <button className="primary" onClick={onCreate} disabled={busy}>
              + New wallet
            </button>
          </div>
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
                        style={{ marginRight: 6 }}
                      >
                        Unlock
                      </button>
                    )}
                    <button
                      className="secondary"
                      onClick={() => onShowMnemonic(w.name)}
                      disabled={busy}
                      title="Decrypt and display the BIP-39 backup phrase"
                    >
                      Backup
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import {
  lightBalance,
  lightSend,
  type LightBalanceResponse,
  type LightSendMode,
} from "../lib/tauri";

interface SendProps {
  activeWallet: string | null;
}

interface ModeOption {
  id: LightSendMode;
  label: string;
  hint: string;
}

const MODES: ModeOption[] = [
  {
    id: "ghostpay",
    label: "Ghost Pay (instant L2)",
    hint: "Instant off-chain transfer through the operator. No on-chain tx, no confirmation wait — settles to L1 in batches later.",
  },
  {
    id: "wraith",
    label: "Wraith (L1 CoinJoin)",
    hint: "Routes through a Wraith Lite mix round so the on-chain trail is unlinked from the wallet's UTXOs. Slower (waits for the round to fill).",
  },
  {
    id: "confidential",
    label: "Confidential (L2)",
    hint: "Zero-knowledge-shielded L2 transfer. Server learns nothing about amount or sender.",
  },
];

/// Recipient prefix → human-readable network/format identifier.
/// Surfaced to the user as a "we recognise this as X" hint so a
/// typo in the address surfaces before submit. We DON'T block
/// submit on this — Ghost-id formats may evolve and we shouldn't
/// hard-fail on a prefix we don't yet know.
function recipientShape(s: string): string | null {
  const t = s.trim();
  if (!t) return null;
  if (t.startsWith("ghost1q")) return "Ghost-id (mainnet)";
  if (t.startsWith("tghost1q")) return "Ghost-id (signet/testnet)";
  if (t.startsWith("sghost1q")) return "Ghost-id (signet)";
  if (t.startsWith("rghost1q")) return "Ghost-id (regtest)";
  if (t.startsWith("bc1")) return "Bitcoin address (mainnet, segwit)";
  if (t.startsWith("tb1")) return "Bitcoin address (testnet/signet, segwit)";
  if (t.startsWith("bcrt1")) return "Bitcoin address (regtest, segwit)";
  if (t.startsWith("1") || t.startsWith("3")) return "Bitcoin address (mainnet, legacy)";
  return null;
}

/// localStorage key for recent recipient suggestions, scoped per
/// wallet. Capped at 10 entries; most-recent first.
function recentsKey(wallet: string | null): string {
  return `wraith.send.recents:${wallet ?? "_none_"}`;
}

function loadRecents(wallet: string | null): string[] {
  if (!wallet) return [];
  try {
    const raw = localStorage.getItem(recentsKey(wallet));
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.filter((s): s is string => typeof s === "string").slice(0, 10);
  } catch {
    return [];
  }
}

function pushRecent(wallet: string | null, recipient: string): void {
  if (!wallet) return;
  try {
    const existing = loadRecents(wallet);
    const next = [recipient, ...existing.filter((r) => r !== recipient)].slice(
      0,
      10,
    );
    localStorage.setItem(recentsKey(wallet), JSON.stringify(next));
  } catch {
    /* quota / sandbox */
  }
}

export function Send({ activeWallet }: SendProps) {
  const [balance, setBalance] = useState<LightBalanceResponse | null>(null);
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [memo, setMemo] = useState("");
  const [mode, setMode] = useState<LightSendMode>("ghostpay");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [recents, setRecents] = useState<string[]>(() =>
    loadRecents(activeWallet),
  );

  useEffect(() => {
    setRecents(loadRecents(activeWallet));
  }, [activeWallet]);

  useEffect(() => {
    if (!activeWallet) return;
    let alive = true;
    const tick = async () => {
      try {
        const b = await lightBalance();
        if (alive) setBalance(b);
      } catch {
        /* ignore — daemon may be transiently unavailable */
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [activeWallet]);

  const validate = (): string | null => {
    if (!recipient.trim()) return "Recipient is required.";
    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0 || !Number.isInteger(amt)) {
      return "Amount must be a positive integer (sats).";
    }
    // Soft-warn over balance — daemon will reject anyway, but surface
    // it before the user clicks confirm.
    if (
      balance &&
      balance.confirmed_sats != null &&
      amt > balance.confirmed_sats
    ) {
      return `Amount exceeds confirmed balance (${balance.confirmed_sats.toLocaleString()} sats).`;
    }
    return null;
  };

  const onReview = () => {
    setErr(null);
    setSuccess(null);
    const v = validate();
    if (v) {
      setErr(v);
      return;
    }
    setConfirming(true);
  };

  const onConfirm = async () => {
    const amt = Number(amount);
    setBusy(true);
    setErr(null);
    try {
      await lightSend(
        recipient.trim(),
        amt,
        mode,
        memo.trim() || undefined,
      );
      setSuccess(
        `Sent ${amt.toLocaleString()} sats to ${recipient.slice(0, 18)}…`,
      );
      pushRecent(activeWallet, recipient.trim());
      setRecents(loadRecents(activeWallet));
      setRecipient("");
      setAmount("");
      setMemo("");
      setConfirming(false);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onCancel = () => {
    setConfirming(false);
  };

  if (!activeWallet) {
    return (
      <div className="screen">
        <h1>Send</h1>
        <div className="card muted">
          Select a wallet first to send L2 payments.
        </div>
      </div>
    );
  }

  const shape = recipientShape(recipient);
  const modeOption = MODES.find((m) => m.id === mode) ?? MODES[0];
  const amtNum = Number(amount);

  return (
    <div className="screen">
      <h1>Send</h1>

      <div className="card">
        <h2>Available balance</h2>
        <div className="kv">
          <div className="k">Confirmed</div>
          <div className="v">
            {balance?.confirmed_sats?.toLocaleString() ?? "—"} sats
          </div>
          <div className="k">Pending</div>
          <div className="v">
            {balance?.unconfirmed_sats?.toLocaleString() ?? "—"} sats
          </div>
          {balance?.locked_sats != null && balance.locked_sats > 0 && (
            <>
              <div className="k">In locks</div>
              <div className="v">
                {balance.locked_sats.toLocaleString()} sats
              </div>
            </>
          )}
        </div>
      </div>

      {confirming ? (
        // Confirmation step — full review of what's about to go out.
        // Prevents a slip of the finger from sending the wrong amount
        // to the wrong recipient.
        <div className="card" style={{ borderColor: "var(--accent, var(--border))" }}>
          <h2>Confirm payment</h2>
          {err && (
            <div
              className="pill fail"
              style={{ alignSelf: "flex-start", marginBottom: 8 }}
            >
              {err}
            </div>
          )}
          <div className="kv">
            <div className="k">Mode</div>
            <div className="v">
              <strong>{modeOption.label}</strong>
              <div
                className="muted"
                style={{ fontSize: 12, marginTop: 4 }}
              >
                {modeOption.hint}
              </div>
            </div>
            <div className="k">Amount</div>
            <div className="v">
              <strong style={{ fontSize: 18 }}>
                {amtNum.toLocaleString()} sats
              </strong>
            </div>
            <div className="k">Recipient</div>
            <div className="v mono" style={{ wordBreak: "break-all" }}>
              {recipient}
              {shape && (
                <div
                  className="muted"
                  style={{ fontFamily: "var(--font-base, sans-serif)", fontSize: 12, marginTop: 4 }}
                >
                  {shape}
                </div>
              )}
            </div>
            {memo && (
              <>
                <div className="k">Memo</div>
                <div className="v">{memo}</div>
              </>
            )}
          </div>
          <div className="row" style={{ marginTop: 16 }}>
            <button
              className="secondary"
              onClick={onCancel}
              disabled={busy}
              style={{ marginRight: 8 }}
            >
              Back
            </button>
            <button
              className="primary"
              onClick={onConfirm}
              disabled={busy}
            >
              {busy ? "Sending…" : "Confirm send"}
            </button>
          </div>
        </div>
      ) : (
        <div className="card">
          <h2>New payment</h2>
          {err && (
            <div className="pill fail" style={{ alignSelf: "flex-start" }}>
              {err}
            </div>
          )}
          {success && (
            <div className="pill pass" style={{ alignSelf: "flex-start" }}>
              {success}
            </div>
          )}
          <div className="col">
            <label>Recipient (Ghost ID or Bitcoin address)</label>
            <input
              className="mono"
              placeholder="ghost1q… / tghost1q… / bc1q…"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              disabled={busy}
              list="send-recents"
            />
            {recents.length > 0 && (
              <datalist id="send-recents">
                {recents.map((r) => (
                  <option key={r} value={r} />
                ))}
              </datalist>
            )}
            {shape && (
              <span className="muted" style={{ fontSize: 12 }}>
                {shape}
              </span>
            )}
          </div>
          <div className="row">
            <div className="col" style={{ flex: 1 }}>
              <label>Amount (sats)</label>
              <input
                type="number"
                min={1}
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                disabled={busy}
              />
            </div>
            <div className="col" style={{ flex: 2 }}>
              <label>Memo (optional, ≤59 chars)</label>
              <input
                maxLength={59}
                value={memo}
                onChange={(e) => setMemo(e.target.value)}
                disabled={busy}
              />
            </div>
          </div>
          <div className="col">
            <label>Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as LightSendMode)}
              disabled={busy}
            >
              {MODES.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
            <span className="muted" style={{ fontSize: 12 }}>
              {modeOption.hint}
            </span>
          </div>
          <div className="row">
            <button className="primary" onClick={onReview} disabled={busy}>
              Review
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

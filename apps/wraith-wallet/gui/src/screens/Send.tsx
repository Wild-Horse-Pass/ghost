import { useEffect, useState } from "react";
import { lightBalance, lightSend, type LightBalanceResponse } from "../lib/tauri";

interface SendProps {
  activeWallet: string | null;
}

export function Send({ activeWallet }: SendProps) {
  const [balance, setBalance] = useState<LightBalanceResponse | null>(null);
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [memo, setMemo] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

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

  const onSend = async () => {
    setErr(null);
    setSuccess(null);
    const amt = Number(amount);
    if (!recipient || !Number.isFinite(amt) || amt <= 0) {
      setErr("Recipient and a positive sat amount are required.");
      return;
    }
    setBusy(true);
    try {
      await lightSend(recipient.trim(), amt, memo.trim() || undefined);
      setSuccess(
        `Sent ${amt.toLocaleString()} sats to ${recipient.slice(0, 18)}…`,
      );
      setAmount("");
      setMemo("");
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
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

  return (
    <div className="screen">
      <h1>Send (L2)</h1>

      <div className="card">
        <h2>Available balance</h2>
        <div className="kv">
          <div className="k">Spendable</div>
          <div className="v">{balance?.spendable_sats?.toLocaleString() ?? "—"} sats</div>
          <div className="k">Pending</div>
          <div className="v">{balance?.pending_sats?.toLocaleString() ?? "—"} sats</div>
        </div>
      </div>

      <div className="card">
        <h2>New L2 payment</h2>
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
          <label>Recipient (Ghost ID or address)</label>
          <input
            className="mono"
            placeholder="ghost1q…"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            disabled={busy}
          />
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
        <div className="row">
          <button className="primary" onClick={onSend} disabled={busy}>
            {busy ? "Sending…" : "Send"}
          </button>
        </div>
      </div>
    </div>
  );
}

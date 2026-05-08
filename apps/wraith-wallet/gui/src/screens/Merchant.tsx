import { useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  daemonEnv,
  lightL1Utxos,
  lightReceive,
  walletGhostId,
  type DetectedPayment,
  type LightL1UtxoEntry,
  onPaymentDetected,
  startWatch,
} from "../lib/tauri";

interface MerchantProps {
  activeWallet: string | null;
  /// Bumped by App on every `payment-detected` push. We listen to
  /// the same event ourselves but use the tick as a re-render
  /// trigger so the UI reflects in-flight detections immediately.
  paymentTick?: number;
}

interface OpenInvoice {
  /// Stable id within this session. Used to key the QR + match
  /// detections to this invoice.
  id: number;
  amount_sats: number;
  memo: string;
  /// BIP86 receive address derived for THIS invoice. Direct
  /// (non-silent-payment) deposits land here; we poll the L1
  /// scanner to spot them.
  address: string;
  /// Wallet's bech32 ghost-id, embedded in the BIP-21 URI as
  /// `ghost=<id>` so Ghost-aware wallets can use the BIP-352
  /// silent-payment path even though the QR is BIP-21.
  ghost_id: string;
  /// BIP86 derivation index of `address`, useful for the L1 scan
  /// that finds direct deposits.
  bip86_index: number;
  /// `Date.now()` at invoice creation. Detections that arrive
  /// before this are from earlier sales and don't count toward
  /// this invoice.
  opened_at: number;
}

interface PaidReceipt {
  invoice_id: number;
  amount_sats: number;
  memo: string;
  /// `silent_payment` (BIP-352 detection via GSP) or `direct`
  /// (UTXO landed at the per-invoice BIP86 address).
  method: "silent_payment" | "direct";
  /// txid for direct deposits, or the silent-payment txid if the
  /// detection carried one.
  txid: string;
  paid_at: number;
}

/// First merchant invoice index. Picks a high gap so it doesn't
/// collide with the Receive screen's index 0 / Mix screen's 90+.
/// Per-invoice indices increment from here.
const MERCHANT_INDEX_BASE = 5000;

const SAT = 100_000_000;

/// localStorage key for persisted takings, scoped per wallet.
function takingsKey(wallet: string | null): string {
  return `wraith.merchant.takings:${wallet ?? "_none_"}`;
}

/// Start of the current local-day window (midnight local time) in
/// epoch ms. Receipts older than this are filtered out of the
/// loaded "today's takings" view.
function startOfLocalDay(): number {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function loadTakings(wallet: string | null): PaidReceipt[] {
  if (!wallet) return [];
  try {
    const raw = localStorage.getItem(takingsKey(wallet));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as PaidReceipt[];
    if (!Array.isArray(parsed)) return [];
    const dayStart = startOfLocalDay();
    return parsed.filter((r) => r && typeof r.paid_at === "number" && r.paid_at >= dayStart);
  } catch {
    // Corrupt JSON / quota error / etc. — start fresh, don't break
    // the merchant flow over a storage quirk.
    return [];
  }
}

function saveTakings(wallet: string | null, takings: PaidReceipt[]): void {
  if (!wallet) return;
  try {
    localStorage.setItem(takingsKey(wallet), JSON.stringify(takings));
  } catch {
    /* quota or sandbox restrictions — silently drop */
  }
}

/// Build a CSV blob from the receipts. Header row + one row per
/// receipt with the same columns as the on-screen takings table
/// plus the txid (so an accountant can match each row to the
/// underlying tx). Memos are quoted and inner quotes doubled per
/// RFC 4180.
function takingsToCsv(takings: PaidReceipt[]): string {
  const header = "paid_at_iso,amount_sats,method,memo,txid,invoice_id";
  const csvEscape = (s: string): string => {
    // Wrap any field containing comma / quote / newline in quotes,
    // and double internal quotes per RFC 4180.
    if (/[",\n\r]/.test(s)) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };
  const rows = takings.map((r) =>
    [
      new Date(r.paid_at).toISOString(),
      String(r.amount_sats),
      r.method,
      csvEscape(r.memo),
      r.txid,
      String(r.invoice_id),
    ].join(","),
  );
  return [header, ...rows].join("\n");
}

/// Trigger a browser download of the supplied text content. Uses
/// a Blob URL + synthetic anchor click; revokes the URL on a
/// short timer so the GC can reclaim the blob. Works in the
/// Tauri webview without needing the dialog plugin.
function downloadText(filename: string, content: string): void {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

type UriFormat = "bip21" | "ghost";

/// BIP-21 URI — the universal Bitcoin wallet format. Amount in BTC.
/// Ghost-aware wallets also pick up `ghost=<id>` and route via the
/// BIP-352 silent-payment path, but no Ghost knowledge is required.
function bip21Uri(
  address: string,
  amount_sats: number,
  memo: string,
  ghost_id: string,
): string {
  const params = new URLSearchParams();
  params.set("amount", (amount_sats / SAT).toFixed(8));
  if (memo) params.set("label", memo);
  if (ghost_id) params.set("ghost", ghost_id);
  return `bitcoin:${address}?${params.toString()}`;
}

/// Ghost native URI — what the mobile TAP wallet emits and scans.
/// Format defined in apps/ghost-tap/core/src/payment/qr.rs:
///   ghost:<address>?amount=<sats>&memo=<text>&label=<text>
/// Amount is in raw sats (NOT BTC). Use this format when the
/// payer is on the mobile TAP app, since its parser only accepts
/// the `ghost:` scheme today.
function ghostUri(address: string, amount_sats: number, memo: string): string {
  const params = new URLSearchParams();
  params.set("amount", String(amount_sats));
  if (memo) params.set("memo", memo);
  return `ghost:${address}?${params.toString()}`;
}

function buildUri(
  format: UriFormat,
  address: string,
  amount_sats: number,
  memo: string,
  ghost_id: string,
): string {
  return format === "ghost"
    ? ghostUri(address, amount_sats, memo)
    : bip21Uri(address, amount_sats, memo, ghost_id);
}

export function Merchant({ activeWallet, paymentTick = 0 }: MerchantProps) {
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [networkLabel, setNetworkLabel] = useState<string | null>(null);
  const [invoiceIndex, setInvoiceIndex] = useState(MERCHANT_INDEX_BASE);
  const [amountInput, setAmountInput] = useState("");
  const [memoInput, setMemoInput] = useState("");
  const [open, setOpen] = useState<OpenInvoice | null>(null);
  const [paid, setPaid] = useState<PaidReceipt | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  /// Active URI format for the open invoice's QR. BIP-21 is the
  /// universal wallet format; `ghost:` is what mobile TAP scans.
  /// Toggle on the open-invoice card swaps the QR live — the
  /// underlying address is the same, only the encoding changes.
  const [uriFormat, setUriFormat] = useState<UriFormat>("bip21");

  // Day's takings — persisted to localStorage so it survives
  // navigation, page reloads, and short daemon restarts. Keyed by
  // wallet name so different wallets keep separate ledgers.
  // Auto-rolls at midnight local time: receipts older than the
  // current local-day window get filtered out so "today's takings"
  // stays meaningful.
  const [takings, setTakings] = useState<PaidReceipt[]>(() =>
    loadTakings(activeWallet),
  );

  // Persist on every change. Keep this lightweight — receipts
  // table is bounded by the merchant's daily volume, so a few
  // hundred rows of JSON in localStorage is fine.
  useEffect(() => {
    saveTakings(activeWallet, takings);
  }, [activeWallet, takings]);

  // Reload when the active wallet changes (kiosk mode pins one
  // wallet, but in regular use users may switch).
  useEffect(() => {
    setTakings(loadTakings(activeWallet));
  }, [activeWallet]);

  // Latest open invoice, accessed from inside the detection
  // listener without re-binding the listener every render.
  const openRef = useRef<OpenInvoice | null>(null);
  useEffect(() => {
    openRef.current = open;
  }, [open]);

  // Bootstrap: ghost_id + network label.
  useEffect(() => {
    if (!activeWallet) return;
    let alive = true;
    (async () => {
      try {
        const id = await walletGhostId();
        if (alive) setGhostId(id.ghost_id);
        const env = await daemonEnv();
        if (alive) setNetworkLabel(env.network);
        // The watch loop on the daemon side is idempotent — calling
        // start_watch is a no-op if it's already running. Cheap to
        // call here so the merchant screen works even if no other
        // screen has opened the watch yet.
        await startWatch();
      } catch (e) {
        if (alive) setErr((e as Error).message ?? String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [activeWallet]);

  // Listen for BIP-352 silent-payment detections. Match the open
  // invoice's expected amount to flip to paid. Detections from
  // before the invoice was opened are ignored — those are stale.
  useEffect(() => {
    let alive = true;
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await onPaymentDetected((p: DetectedPayment) => {
          if (!alive) return;
          const inv = openRef.current;
          if (!inv) return;
          const detect_ms = p.received_at * 1000;
          if (detect_ms < inv.opened_at - 5_000) return;
          // BIP-352 amount can land EXACTLY on the invoice amount
          // (the customer's wallet honoured the URI). We allow
          // overpayment; under-payment doesn't count.
          if (p.amount_sats < inv.amount_sats) return;
          markPaid({
            invoice_id: inv.id,
            amount_sats: p.amount_sats,
            memo: inv.memo,
            method: "silent_payment",
            txid: p.txid,
            paid_at: Date.now(),
          });
        });
      } catch (e) {
        if (alive) setErr((e as Error).message ?? String(e));
      }
    })();
    return () => {
      alive = false;
      if (unlisten) unlisten();
    };
    // The listener is stable — it reads from openRef each tick.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Poll the L1 UTXO scanner while an invoice is open. Catches
  // direct deposits (non-Ghost wallets paying the BIP86 address
  // directly). Disabled once paid, and unmounted with the screen.
  useEffect(() => {
    if (!open) return;
    let alive = true;
    const tick = async () => {
      try {
        // Scan up to and including this invoice's index. Filter
        // strictly by address so other invoices' UTXOs in the
        // history don't trigger a false positive.
        const r = await lightL1Utxos(open.bip86_index + 1, 0);
        if (!alive) return;
        const match: LightL1UtxoEntry | undefined = r.utxos.find(
          (u) =>
            u.address === open.address && u.amount_sats >= open.amount_sats,
        );
        if (match) {
          markPaid({
            invoice_id: open.id,
            amount_sats: match.amount_sats,
            memo: open.memo,
            method: "direct",
            txid: match.txid,
            paid_at: Date.now(),
          });
        }
      } catch {
        /* scantxoutset is best-effort; transient failures don't
           break the merchant screen — the BIP-352 path is still
           live in parallel */
      }
    };
    tick();
    const id = setInterval(tick, 4000);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // paymentTick is a render trigger only; the polling cadence
    // is governed by the interval above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, paymentTick]);

  const markPaid = (receipt: PaidReceipt) => {
    if (paid) return; // already settled — ignore late-firing detections
    setPaid(receipt);
    setTakings((prev) => [receipt, ...prev]);
    setOpen(null);
  };

  const onCreateInvoice = async () => {
    setErr(null);
    const amt = Number(amountInput);
    if (!Number.isFinite(amt) || amt <= 0 || !Number.isInteger(amt)) {
      setErr("Amount must be a positive integer (sats).");
      return;
    }
    if (!ghostId) {
      setErr("Ghost ID not loaded yet — try again in a second.");
      return;
    }
    setBusy(true);
    try {
      const recv = await lightReceive(invoiceIndex);
      const id = invoiceIndex;
      setOpen({
        id,
        amount_sats: amt,
        memo: memoInput.trim(),
        address: recv.address,
        ghost_id: ghostId,
        bip86_index: id,
        opened_at: Date.now(),
      });
      setPaid(null);
      setInvoiceIndex(invoiceIndex + 1);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onCancel = () => {
    setOpen(null);
    setPaid(null);
  };

  const onNextSale = () => {
    setOpen(null);
    setPaid(null);
    setAmountInput("");
    setMemoInput("");
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* clipboard unavailable in some webview sandboxes */
    }
  };

  if (!activeWallet) {
    return (
      <div className="screen">
        <h1>Merchant</h1>
        <div className="card muted">
          Select and unlock a wallet first to take payments.
        </div>
      </div>
    );
  }

  // Paid receipt view — full-screen success.
  if (paid) {
    return (
      <div className="screen">
        <div
          className="card"
          style={{
            borderColor: "var(--pass)",
            borderWidth: 2,
            textAlign: "center",
            padding: 32,
          }}
        >
          <div style={{ fontSize: 48, color: "var(--pass)", marginBottom: 8 }}>
            ✓
          </div>
          <div style={{ fontSize: 14, color: "var(--muted)" }}>PAID</div>
          <div
            style={{
              fontSize: 42,
              fontWeight: 600,
              letterSpacing: "-0.02em",
              margin: "8px 0",
            }}
          >
            {paid.amount_sats.toLocaleString()}{" "}
            <span style={{ fontSize: 22, fontWeight: 400 }}>sats</span>
          </div>
          {paid.memo && (
            <div className="muted" style={{ fontSize: 14 }}>
              {paid.memo}
            </div>
          )}
          <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>
            via {paid.method === "silent_payment" ? "Ghost silent payment" : "direct deposit"}
            {" · "}
            {new Date(paid.paid_at).toLocaleTimeString()}
          </div>
          <div className="mono muted" style={{ fontSize: 11, marginTop: 4 }}>
            {paid.txid}
          </div>
          <button
            className="primary"
            onClick={onNextSale}
            style={{ marginTop: 24, padding: "10px 24px", fontSize: 16 }}
          >
            Next sale
          </button>
        </div>

        {takings.length > 0 && <TakingsCard takings={takings} onClear={() => setTakings([])} />}
      </div>
    );
  }

  // Open invoice view — QR + amount, waiting for payment.
  if (open) {
    const uri = buildUri(
      uriFormat,
      open.address,
      open.amount_sats,
      open.memo,
      open.ghost_id,
    );
    return (
      <div className="screen">
        {err && (
          <div className="card" style={{ borderColor: "var(--fail)" }}>
            {err}
          </div>
        )}
        <div className="card" style={{ textAlign: "center", padding: 24 }}>
          <div className="muted" style={{ fontSize: 13 }}>
            INVOICE #{open.id}
            {networkLabel && (
              <span className="pill mute" style={{ marginLeft: 8 }}>
                {networkLabel}
              </span>
            )}
          </div>
          <div
            style={{
              fontSize: 42,
              fontWeight: 600,
              letterSpacing: "-0.02em",
              margin: "4px 0 16px",
            }}
          >
            {open.amount_sats.toLocaleString()}{" "}
            <span style={{ fontSize: 22, fontWeight: 400 }}>sats</span>
          </div>
          {open.memo && (
            <div className="muted" style={{ fontSize: 14, marginBottom: 12 }}>
              {open.memo}
            </div>
          )}
          <div
            className="row"
            style={{
              justifyContent: "center",
              marginBottom: 12,
              gap: 4,
            }}
          >
            <button
              className={uriFormat === "bip21" ? "primary" : "secondary"}
              onClick={() => setUriFormat("bip21")}
              style={{ fontSize: 12, padding: "4px 10px" }}
              title="BIP-21 — universal Bitcoin wallet format. Ghost-aware wallets pick up the BIP-352 silent-payment path via the ghost= extension."
            >
              Any wallet
            </button>
            <button
              className={uriFormat === "ghost" ? "primary" : "secondary"}
              onClick={() => setUriFormat("ghost")}
              style={{ fontSize: 12, padding: "4px 10px" }}
              title="ghost: — Ghost-native URI. Use when the customer is paying from the mobile TAP wallet."
            >
              Ghost (TAP)
            </button>
          </div>
          <div
            style={{
              display: "inline-block",
              padding: 16,
              background: "white",
              borderRadius: 8,
              marginBottom: 12,
            }}
          >
            <QRCodeSVG value={uri} size={240} level="M" />
          </div>
          <div
            className="mono"
            style={{
              fontSize: 11,
              wordBreak: "break-all",
              padding: 8,
              background: "var(--bg)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              userSelect: "text",
              textAlign: "left",
            }}
          >
            {uri}
          </div>
          <div className="row" style={{ justifyContent: "center", marginTop: 12 }}>
            <button
              className="secondary"
              onClick={() => copy(uri)}
              style={{ marginRight: 8 }}
            >
              Copy URI
            </button>
            <button className="secondary" onClick={onCancel}>
              Cancel
            </button>
          </div>
          <div
            className="muted"
            style={{ fontSize: 12, marginTop: 16, fontStyle: "italic" }}
          >
            <span
              className="pill mute"
              style={{ marginRight: 6, fontSize: 11 }}
            >
              waiting
            </span>
            Listening for payment via Ghost silent-payment AND direct
            deposit. Either path will mark this invoice paid.
          </div>
        </div>

        {takings.length > 0 && <TakingsCard takings={takings} onClear={() => setTakings([])} />}
      </div>
    );
  }

  // Idle — invoice creation form + day's takings summary.
  return (
    <div className="screen">
      <h1>Merchant</h1>
      {err && (
        <div className="card" style={{ borderColor: "var(--fail)" }}>
          {err}
        </div>
      )}

      <div className="card">
        <h2>New invoice</h2>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Generates a BIP-21 payment QR with a Ghost extension.
          Bitcoin wallets see a regular BIP-21 URI; Ghost-aware
          wallets pick up the silent-payment path automatically.
        </p>
        <div className="row">
          <div className="col" style={{ flex: 1 }}>
            <label>Amount (sats)</label>
            <input
              type="number"
              min={1}
              value={amountInput}
              onChange={(e) => setAmountInput(e.target.value)}
              disabled={busy}
              autoFocus
            />
          </div>
          <div className="col" style={{ flex: 2 }}>
            <label>Memo (optional)</label>
            <input
              maxLength={59}
              value={memoInput}
              onChange={(e) => setMemoInput(e.target.value)}
              disabled={busy}
              placeholder="e.g. Coffee + croissant"
            />
          </div>
        </div>
        <div className="row">
          <button
            className="primary"
            onClick={onCreateInvoice}
            disabled={busy}
          >
            {busy ? "Creating…" : "Create invoice"}
          </button>
        </div>
      </div>

      {takings.length > 0 && <TakingsCard takings={takings} onClear={() => setTakings([])} />}
    </div>
  );
}

function TakingsCard({
  takings,
  onClear,
}: {
  takings: PaidReceipt[];
  onClear: () => void;
}) {
  const total = takings.reduce((acc, r) => acc + r.amount_sats, 0);
  const onExport = () => {
    const stamp = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    downloadText(`takings-${stamp}.csv`, takingsToCsv(takings));
  };
  const onClearClick = () => {
    if (
      window.confirm(
        `Clear all ${takings.length} sale(s) from today's takings? ` +
          `This only clears the on-screen ledger — the underlying ` +
          `payments are still on chain. Export to CSV first if you ` +
          `need a record.`,
      )
    ) {
      onClear();
    }
  };
  return (
    <div className="card">
      <div className="card-header">
        <h2>Today's takings</h2>
        <div className="row" style={{ alignItems: "center", gap: 8 }}>
          <span className="muted">
            {takings.length} sale{takings.length === 1 ? "" : "s"} ·{" "}
            <strong style={{ color: "var(--fg)" }}>
              {total.toLocaleString()} sats
            </strong>
          </span>
          <button
            className="secondary"
            onClick={onExport}
            disabled={takings.length === 0}
            title="Download today's sales as a CSV file"
          >
            Export CSV
          </button>
          <button
            className="secondary"
            onClick={onClearClick}
            disabled={takings.length === 0}
            title="Clear the on-screen ledger (does not touch the chain)"
          >
            Clear
          </button>
        </div>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>When</th>
            <th>Amount</th>
            <th>Memo</th>
            <th>Method</th>
          </tr>
        </thead>
        <tbody>
          {takings.map((r) => (
            <tr key={r.invoice_id + ":" + r.txid}>
              <td className="muted">
                {new Date(r.paid_at).toLocaleTimeString()}
              </td>
              <td className="mono" style={{ color: "var(--pass)" }}>
                +{r.amount_sats.toLocaleString()}
              </td>
              <td className="muted">{r.memo || "—"}</td>
              <td>
                <span className="pill mute" style={{ fontSize: 11 }}>
                  {r.method === "silent_payment" ? "Ghost SP" : "direct"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

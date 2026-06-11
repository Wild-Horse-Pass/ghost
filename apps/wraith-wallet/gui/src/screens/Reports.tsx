import { useEffect, useMemo, useState } from "react";
import {
  loadTakings,
  saveTakings,
  takingsToCsv,
  startOfLocalDay,
  downloadText,
  type PaidReceipt,
} from "./Merchant";
import { printReceipt, printSalesReport } from "../lib/receipt";

interface ReportsProps {
  activeWallet: string | null;
}

type Range = "today" | "7d" | "30d" | "all" | "custom";

interface RangeWindow {
  start: number;
  end: number;
  label: string;
}

const SAT = 100_000_000;

/// Accounting + sales-report screen for merchant takings.
///
/// Two distinct views, one screen:
///   - Transactions  — flat ledger, exportable as CSV, every row
///                     reprints to the thermal/A4 receipt template.
///   - Breakdowns    — top products, sales-by-day, average ticket,
///                     peak hour. Printable as an A4 report.
///
/// Source of truth is the same localStorage key Merchant writes to
/// (`wraith.merchant.takings:<wallet>`). We re-read it on mount and
/// every time the user lands back on this tab — there's no live
/// stream from Merchant, but the till is the only writer, and the
/// merchant flow always closes the till before opening reports in
/// practice. Refresh button covers the rare overlap.
export function Reports({ activeWallet }: ReportsProps) {
  const [view, setView] = useState<"transactions" | "breakdowns">(
    "transactions",
  );
  const [range, setRange] = useState<Range>("7d");
  const [customStart, setCustomStart] = useState<string>(
    () => isoDate(Date.now() - 7 * 86400_000),
  );
  const [customEnd, setCustomEnd] = useState<string>(() => isoDate(Date.now()));
  const [takings, setTakings] = useState<PaidReceipt[]>(() =>
    loadTakings(activeWallet),
  );

  useEffect(() => {
    setTakings(loadTakings(activeWallet));
  }, [activeWallet]);

  const rangeWindow: RangeWindow = useMemo(
    () => buildWindow(range, customStart, customEnd),
    [range, customStart, customEnd],
  );

  const filtered = useMemo(
    () =>
      takings
        .filter(
          (r) => r.paid_at >= rangeWindow.start && r.paid_at < rangeWindow.end,
        )
        .sort((a, b) => b.paid_at - a.paid_at),
    [takings, rangeWindow],
  );

  const total = filtered.reduce((acc, r) => acc + r.amount_sats, 0);
  const avg = filtered.length ? Math.round(total / filtered.length) : 0;

  const onRefresh = () => setTakings(loadTakings(activeWallet));

  const onExportCsv = () => {
    const stamp = new Date().toISOString().slice(0, 10);
    const tag = range === "custom" ? "custom" : range;
    downloadText(
      `takings-${tag}-${stamp}.csv`,
      takingsToCsv(filtered),
    );
  };

  const onPrintReport = () => {
    printSalesReport(filtered, {
      wallet: activeWallet,
      title: "Sales report",
      rangeLabel: rangeWindow.label,
    });
  };

  const onDeleteRow = (r: PaidReceipt) => {
    if (
      !window.confirm(
        `Remove this ${r.amount_sats.toLocaleString()} sat sale (#${r.invoice_id}) from the local accounting log?\n\nChain history is not affected — this only deletes the local row used for reports/printouts.`,
      )
    ) {
      return;
    }
    const next = takings.filter(
      (t) => !(t.invoice_id === r.invoice_id && t.txid === r.txid),
    );
    setTakings(next);
    saveTakings(activeWallet, next);
  };

  // ----- Empty wallet -----
  if (!activeWallet) {
    return (
      <div className="screen">
        <div className="page-head">
          <div>
            <span className="eyebrow">accounting</span>
            <h1>Reports</h1>
            <p className="lead">
              Sales ledger and breakdowns for the merchant till.
            </p>
          </div>
        </div>
        <div className="card muted">
          Select and unlock a wallet to view its sales reports.
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">accounting</span>
          <h1>Reports</h1>
          <p className="lead">
            Sales ledger, exports, and breakdowns. Reads from the same
            local takings log the till writes to — wallet{" "}
            <span className="mono">{activeWallet}</span>.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <button
            className="btn-secondary"
            onClick={onRefresh}
            title="Re-read the takings log from local storage"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* ----- View toggle + range filters ----- */}
      <div className="card">
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <div className="row" style={{ gap: 0 }}>
            <button
              className={`btn-secondary btn-sm${view === "transactions" ? " active" : ""}`}
              onClick={() => setView("transactions")}
              style={{
                borderTopRightRadius: 0,
                borderBottomRightRadius: 0,
              }}
            >
              Transactions
            </button>
            <button
              className={`btn-secondary btn-sm${view === "breakdowns" ? " active" : ""}`}
              onClick={() => setView("breakdowns")}
              style={{
                borderTopLeftRadius: 0,
                borderBottomLeftRadius: 0,
                borderLeft: 0,
              }}
            >
              Breakdowns
            </button>
          </div>
          <span className="spacer" />
          <RangeButton
            label="Today"
            active={range === "today"}
            onClick={() => setRange("today")}
          />
          <RangeButton
            label="7 days"
            active={range === "7d"}
            onClick={() => setRange("7d")}
          />
          <RangeButton
            label="30 days"
            active={range === "30d"}
            onClick={() => setRange("30d")}
          />
          <RangeButton
            label="All time"
            active={range === "all"}
            onClick={() => setRange("all")}
          />
          <RangeButton
            label="Custom…"
            active={range === "custom"}
            onClick={() => setRange("custom")}
          />
        </div>
        {range === "custom" && (
          <div
            className="row"
            style={{ gap: 8, alignItems: "center", marginTop: 8 }}
          >
            <label className="muted" style={{ fontSize: 11 }}>
              From
            </label>
            <input
              type="date"
              value={customStart}
              onChange={(e) => setCustomStart(e.target.value)}
            />
            <label className="muted" style={{ fontSize: 11 }}>
              to
            </label>
            <input
              type="date"
              value={customEnd}
              onChange={(e) => setCustomEnd(e.target.value)}
            />
          </div>
        )}
        <div
          className="row"
          style={{ gap: 16, marginTop: 12, flexWrap: "wrap" }}
        >
          <Stat label="Sales" value={String(filtered.length)} />
          <Stat label="Total" value={`${total.toLocaleString()} sats`} />
          <Stat label="≈ BTC" value={(total / SAT).toFixed(8)} />
          <Stat
            label="Average"
            value={`${avg.toLocaleString()} sats`}
          />
          <Stat label="Range" value={rangeWindow.label} muted />
        </div>
        <div className="row" style={{ gap: 8, marginTop: 8 }}>
          <button
            className="btn-secondary btn-sm"
            onClick={onExportCsv}
            disabled={filtered.length === 0}
          >
            Export CSV
          </button>
          <button
            className="btn-secondary btn-sm"
            onClick={onPrintReport}
            disabled={filtered.length === 0}
          >
            Print report
          </button>
        </div>
      </div>

      {/* ----- Active view ----- */}
      {view === "transactions" ? (
        <TransactionsView
          rows={filtered}
          onPrintReceipt={(r) =>
            printReceipt(r, {
              wallet: activeWallet,
              title: "Reprint",
            })
          }
          onDeleteRow={onDeleteRow}
        />
      ) : (
        <BreakdownsView rows={filtered} rangeWindow={rangeWindow} />
      )}
    </div>
  );
}

interface TransactionsProps {
  rows: PaidReceipt[];
  onPrintReceipt: (r: PaidReceipt) => void;
  onDeleteRow: (r: PaidReceipt) => void;
}

function TransactionsView({
  rows,
  onPrintReceipt,
  onDeleteRow,
}: TransactionsProps) {
  if (rows.length === 0) {
    return (
      <div className="card muted">
        No sales in this range. Take a payment from the Merchant tab
        and it will show up here.
      </div>
    );
  }
  return (
    <div className="card">
      <h2>Transactions</h2>
      <table className="table">
        <thead>
          <tr>
            <th style={{ width: 140 }}>When</th>
            <th style={{ width: 70 }}>Inv #</th>
            <th>Item / memo</th>
            <th style={{ width: 80 }}>Method</th>
            <th style={{ width: 110, textAlign: "right" }}>Sats</th>
            <th style={{ width: 140 }}></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const ts = new Date(r.paid_at);
            const itemSummary = (r.lines ?? [])
              .map((l) => (l.qty > 1 ? `${l.label} ×${l.qty}` : l.label))
              .join(", ");
            return (
              <tr key={r.invoice_id + ":" + r.txid}>
                <td>
                  <div style={{ fontSize: 12 }}>
                    {ts.toLocaleDateString()}
                  </div>
                  <div className="muted" style={{ fontSize: 10 }}>
                    {ts.toLocaleTimeString()}
                  </div>
                </td>
                <td className="mono" style={{ fontSize: 11 }}>
                  #{r.invoice_id}
                </td>
                <td style={{ fontSize: 12 }}>
                  <div>{r.memo || itemSummary || "—"}</div>
                  {itemSummary && r.memo && r.memo !== itemSummary && (
                    <div className="muted" style={{ fontSize: 10 }}>
                      {itemSummary}
                    </div>
                  )}
                  <div
                    className="muted mono"
                    style={{
                      fontSize: 9,
                      marginTop: 2,
                      wordBreak: "break-all",
                    }}
                  >
                    {r.txid}
                  </div>
                </td>
                <td>
                  <span className="pill mute" style={{ fontSize: 10 }}>
                    {r.method === "silent_payment" ? "silent" : "direct"}
                  </span>
                </td>
                <td
                  className="mono"
                  style={{ textAlign: "right", fontSize: 13 }}
                >
                  {r.amount_sats.toLocaleString()}
                </td>
                <td>
                  <button
                    className="btn-secondary btn-sm"
                    onClick={() => onPrintReceipt(r)}
                    title="Re-print this receipt"
                  >
                    Print
                  </button>{" "}
                  <button
                    className="btn-secondary btn-sm"
                    onClick={() => onDeleteRow(r)}
                    title="Remove from local accounting log (chain history not affected)"
                    style={{ marginLeft: 4 }}
                  >
                    ✕
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

interface BreakdownsProps {
  rows: PaidReceipt[];
  rangeWindow: RangeWindow;
}

function BreakdownsView({ rows, rangeWindow }: BreakdownsProps) {
  if (rows.length === 0) {
    return (
      <div className="card muted">
        No sales in this range — nothing to break down yet.
      </div>
    );
  }

  // ---- Top products by revenue and quantity ----
  const productAgg = new Map<
    string,
    { qty: number; revenue: number; emoji?: string }
  >();
  let receiptsWithLines = 0;
  for (const r of rows) {
    if (!r.lines || r.lines.length === 0) continue;
    receiptsWithLines += 1;
    for (const l of r.lines) {
      const key = l.label;
      const cur = productAgg.get(key) ?? { qty: 0, revenue: 0, emoji: l.emoji };
      cur.qty += l.qty;
      cur.revenue += l.unit_sats * l.qty;
      cur.emoji = cur.emoji ?? l.emoji;
      productAgg.set(key, cur);
    }
  }
  const topProducts = Array.from(productAgg.entries())
    .map(([label, v]) => ({ label, ...v }))
    .sort((a, b) => b.revenue - a.revenue)
    .slice(0, 10);

  // ---- Sales by day ----
  const dayAgg = new Map<string, { count: number; revenue: number }>();
  for (const r of rows) {
    const key = isoDate(r.paid_at);
    const cur = dayAgg.get(key) ?? { count: 0, revenue: 0 };
    cur.count += 1;
    cur.revenue += r.amount_sats;
    dayAgg.set(key, cur);
  }
  const days = Array.from(dayAgg.entries())
    .map(([day, v]) => ({ day, ...v }))
    .sort((a, b) => (a.day < b.day ? 1 : -1))
    .slice(0, 30);
  const peakDayRevenue = Math.max(...days.map((d) => d.revenue), 1);

  // ---- Sales by hour-of-day (peak hour) ----
  const hourAgg = new Array<{ count: number; revenue: number }>(24)
    .fill(null as never)
    .map(() => ({ count: 0, revenue: 0 }));
  for (const r of rows) {
    const h = new Date(r.paid_at).getHours();
    hourAgg[h].count += 1;
    hourAgg[h].revenue += r.amount_sats;
  }
  const peakHourIdx = hourAgg.reduce(
    (best, h, i) => (h.revenue > hourAgg[best].revenue ? i : best),
    0,
  );
  const peakHourRevenue = Math.max(...hourAgg.map((h) => h.revenue), 1);

  // ---- Method split ----
  const sp = rows.filter((r) => r.method === "silent_payment");
  const direct = rows.filter((r) => r.method === "direct");

  return (
    <>
      <div className="card">
        <div className="card-header">
          <h2>Top products</h2>
          <span className="muted" style={{ fontSize: 11 }}>
            {receiptsWithLines} of {rows.length} sales had itemised lines
          </span>
        </div>
        {topProducts.length === 0 ? (
          <div className="muted">
            No itemised sales in this range. Tap products on the till
            instead of using the custom-amount keypad to feed the
            breakdown.
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Product</th>
                <th style={{ width: 80, textAlign: "right" }}>Qty</th>
                <th style={{ width: 120, textAlign: "right" }}>Revenue</th>
                <th style={{ width: 80, textAlign: "right" }}>Share</th>
              </tr>
            </thead>
            <tbody>
              {topProducts.map((p) => {
                const totalRev = topProducts.reduce(
                  (acc, x) => acc + x.revenue,
                  0,
                );
                const share = totalRev > 0 ? (p.revenue / totalRev) * 100 : 0;
                return (
                  <tr key={p.label}>
                    <td>
                      {p.emoji && (
                        <span style={{ marginRight: 6 }}>{p.emoji}</span>
                      )}
                      {p.label}
                    </td>
                    <td className="mono" style={{ textAlign: "right" }}>
                      {p.qty}
                    </td>
                    <td className="mono" style={{ textAlign: "right" }}>
                      {p.revenue.toLocaleString()}
                    </td>
                    <td
                      className="muted mono"
                      style={{ textAlign: "right", fontSize: 11 }}
                    >
                      {share.toFixed(1)}%
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2>Sales by day</h2>
        <p className="muted" style={{ fontSize: 11, margin: 0 }}>
          {rangeWindow.label}. Bar length is normalised to the peak day in
          this range.
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 8 }}>
          {days.map((d) => {
            const pct = (d.revenue / peakDayRevenue) * 100;
            return (
              <div
                key={d.day}
                className="row"
                style={{ alignItems: "center", gap: 8 }}
              >
                <div
                  className="mono muted"
                  style={{ width: 90, fontSize: 11 }}
                >
                  {d.day}
                </div>
                <div
                  style={{
                    flex: 1,
                    height: 14,
                    background: "var(--card-bg-elev, #f0eee5)",
                    borderRadius: 2,
                    position: "relative",
                  }}
                >
                  <div
                    style={{
                      width: `${pct}%`,
                      height: "100%",
                      background: "var(--accent)",
                      borderRadius: 2,
                      opacity: 0.8,
                    }}
                  />
                </div>
                <div
                  className="mono"
                  style={{ width: 110, textAlign: "right", fontSize: 12 }}
                >
                  {d.revenue.toLocaleString()} sats
                </div>
                <div
                  className="muted mono"
                  style={{ width: 40, textAlign: "right", fontSize: 11 }}
                >
                  ×{d.count}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="card">
        <h2>Hour of day</h2>
        <p className="muted" style={{ fontSize: 11, margin: 0 }}>
          When the till is busiest. Peak hour:{" "}
          <strong style={{ color: "var(--fg)" }}>
            {String(peakHourIdx).padStart(2, "0")}:00
          </strong>{" "}
          ({hourAgg[peakHourIdx].revenue.toLocaleString()} sats across{" "}
          {hourAgg[peakHourIdx].count} sale
          {hourAgg[peakHourIdx].count === 1 ? "" : "s"}).
        </p>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(24, 1fr)",
            gap: 2,
            marginTop: 8,
            alignItems: "end",
            height: 80,
          }}
        >
          {hourAgg.map((h, i) => {
            const pct = (h.revenue / peakHourRevenue) * 100;
            return (
              <div
                key={i}
                title={`${String(i).padStart(2, "0")}:00 — ${h.revenue.toLocaleString()} sats, ${h.count} sale${h.count === 1 ? "" : "s"}`}
                style={{
                  height: `${Math.max(pct, h.revenue > 0 ? 4 : 0)}%`,
                  background: i === peakHourIdx ? "var(--accent)" : "var(--card-bg-elev, #d9d6cb)",
                  borderRadius: 2,
                  minHeight: 2,
                }}
              />
            );
          })}
        </div>
        <div
          className="row"
          style={{
            justifyContent: "space-between",
            marginTop: 4,
            fontSize: 9,
          }}
        >
          <span className="muted">00</span>
          <span className="muted">06</span>
          <span className="muted">12</span>
          <span className="muted">18</span>
          <span className="muted">23</span>
        </div>
      </div>

      <div className="card">
        <h2>Payment method</h2>
        <div className="kv">
          <div className="k">Silent payment</div>
          <div className="v">
            {sp.length} sale{sp.length === 1 ? "" : "s"} ·{" "}
            <span className="mono">
              {sp.reduce((acc, r) => acc + r.amount_sats, 0).toLocaleString()}
            </span>{" "}
            sats
          </div>
          <div className="k">Direct deposit</div>
          <div className="v">
            {direct.length} sale{direct.length === 1 ? "" : "s"} ·{" "}
            <span className="mono">
              {direct
                .reduce((acc, r) => acc + r.amount_sats, 0)
                .toLocaleString()}
            </span>{" "}
            sats
          </div>
        </div>
      </div>
    </>
  );
}

// ----- helpers -----

function buildWindow(
  range: Range,
  customStart: string,
  customEnd: string,
): RangeWindow {
  const now = Date.now();
  if (range === "today") {
    const start = startOfLocalDay(now);
    return { start, end: now + 1, label: "today" };
  }
  if (range === "7d") {
    return {
      start: now - 7 * 86400_000,
      end: now + 1,
      label: "last 7 days",
    };
  }
  if (range === "30d") {
    return {
      start: now - 30 * 86400_000,
      end: now + 1,
      label: "last 30 days",
    };
  }
  if (range === "all") {
    return { start: 0, end: now + 1, label: "all time" };
  }
  // custom
  const startMs = customStart ? Date.parse(customStart + "T00:00:00") : 0;
  const endMs = customEnd
    ? Date.parse(customEnd + "T23:59:59.999")
    : now + 1;
  return {
    start: Number.isFinite(startMs) ? startMs : 0,
    end: Number.isFinite(endMs) ? endMs : now + 1,
    label: `${customStart || "start"} to ${customEnd || "now"}`,
  };
}

function isoDate(at: number | string): string {
  const d = typeof at === "string" ? new Date(at) : new Date(at);
  // Local date — what merchants think in. Toolchain conversion to
  // UTC is fine for CSV export but bad for the date picker.
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function RangeButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      className={`btn-secondary btn-sm${active ? " active" : ""}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function Stat({
  label,
  value,
  muted,
}: {
  label: string;
  value: string;
  muted?: boolean;
}) {
  return (
    <div>
      <div
        className="eyebrow eyebrow-dim"
        style={{ fontSize: 9, marginBottom: 2 }}
      >
        {label}
      </div>
      <div
        className="mono"
        style={{
          fontSize: 14,
          fontWeight: 500,
          color: muted ? "var(--dim)" : "var(--fg)",
        }}
      >
        {value}
      </div>
    </div>
  );
}

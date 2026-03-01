import { useState } from "react";
import { exportCsv, exportHtml } from "../api/commands";

export default function Export() {
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [businessName, setBusinessName] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const parseDate = (d: string): number => {
    if (!d) return 0;
    return Math.floor(new Date(d).getTime() / 1000);
  };

  const handleCsv = async () => {
    try {
      setError("");
      setSuccess("");
      const sinceTs = parseDate(since);
      const untilTs = until ? parseDate(until) : Math.floor(Date.now() / 1000);
      const csv = await exportCsv(sinceTs, untilTs);

      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ghost-transactions-${since || "all"}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess("CSV exported successfully");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleHtml = async () => {
    try {
      setError("");
      setSuccess("");
      const sinceTs = parseDate(since);
      const untilTs = until ? parseDate(until) : Math.floor(Date.now() / 1000);
      const html = await exportHtml(sinceTs, untilTs, businessName || undefined);

      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ghost-report-${since || "all"}.html`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess("HTML report exported successfully");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  return (
    <div className="page">
      <h1>Export Transactions</h1>
      <div className="card" style={{ maxWidth: 500 }}>
        <div className="form-group">
          <label>From Date</label>
          <input type="date" value={since} onChange={(e) => setSince(e.target.value)} />
        </div>
        <div className="form-group">
          <label>To Date</label>
          <input type="date" value={until} onChange={(e) => setUntil(e.target.value)} />
        </div>
        <div className="form-group">
          <label>Business Name (for HTML report)</label>
          <input
            value={businessName}
            onChange={(e) => setBusinessName(e.target.value)}
            placeholder="Your Business"
          />
        </div>
        {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
        {success && <div className="success-text" style={{ marginBottom: 12 }}>{success}</div>}
        <div style={{ display: "flex", gap: 12 }}>
          <button className="btn-primary" onClick={handleCsv} style={{ flex: 1 }}>
            Export CSV
          </button>
          <button className="btn-secondary" onClick={handleHtml} style={{ flex: 1 }}>
            Export HTML Report
          </button>
        </div>
      </div>
    </div>
  );
}

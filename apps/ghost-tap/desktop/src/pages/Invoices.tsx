import { useState } from "react";
import {
  createInvoice,
  newReceiveAddress,
  formatGhost,
  type InvoiceResponse,
  type LineItemInput,
} from "../api/commands";
import QrCode from "../components/QrCode";

export default function Invoices() {
  const [invoices, setInvoices] = useState<InvoiceResponse[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [amount, setAmount] = useState("");
  const [memo, setMemo] = useState("");
  const [businessName, setBusinessName] = useState("");
  const [items, setItems] = useState<LineItemInput[]>([]);
  const [itemDesc, setItemDesc] = useState("");
  const [itemAmount, setItemAmount] = useState("");
  const [selected, setSelected] = useState<InvoiceResponse | null>(null);
  const [error, setError] = useState("");

  const handleCreate = async () => {
    try {
      setError("");
      const address = await newReceiveAddress();
      const amountSats = Math.floor(parseFloat(amount) * 100_000_000);
      const invoice = await createInvoice(
        address,
        amountSats,
        businessName || undefined,
        memo || undefined,
        undefined,
        items.length > 0 ? items : undefined,
      );
      setInvoices([invoice, ...invoices]);
      setShowCreate(false);
      setAmount("");
      setMemo("");
      setItems([]);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const addItem = () => {
    if (itemDesc && itemAmount) {
      setItems([...items, {
        description: itemDesc,
        amount: Math.floor(parseFloat(itemAmount) * 100_000_000),
      }]);
      setItemDesc("");
      setItemAmount("");
    }
  };

  if (selected) {
    return (
      <div className="page">
        <button className="btn-secondary btn-small" onClick={() => setSelected(null)} style={{ marginBottom: 16 }}>
          Back to Invoices
        </button>
        <h1>Invoice {selected.invoice_id}</h1>
        <div className="card" style={{ maxWidth: 500, textAlign: "center" }}>
          <div style={{ marginBottom: 16 }}>
            <span className={`badge badge-${selected.status.toLowerCase()}`}>
              {selected.status}
            </span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, marginBottom: 16 }}>
            {formatGhost(selected.amount)}{" "}
            <span style={{ fontSize: 14, color: "var(--text-muted)" }}>GHOST</span>
          </div>
          <QrCode value={selected.payment_uri} size={200} />
          <div className="mono" style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 12, wordBreak: "break-all" }}>
            {selected.payment_uri}
          </div>
          {selected.memo && (
            <div style={{ marginTop: 16, fontSize: 13, color: "var(--text-secondary)" }}>
              {selected.memo}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>Invoices</h1>
        <button className="btn-primary" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? "Cancel" : "Create Invoice"}
        </button>
      </div>

      {showCreate && (
        <div className="card" style={{ maxWidth: 500, marginBottom: 24 }}>
          <div className="form-group">
            <label>Business Name</label>
            <input value={businessName} onChange={(e) => setBusinessName(e.target.value)} placeholder="Your Business" />
          </div>
          <div className="form-group">
            <label>Total Amount (GHOST)</label>
            <input type="number" step="0.00000001" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.00000000" />
          </div>
          <div className="form-group">
            <label>Memo</label>
            <input value={memo} onChange={(e) => setMemo(e.target.value)} placeholder="Optional note..." />
          </div>
          <div className="form-group">
            <label>Line Items</label>
            <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
              <input placeholder="Description" value={itemDesc} onChange={(e) => setItemDesc(e.target.value)} style={{ flex: 2 }} />
              <input type="number" placeholder="Amount" value={itemAmount} onChange={(e) => setItemAmount(e.target.value)} style={{ flex: 1 }} />
              <button className="btn-secondary btn-small" onClick={addItem}>Add</button>
            </div>
            {items.map((item, i) => (
              <div key={i} style={{ fontSize: 12, color: "var(--text-secondary)", padding: "4px 0" }}>
                {item.description}: {formatGhost(item.amount)} GHOST
              </div>
            ))}
          </div>
          {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
          <button className="btn-primary" onClick={handleCreate} disabled={!amount} style={{ width: "100%" }}>
            Create
          </button>
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        <table>
          <thead>
            <tr>
              <th>Invoice</th>
              <th>Amount</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {invoices.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  No invoices yet
                </td>
              </tr>
            ) : (
              invoices.map((inv) => (
                <tr key={inv.invoice_id}>
                  <td className="mono">{inv.invoice_id}</td>
                  <td>{formatGhost(inv.amount)} GHOST</td>
                  <td>
                    <span className={`badge badge-${inv.status.toLowerCase()}`}>
                      {inv.status}
                    </span>
                  </td>
                  <td>
                    <button className="btn-secondary btn-small" onClick={() => setSelected(inv)}>
                      View
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

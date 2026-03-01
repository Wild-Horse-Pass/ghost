import { useState } from "react";
import { generateReceipt, type LineItemInput } from "../api/commands";

export default function Receipts() {
  const [txid, setTxid] = useState("");
  const [amount, setAmount] = useState("");
  const [merchantName, setMerchantName] = useState("");
  const [memo, setMemo] = useState("");
  const [items, setItems] = useState<LineItemInput[]>([]);
  const [itemDesc, setItemDesc] = useState("");
  const [itemAmount, setItemAmount] = useState("");
  const [receiptHtml, setReceiptHtml] = useState("");
  const [error, setError] = useState("");

  const addItem = () => {
    if (itemDesc && itemAmount) {
      setItems([
        ...items,
        {
          description: itemDesc,
          amount: Math.floor(parseFloat(itemAmount) * 100_000_000),
        },
      ]);
      setItemDesc("");
      setItemAmount("");
    }
  };

  const handleGenerate = async () => {
    try {
      setError("");
      const amountSats = Math.floor(parseFloat(amount) * 100_000_000);
      const result = await generateReceipt(
        txid,
        amountSats,
        items,
        merchantName || undefined,
        memo || undefined,
      );
      setReceiptHtml(result.html);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  if (receiptHtml) {
    return (
      <div className="page">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <h1 style={{ marginBottom: 0 }}>Receipt</h1>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn-secondary" onClick={() => setReceiptHtml("")}>
              Back
            </button>
            <button
              className="btn-primary"
              onClick={() => {
                const w = window.open("", "_blank");
                if (w) {
                  w.document.write(receiptHtml);
                  w.document.close();
                  w.print();
                }
              }}
            >
              Print
            </button>
          </div>
        </div>
        <div
          className="card"
          style={{ maxWidth: 500 }}
          dangerouslySetInnerHTML={{ __html: receiptHtml }}
        />
      </div>
    );
  }

  return (
    <div className="page">
      <h1>Generate Receipt</h1>
      <div className="card" style={{ maxWidth: 500 }}>
        <div className="form-group">
          <label>Transaction ID</label>
          <input
            value={txid}
            onChange={(e) => setTxid(e.target.value)}
            placeholder="Enter txid..."
            className="mono"
          />
        </div>
        <div className="form-group">
          <label>Amount (GHOST)</label>
          <input
            type="number"
            step="0.00000001"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0.00000000"
          />
        </div>
        <div className="form-group">
          <label>Merchant Name</label>
          <input
            value={merchantName}
            onChange={(e) => setMerchantName(e.target.value)}
            placeholder="Your Business"
          />
        </div>
        <div className="form-group">
          <label>Memo</label>
          <input
            value={memo}
            onChange={(e) => setMemo(e.target.value)}
            placeholder="Optional..."
          />
        </div>
        <div className="form-group">
          <label>Line Items</label>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <input
              placeholder="Description"
              value={itemDesc}
              onChange={(e) => setItemDesc(e.target.value)}
              style={{ flex: 2 }}
            />
            <input
              type="number"
              placeholder="Amount"
              value={itemAmount}
              onChange={(e) => setItemAmount(e.target.value)}
              style={{ flex: 1 }}
            />
            <button className="btn-secondary btn-small" onClick={addItem}>
              Add
            </button>
          </div>
          {items.map((item, i) => (
            <div key={i} style={{ fontSize: 12, color: "var(--text-secondary)", padding: "4px 0" }}>
              {item.description}: {(item.amount / 100_000_000).toFixed(8)} GHOST
            </div>
          ))}
        </div>
        {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
        <button
          className="btn-primary"
          onClick={handleGenerate}
          disabled={!txid || !amount}
          style={{ width: "100%" }}
        >
          Generate Receipt
        </button>
      </div>
    </div>
  );
}

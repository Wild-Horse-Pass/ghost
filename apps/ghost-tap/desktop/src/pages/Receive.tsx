import { useEffect, useState } from "react";
import { newReceiveAddress, createPaymentUri } from "../api/commands";
import QrCode from "../components/QrCode";

export default function Receive() {
  const [address, setAddress] = useState("");
  const [uri, setUri] = useState("");
  const [error, setError] = useState("");

  const generateAddress = async () => {
    try {
      setError("");
      const addr = await newReceiveAddress();
      setAddress(addr);
      const payUri = await createPaymentUri(addr);
      setUri(payUri);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  useEffect(() => {
    generateAddress();
  }, []);

  return (
    <div className="page">
      <h1>Receive</h1>
      <div className="card" style={{ maxWidth: 420, textAlign: "center" }}>
        {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
        {uri && <QrCode value={uri} size={220} />}
        <div
          className="mono"
          style={{
            fontSize: 13,
            marginTop: 20,
            padding: "12px",
            background: "var(--bg-tertiary)",
            borderRadius: 6,
            wordBreak: "break-all",
            userSelect: "all",
          }}
        >
          {address}
        </div>
        <button
          className="btn-secondary"
          onClick={generateAddress}
          style={{ marginTop: 16 }}
        >
          New Address
        </button>
      </div>
    </div>
  );
}

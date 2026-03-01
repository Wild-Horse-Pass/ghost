import { useState } from "react";

interface Props {
  onSubmit: (pin: string) => void;
  label?: string;
}

export default function PinEntry({ onSubmit, label = "Enter PIN" }: Props) {
  const [pin, setPin] = useState("");

  const handleKey = (digit: string) => {
    if (pin.length < 6) {
      const next = pin + digit;
      setPin(next);
      if (next.length === 6) {
        onSubmit(next);
        setPin("");
      }
    }
  };

  const handleDelete = () => {
    setPin(pin.slice(0, -1));
  };

  return (
    <div style={{ textAlign: "center" }}>
      <div style={{ fontSize: 14, color: "var(--text-secondary)", marginBottom: 16 }}>
        {label}
      </div>
      <div style={{ display: "flex", justifyContent: "center", gap: 10, marginBottom: 24 }}>
        {[0, 1, 2, 3, 4, 5].map((i) => (
          <div
            key={i}
            style={{
              width: 14,
              height: 14,
              borderRadius: "50%",
              background: i < pin.length ? "var(--accent)" : "var(--border)",
              transition: "background 0.1s ease",
            }}
          />
        ))}
      </div>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 60px)",
          gap: 8,
          justifyContent: "center",
        }}
      >
        {["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "DEL"].map(
          (key) =>
            key === "" ? (
              <div key="empty" />
            ) : (
              <button
                key={key}
                className="btn-secondary"
                onClick={() => (key === "DEL" ? handleDelete() : handleKey(key))}
                style={{ padding: "12px 0", fontSize: 16 }}
              >
                {key}
              </button>
            ),
        )}
      </div>
    </div>
  );
}

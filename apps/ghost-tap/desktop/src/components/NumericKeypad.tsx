interface Props {
  value: string;
  onChange: (value: string) => void;
}

export default function NumericKeypad({ value, onChange }: Props) {
  const handleKey = (key: string) => {
    if (key === "C") {
      onChange("");
    } else if (key === "DEL") {
      onChange(value.slice(0, -1));
    } else if (key === ".") {
      if (!value.includes(".")) {
        onChange(value + ".");
      }
    } else {
      onChange(value + key);
    }
  };

  const keys = ["7", "8", "9", "4", "5", "6", "1", "2", "3", "C", "0", "."];

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(3, 1fr)",
        gap: 8,
        maxWidth: 280,
      }}
    >
      {keys.map((key) => (
        <button
          key={key}
          className="btn-secondary"
          onClick={() => handleKey(key)}
          style={{
            padding: "16px 0",
            fontSize: 20,
            fontWeight: 600,
            borderRadius: 8,
          }}
        >
          {key}
        </button>
      ))}
      <button
        className="btn-secondary"
        onClick={() => handleKey("DEL")}
        style={{
          gridColumn: "span 3",
          padding: "12px 0",
          fontSize: 14,
        }}
      >
        Delete
      </button>
    </div>
  );
}

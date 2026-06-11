interface NumpadProps {
  /// Current amount string. Parent owns it so `onChange` is the
  /// only mutation channel — keeps the parent's cart/total math
  /// in one place.
  value: string;
  onChange: (next: string) => void;
  disabled?: boolean;
}

/// Touch-friendly numeric keypad. 4×3 grid: digits 0-9, double-zero,
/// backspace. No decimal — sats are whole numbers; if a future
/// fiat-mode lands it can swap the `00` for `.`.
///
/// Parent owns the value as a string so leading zeros and partial
/// states (empty after a backspace) round-trip cleanly. Numeric
/// parsing happens at submit time, not on every key.
export function Numpad({ value, onChange, disabled }: NumpadProps) {
  const append = (digits: string) => {
    if (disabled) return;
    // Strip leading zeros so "0" + "5" → "5", not "05". An empty
    // string is fine (treated as 0 by the parent's parser).
    const next =
      value === "0" || value === ""
        ? digits === "00" || digits === "0"
          ? "0"
          : digits
        : value + digits;
    onChange(next);
  };
  const backspace = () => {
    if (disabled) return;
    onChange(value.slice(0, -1));
  };
  const clear = () => {
    if (disabled) return;
    onChange("");
  };

  const KeyBtn = ({
    label,
    onClick,
    variant,
  }: {
    label: string | React.ReactNode;
    onClick: () => void;
    variant?: "primary" | "danger";
  }) => (
    <button
      type="button"
      className={`numpad-key${variant ? ` numpad-key-${variant}` : ""}`}
      onClick={onClick}
      disabled={disabled}
    >
      {label}
    </button>
  );

  return (
    <div className="numpad">
      <KeyBtn label="1" onClick={() => append("1")} />
      <KeyBtn label="2" onClick={() => append("2")} />
      <KeyBtn label="3" onClick={() => append("3")} />
      <KeyBtn label="4" onClick={() => append("4")} />
      <KeyBtn label="5" onClick={() => append("5")} />
      <KeyBtn label="6" onClick={() => append("6")} />
      <KeyBtn label="7" onClick={() => append("7")} />
      <KeyBtn label="8" onClick={() => append("8")} />
      <KeyBtn label="9" onClick={() => append("9")} />
      <KeyBtn label="00" onClick={() => append("00")} />
      <KeyBtn label="0" onClick={() => append("0")} />
      <KeyBtn
        label={
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            width="22"
            height="22"
          >
            <path d="M22 6H8.5a2 2 0 0 0-1.45.65l-5.66 6a1 1 0 0 0 0 1.4l5.66 6A2 2 0 0 0 8.5 21H22a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2z" />
            <line x1="18" y1="9" x2="12" y2="15" />
            <line x1="12" y1="9" x2="18" y2="15" />
          </svg>
        }
        onClick={backspace}
        variant="danger"
      />
      {value.length > 0 && (
        <button
          type="button"
          className="numpad-clear"
          onClick={clear}
          disabled={disabled}
        >
          clear
        </button>
      )}
    </div>
  );
}

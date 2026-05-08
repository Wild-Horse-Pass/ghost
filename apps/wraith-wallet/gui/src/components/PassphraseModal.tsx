import { useEffect, useRef, useState } from "react";

interface PassphraseModalProps {
  /// Title shown at the top of the modal.
  title: string;
  /// Optional explanation displayed beneath the title.
  description?: string;
  /// Submit-button label. Defaults to "Submit".
  submitLabel?: string;
  /// Called with the typed passphrase when the user submits a
  /// non-empty value. The parent decides what to do with it
  /// (decrypt a keystore, reveal a mnemonic, etc.). The parent is
  /// responsible for closing the modal afterwards via `onCancel`
  /// — that lets the modal stay open while the parent's async
  /// operation runs.
  onSubmit: (passphrase: string) => void;
  /// Called when the user dismisses without submitting.
  onCancel: () => void;
  /// Optional error string to display in the modal — typically the
  /// daemon's "wrong passphrase" response. Reset to null when the
  /// user types again.
  error?: string | null;
  /// Disabled state for both inputs and buttons (parent's busy
  /// indicator).
  busy?: boolean;
}

/// A modal dialog with a masked passphrase field. Replaces the
/// browser's `prompt()` for any passphrase entry — `prompt()`
/// renders a single-line input that ECHOES the typed characters,
/// which is unacceptable for a wallet's keystore passphrase.
///
/// Usage:
///   const [pass, setPass] = useState<{ for: string } | null>(null);
///   ...
///   {pass && (
///     <PassphraseModal
///       title={`Unlock ${pass.for}`}
///       onSubmit={(p) => unlockWith(pass.for, p)}
///       onCancel={() => setPass(null)}
///     />
///   )}
export function PassphraseModal({
  title,
  description,
  submitLabel = "Submit",
  onSubmit,
  onCancel,
  error,
  busy,
}: PassphraseModalProps) {
  const [value, setValue] = useState("");
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Focus the input on mount so the user can start typing
  // immediately. Also handles Esc to cancel.
  useEffect(() => {
    inputRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  const submit = () => {
    if (!value || busy) return;
    onSubmit(value);
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.55)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
      onClick={(e) => {
        // Click outside the inner card cancels — matches the
        // affordance of a modal.
        if (e.target === e.currentTarget && !busy) onCancel();
      }}
    >
      <div
        className="card"
        style={{ width: "min(440px, 90vw)", padding: 24 }}
        onClick={(e) => e.stopPropagation()}
      >
        <h2 style={{ marginTop: 0 }}>{title}</h2>
        {description && (
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            {description}
          </p>
        )}
        {error && (
          <div
            className="pill fail"
            style={{ alignSelf: "flex-start", marginTop: 8 }}
          >
            {error}
          </div>
        )}
        <div className="col" style={{ marginTop: 12 }}>
          <label>Passphrase</label>
          <input
            ref={inputRef}
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            disabled={busy}
            onKeyDown={(e) => {
              if (e.key === "Enter") submit();
            }}
          />
        </div>
        <div className="row" style={{ marginTop: 16, justifyContent: "flex-end" }}>
          <button
            className="secondary"
            onClick={onCancel}
            disabled={busy}
            style={{ marginRight: 8 }}
          >
            Cancel
          </button>
          <button
            className="primary"
            onClick={submit}
            disabled={busy || !value}
          >
            {busy ? "Working…" : submitLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

import { useState } from "react";
import { walletCreate, walletImport } from "../lib/tauri";

interface OnboardingProps {
  /// "create" launches the create-new flow; "import" launches the
  /// import-from-mnemonic flow. The two paths share the close-form
  /// shell but differ in their middle steps.
  mode: "create" | "import";
  /// Called when the wizard finishes (wallet was created/imported)
  /// or the user cancels. The parent re-fetches the wallet list.
  onClose: () => void;
}

type Step =
  | "name_pass"
  | "show_mnemonic"
  | "confirm_acked"
  | "enter_mnemonic"
  | "submitting"
  | "done";

/// Multi-step wizard for wallet onboarding. Replaces the bare
/// `prompt()` dialogs with a guided flow that surfaces each piece
/// of friction (name, passphrase, mnemonic backup) on its own
/// screen with proper validation and a back button.
///
/// Two paths share the shell:
///   create: name+pass → wallet_create call → display mnemonic +
///           "I have written it down" gate → done
///   import: name+pass → enter mnemonic → wallet_import call → done
///
/// The on-chain wallet exists from the moment we receive the
/// CreateResponse — leaving the wizard mid-flow does NOT undo
/// creation. The acknowledgement gate is purely UI ceremony to
/// reduce the rate of "I lost my mnemonic" tickets.
export function Onboarding({ mode, onClose }: OnboardingProps) {
  const [step, setStep] = useState<Step>(
    mode === "create" ? "name_pass" : "name_pass",
  );
  const [name, setName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  const [mnemonic, setMnemonic] = useState(""); // import-mode input
  const [generatedMnemonic, setGeneratedMnemonic] = useState<string | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const validateNamePass = (): string | null => {
    if (!name.trim()) return "Wallet name is required.";
    if (!/^[A-Za-z0-9._-]+$/.test(name.trim())) {
      return "Wallet name can only contain letters, numbers, dot, underscore, hyphen.";
    }
    if (passphrase.length < 8) {
      return "Passphrase must be at least 8 characters.";
    }
    if (passphrase !== passphraseConfirm) {
      return "Passphrases don't match.";
    }
    return null;
  };

  const onSubmitNamePass = async () => {
    const v = validateNamePass();
    if (v) {
      setErr(v);
      return;
    }
    setErr(null);
    if (mode === "create") {
      // Fire the create call here. We need the daemon-generated
      // mnemonic before we can show it on the next step. Failure
      // here keeps the user on this screen with a clear error
      // (typically "wallet already exists").
      setBusy(true);
      setStep("submitting");
      try {
        const r = await walletCreate(name.trim(), passphrase);
        setGeneratedMnemonic(r.mnemonic);
        setStep("show_mnemonic");
      } catch (e) {
        setErr((e as Error).message ?? String(e));
        setStep("name_pass");
      } finally {
        setBusy(false);
      }
    } else {
      setStep("enter_mnemonic");
    }
  };

  const onSubmitMnemonic = async () => {
    const cleaned = mnemonic
      .split(/\s+/)
      .filter((w) => w.length > 0)
      .join(" ");
    const wordCount = cleaned.split(" ").length;
    if (wordCount !== 12 && wordCount !== 24) {
      setErr(`Expected 12 or 24 words, got ${wordCount}.`);
      return;
    }
    setErr(null);
    setBusy(true);
    setStep("submitting");
    try {
      await walletImport(name.trim(), cleaned, passphrase);
      setStep("done");
    } catch (e) {
      setErr((e as Error).message ?? String(e));
      setStep("enter_mnemonic");
    } finally {
      setBusy(false);
    }
  };

  const onAckMnemonic = () => {
    setStep("confirm_acked");
    // Brief "all set" pause before closing — gives the user a
    // chance to read "the wallet is ready". Then close.
    setTimeout(() => {
      setStep("done");
    }, 600);
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable in some webview sandboxes */
    }
  };

  // The "done" state closes the wizard. Centralised in an effect
  // so all paths converge here.
  if (step === "done") {
    onClose();
    return null;
  }

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
    >
      <div
        className="card"
        style={{
          width: "min(560px, 90vw)",
          maxHeight: "90vh",
          overflow: "auto",
          padding: 24,
        }}
      >
        <div className="card-header">
          <h2 style={{ margin: 0 }}>
            {mode === "create" ? "Create new wallet" : "Import wallet"}
          </h2>
          <span className="muted" style={{ fontSize: 13 }}>
            {stepLabel(mode, step)}
          </span>
        </div>

        {err && (
          <div
            className="pill fail"
            style={{ alignSelf: "flex-start", marginTop: 8 }}
          >
            {err}
          </div>
        )}

        {/* Step 1: name + passphrase. Shared by both paths. */}
        {step === "name_pass" && (
          <>
            <div className="col">
              <label>Wallet name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={busy}
                placeholder="e.g. personal, merchant-till-1"
                autoFocus
              />
            </div>
            <div className="col">
              <label>Passphrase</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                disabled={busy}
                placeholder="At least 8 characters"
              />
            </div>
            <div className="col">
              <label>Confirm passphrase</label>
              <input
                type="password"
                value={passphraseConfirm}
                onChange={(e) => setPassphraseConfirm(e.target.value)}
                disabled={busy}
                onKeyDown={(e) => {
                  if (e.key === "Enter") onSubmitNamePass();
                }}
              />
            </div>
            <p className="muted" style={{ margin: 0, fontSize: 12 }}>
              The passphrase encrypts the keystore at rest. It does
              NOT replace your backup phrase — losing the passphrase
              means losing the wallet unless you have the mnemonic.
            </p>
            <div className="row" style={{ marginTop: 12 }}>
              <button
                className="secondary"
                onClick={onClose}
                style={{ marginRight: 8 }}
              >
                Cancel
              </button>
              <button
                className="primary"
                onClick={onSubmitNamePass}
                disabled={busy}
              >
                Continue
              </button>
            </div>
          </>
        )}

        {/* Step 2 (create): show generated mnemonic. */}
        {step === "show_mnemonic" && generatedMnemonic && (
          <>
            <div
              className="card"
              style={{
                borderColor: "var(--warn, #d97706)",
                borderWidth: 2,
                background: "var(--bg)",
                margin: "12px 0",
              }}
            >
              <p style={{ margin: 0 }}>
                <strong>Write these 12 words down on paper.</strong>{" "}
                Anyone with this phrase can spend funds in this
                wallet. The daemon does not keep it in plaintext.
                Without it, fund recovery is impossible if the
                keystore file or its passphrase are lost.
              </p>
              <div
                className="mono"
                style={{
                  marginTop: 12,
                  padding: 16,
                  background: "var(--bg-subtle, rgba(0,0,0,0.06))",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  wordSpacing: 4,
                  lineHeight: 1.8,
                  fontSize: 16,
                  userSelect: "text",
                }}
              >
                {generatedMnemonic}
              </div>
              <button
                className="secondary"
                onClick={() => copy(generatedMnemonic)}
                style={{ marginTop: 8 }}
              >
                {copied ? "copied" : "Copy to clipboard"}
              </button>
            </div>
            <div className="row">
              <button
                className="primary"
                onClick={onAckMnemonic}
                style={{ width: "100%" }}
              >
                I have written it down
              </button>
            </div>
          </>
        )}

        {/* Step 2 (import): enter existing mnemonic. */}
        {step === "enter_mnemonic" && (
          <>
            <div className="col">
              <label>BIP-39 mnemonic (12 or 24 words)</label>
              <textarea
                value={mnemonic}
                onChange={(e) => setMnemonic(e.target.value)}
                disabled={busy}
                placeholder="word1 word2 word3 ..."
                rows={4}
                style={{
                  fontFamily: "var(--mono, monospace)",
                  resize: "vertical",
                }}
                autoFocus
              />
            </div>
            <p className="muted" style={{ margin: 0, fontSize: 12 }}>
              Whitespace is normalised — paste from any line wrapping.
              The mnemonic is sent over the local IPC socket to the
              daemon and then encrypted at rest with your passphrase.
              It is never sent over the network.
            </p>
            <div className="row" style={{ marginTop: 12 }}>
              <button
                className="secondary"
                onClick={() => setStep("name_pass")}
                style={{ marginRight: 8 }}
                disabled={busy}
              >
                Back
              </button>
              <button
                className="primary"
                onClick={onSubmitMnemonic}
                disabled={busy}
              >
                {busy ? "Importing…" : "Import"}
              </button>
            </div>
          </>
        )}

        {step === "submitting" && (
          <div
            style={{ padding: 24, textAlign: "center" }}
            className="muted"
          >
            Working…
          </div>
        )}

        {step === "confirm_acked" && (
          <div
            style={{
              padding: 24,
              textAlign: "center",
            }}
          >
            <div
              style={{ fontSize: 36, color: "var(--pass)", marginBottom: 4 }}
            >
              ✓
            </div>
            <div className="muted">Wallet ready</div>
          </div>
        )}
      </div>
    </div>
  );
}

function stepLabel(mode: "create" | "import", step: Step): string {
  if (mode === "create") {
    if (step === "name_pass") return "Step 1 of 2";
    if (step === "show_mnemonic") return "Step 2 of 2 — backup";
    return "";
  }
  if (step === "name_pass") return "Step 1 of 2";
  if (step === "enter_mnemonic") return "Step 2 of 2 — restore";
  return "";
}

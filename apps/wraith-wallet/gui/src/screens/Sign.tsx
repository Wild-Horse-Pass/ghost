import { useState } from "react";
import {
  psbtBroadcast,
  psbtBumpFee,
  psbtInspect,
  psbtSign,
  type PsbtInspectResponse,
} from "../lib/tauri";

interface SignProps {
  activeWallet: string | null;
}

/// PSBT signer screen.
///
/// Phase 1 scope: load a PSBT (paste, drop, or "Open file"),
/// inspect it, sign whatever inputs the active wallet can sign,
/// and export the result. This is the cosigner-role tool that
/// will later be the meeting point for hardware wallets and
/// multisig collaboration.
///
/// What we *don't* do here: build PSBTs from scratch (Phase 2,
/// owned by Send) or broadcast (also Phase 2 — sender-side flow).
/// A wallet that can sign a PSBT from elsewhere is already
/// useful as a participant in any external multisig setup.
export function Sign({ activeWallet }: SignProps) {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [inspectResp, setInspectResp] = useState<PsbtInspectResponse | null>(
    null,
  );
  const [signedPsbt, setSignedPsbt] = useState<string | null>(null);
  const [signedCount, setSignedCount] = useState<number | null>(null);

  // Reset to an "empty" state — used after a successful sign so the
  // user can drop in another PSBT without leftover state.
  const reset = () => {
    setInput("");
    setErr(null);
    setInfo(null);
    setInspectResp(null);
    setSignedPsbt(null);
    setSignedCount(null);
  };

  const onInspect = async (text: string) => {
    setErr(null);
    setInfo(null);
    setInspectResp(null);
    setSignedPsbt(null);
    setSignedCount(null);
    if (!text.trim()) return;
    setBusy(true);
    try {
      const r = await psbtInspect(text.trim());
      setInspectResp(r);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onPaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    // Auto-inspect on paste so the inspector populates
    // immediately. Keeps the manual "Inspect" button as a fallback.
    const text = e.clipboardData.getData("text");
    if (text && text.trim().length > 0) {
      setInput(text);
      // Defer to next tick so React state has caught up.
      setTimeout(() => onInspect(text), 0);
    }
  };

  const onDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer?.files?.[0];
    if (file) {
      const text = await readPsbtFile(file);
      setInput(text);
      onInspect(text);
    } else {
      const text = e.dataTransfer?.getData("text");
      if (text) {
        setInput(text);
        onInspect(text);
      }
    }
  };

  const onPickFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await readPsbtFile(file);
    setInput(text);
    onInspect(text);
    // Reset the input so re-picking the same file works.
    e.target.value = "";
  };

  const onSign = async () => {
    if (!inspectResp) return;
    setErr(null);
    setInfo(null);
    setBusy(true);
    try {
      const r = await psbtSign(input.trim());
      setSignedPsbt(r.psbt);
      setSignedCount(r.signed_inputs.length);
      // Re-inspect so the GUI shows the input rows as finalized.
      const fresh = await psbtInspect(r.psbt);
      setInspectResp(fresh);
      if (r.signed_inputs.length === 0) {
        setInfo(
          "No inputs were signable by this wallet. The PSBT is unchanged. " +
            "Multi-cosigner flows: pass it to the next signer.",
        );
      } else if (r.is_complete) {
        setInfo(
          `Signed ${r.signed_inputs.length} input(s). PSBT is now complete and ready to broadcast.`,
        );
      } else {
        setInfo(
          `Signed ${r.signed_inputs.length} input(s). Pass the result to the remaining cosigners — ${
            r.input_count - r.signed_inputs.length
          } input(s) still need signatures.`,
        );
      }
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onCopySigned = async () => {
    if (!signedPsbt) return;
    try {
      await navigator.clipboard.writeText(signedPsbt);
      setInfo("Signed PSBT copied to clipboard.");
    } catch {
      setErr("Clipboard access denied — use the Download button instead.");
    }
  };

  const onDownloadSigned = () => {
    if (!signedPsbt) return;
    const isHex = /^[0-9a-fA-F\s]+$/.test(signedPsbt.trim());
    const ext = isHex ? "psbt.hex" : "psbt";
    const filename = `signed-${inspectResp?.txid?.slice(0, 12) ?? "wraith"}.${ext}`;
    const blob = new Blob([signedPsbt], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  };

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">cosigner</span>
          <h1>Sign PSBT</h1>
          <p className="lead">
            Drop in a partially-signed Bitcoin transaction (BIP-174) —
            base64 or hex — and Wraith signs every input the active
            wallet owns. Pair with a hardware wallet, multisig
            cosigner, or air-gapped signer.
          </p>
        </div>
      </div>

      {!activeWallet && (
        <div className="card muted">
          Select and unlock a wallet first. The inspector still works
          without one, but Sign needs an unlocked wallet to access
          its keys.
        </div>
      )}

      {err && <div className="card error-card">{err}</div>}
      {info && (
        <div className="card" style={{ borderColor: "var(--pass)" }}>
          {info}
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2>Load PSBT</h2>
          <span className="muted" style={{ fontSize: 11 }}>
            base64 or hex · paste, drop, or pick a file
          </span>
        </div>
        <div
          className="psbt-drop"
          onDragOver={(e) => e.preventDefault()}
          onDrop={onDrop}
        >
          <textarea
            value={input}
            placeholder="cHNidP8B…  or  70736274ff…"
            rows={4}
            onChange={(e) => setInput(e.target.value)}
            onPaste={onPaste}
            spellCheck={false}
            style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}
          />
        </div>
        <div className="row" style={{ gap: 8 }}>
          <button
            className="btn-secondary btn-sm"
            onClick={() => onInspect(input)}
            disabled={busy || !input.trim()}
          >
            Inspect
          </button>
          <label
            className="btn-secondary btn-sm"
            style={{ cursor: "pointer" }}
          >
            Open file…
            <input
              type="file"
              accept=".psbt,.txn,.hex,.txt,application/octet-stream"
              onChange={onPickFile}
              style={{ display: "none" }}
            />
          </label>
          <span className="spacer" />
          <button
            className="btn-secondary btn-sm"
            onClick={reset}
            disabled={busy && !input}
          >
            Clear
          </button>
        </div>
      </div>

      {inspectResp && (
        <PsbtInspector
          inspect={inspectResp}
          activeWallet={activeWallet}
          busy={busy}
          onSign={onSign}
          onBumpFee={async () => {
            if (!input.trim()) return;
            const promptVal = window.prompt(
              "Bump fee — new rate (sats/vB). Must strictly exceed the original.",
              "20",
            );
            if (!promptVal) return;
            const newRate = Number(promptVal);
            if (!Number.isFinite(newRate) || newRate <= 0) {
              setErr("Fee rate must be a positive number.");
              return;
            }
            setBusy(true);
            setErr(null);
            setInfo(null);
            try {
              const r = await psbtBumpFee({
                psbt: input.trim(),
                new_fee_rate_sats_per_vb: newRate,
              });
              // Replace the loaded PSBT with the bumped one and
              // re-inspect so the UI reflects the new state.
              setInput(r.psbt);
              const fresh = await psbtInspect(r.psbt);
              setInspectResp(fresh);
              setSignedPsbt(null);
              setSignedCount(null);
              setInfo(
                `Fee bumped: ${r.old_fee_sats.toLocaleString()} → ${r.new_fee_sats.toLocaleString()} sats. Sign + broadcast the new PSBT to replace the original in mempool.`,
              );
            } catch (e) {
              setErr((e as Error).message ?? String(e));
            } finally {
              setBusy(false);
            }
          }}
        />
      )}

      {signedPsbt && (
        <div className="card">
          <div className="card-header">
            <h2>Signed PSBT</h2>
            <span className="muted" style={{ fontSize: 11 }}>
              {signedCount ?? 0} input(s) signed ·{" "}
              {inspectResp?.is_complete ? "complete" : "needs more signatures"}
            </span>
          </div>
          <textarea
            readOnly
            value={signedPsbt}
            rows={3}
            spellCheck={false}
            style={{ fontFamily: "var(--font-mono)", fontSize: 10 }}
          />
          <div className="row" style={{ gap: 8 }}>
            <button className="btn-secondary btn-sm" onClick={onCopySigned}>
              Copy
            </button>
            <button
              className="btn-secondary btn-sm"
              onClick={onDownloadSigned}
            >
              Download
            </button>
            {inspectResp?.is_complete && (
              <button
                className="btn-primary btn-sm"
                onClick={async () => {
                  if (!signedPsbt) return;
                  if (
                    !window.confirm(
                      "Broadcast this transaction now via ghost-pay → bitcoind?\n\nOnce broadcast, this cannot be undone — the operator's node will relay it to the network.",
                    )
                  ) {
                    return;
                  }
                  setBusy(true);
                  setErr(null);
                  setInfo(null);
                  try {
                    const r = await psbtBroadcast(signedPsbt);
                    setInfo(`Broadcast accepted. txid: ${r.txid}`);
                  } catch (e) {
                    setErr((e as Error).message ?? String(e));
                  } finally {
                    setBusy(false);
                  }
                }}
                disabled={busy}
                title="Broadcast via ghost-pay (operator's bitcoind)"
              >
                Broadcast
              </button>
            )}
            <span className="spacer" />
            <button className="btn-secondary btn-sm" onClick={reset}>
              Sign another
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

interface InspectorProps {
  inspect: PsbtInspectResponse;
  activeWallet: string | null;
  busy: boolean;
  onSign: () => void;
  onBumpFee: () => void;
}

function PsbtInspector({
  inspect,
  activeWallet,
  busy,
  onSign,
  onBumpFee,
}: InspectorProps) {
  const signableCount = inspect.inputs.filter(
    (i) => i.is_signable_by_active_wallet,
  ).length;
  const signedCount = inspect.inputs.filter((i) => i.is_finalized).length;

  return (
    <>
      <div className="card">
        <div className="card-header">
          <h2>Transaction</h2>
          <span
            className={`pill ${inspect.is_complete ? "pass" : "warn"}`}
            style={{ fontSize: 11 }}
          >
            {inspect.is_complete
              ? "complete"
              : `${signedCount} of ${inspect.inputs.length} signed`}
          </span>
        </div>
        <div className="kv">
          <div className="k">Network</div>
          <div className="v">
            <span className="pill mute" style={{ fontSize: 10 }}>
              {inspect.network}
            </span>
          </div>
          <div className="k">Txid</div>
          <div className="v mono" style={{ fontSize: 11, wordBreak: "break-all" }}>
            {inspect.txid}
          </div>
          <div className="k">Total in</div>
          <div className="v mono">
            {inspect.total_in_sats != null
              ? `${inspect.total_in_sats.toLocaleString()} sats`
              : "—"}
          </div>
          <div className="k">Total out</div>
          <div className="v mono">
            {inspect.total_out_sats.toLocaleString()} sats
          </div>
          <div className="k">Fee</div>
          <div className="v mono">
            {inspect.fee_sats != null ? (
              <>
                {inspect.fee_sats.toLocaleString()} sats
                {inspect.fee_sats < 0 && (
                  <span
                    className="pill fail"
                    style={{ marginLeft: 8, fontSize: 10 }}
                  >
                    NEGATIVE — invalid PSBT
                  </span>
                )}
              </>
            ) : (
              <span className="muted">undeterminable (missing prevouts)</span>
            )}
          </div>
        </div>
        {activeWallet && (
          <div className="row" style={{ gap: 8, marginTop: 8 }}>
            <button
              className="btn-primary"
              onClick={onSign}
              disabled={busy || !inspect.has_signable_inputs || inspect.is_complete}
              title={
                inspect.is_complete
                  ? "PSBT is already complete — no inputs need signing"
                  : !inspect.has_signable_inputs
                    ? "No inputs in this PSBT are signable by the active wallet"
                    : `Sign ${signableCount} input(s) with ${activeWallet}`
              }
            >
              {busy
                ? "Signing…"
                : inspect.is_complete
                  ? "Already complete"
                  : !inspect.has_signable_inputs
                    ? "Nothing for this wallet to sign"
                    : `Sign ${signableCount} input(s)`}
            </button>
            {!inspect.is_complete && (
              <button
                className="btn-secondary"
                onClick={onBumpFee}
                disabled={busy}
                title="BIP-125 RBF fee-bump. Reduces the wallet's change output to absorb a higher fee, returns a new unsigned PSBT that needs re-signing."
              >
                Bump fee…
              </button>
            )}
          </div>
        )}
      </div>

      <div className="card">
        <h2>Inputs ({inspect.inputs.length})</h2>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 32 }}>#</th>
              <th>Outpoint</th>
              <th>Address</th>
              <th style={{ width: 100, textAlign: "right" }}>Sats</th>
              <th style={{ width: 110 }}>State</th>
            </tr>
          </thead>
          <tbody>
            {inspect.inputs.map((i, idx) => (
              <tr key={idx}>
                <td className="mono" style={{ fontSize: 11 }}>
                  {idx}
                </td>
                <td className="mono" style={{ fontSize: 10, wordBreak: "break-all" }}>
                  {i.previous_txid.slice(0, 12)}…:{i.previous_vout}
                </td>
                <td className="mono" style={{ fontSize: 11 }}>
                  {i.address ? (
                    <>
                      <span style={{ wordBreak: "break-all" }}>
                        {i.address}
                      </span>
                    </>
                  ) : (
                    <span className="muted">unknown</span>
                  )}
                </td>
                <td className="mono" style={{ textAlign: "right", fontSize: 12 }}>
                  {i.value_sats != null ? i.value_sats.toLocaleString() : "—"}
                </td>
                <td>
                  {i.is_finalized ? (
                    <span className="pill pass" style={{ fontSize: 10 }}>
                      finalized
                    </span>
                  ) : i.is_signable_by_active_wallet ? (
                    <span className="pill warn" style={{ fontSize: 10 }}>
                      signs with you
                    </span>
                  ) : i.partial_signatures > 0 ? (
                    <span className="pill mute" style={{ fontSize: 10 }}>
                      {i.partial_signatures} sig
                      {i.partial_signatures === 1 ? "" : "s"}
                    </span>
                  ) : (
                    <span className="pill mute" style={{ fontSize: 10 }}>
                      unsigned
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>Outputs ({inspect.outputs.length})</h2>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 32 }}>#</th>
              <th>Address</th>
              <th style={{ width: 100, textAlign: "right" }}>Sats</th>
              <th style={{ width: 80 }}></th>
            </tr>
          </thead>
          <tbody>
            {inspect.outputs.map((o, idx) => (
              <tr key={idx}>
                <td className="mono" style={{ fontSize: 11 }}>
                  {idx}
                </td>
                <td className="mono" style={{ fontSize: 11, wordBreak: "break-all" }}>
                  {o.address ?? `script: ${o.script_pubkey_hex.slice(0, 24)}…`}
                </td>
                <td className="mono" style={{ textAlign: "right", fontSize: 12 }}>
                  {o.value_sats.toLocaleString()}
                </td>
                <td>
                  {o.is_owned_by_active_wallet && (
                    <span className="pill pass" style={{ fontSize: 10 }}>
                      change
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

async function readPsbtFile(file: File): Promise<string> {
  // PSBT files can come as raw bytes (Sparrow / Bitcoin Core .psbt)
  // or as ASCII (hex / base64). Sniff by reading as bytes first;
  // if the magic matches, we'll convert to hex. If the bytes
  // decode to ASCII that starts with the base64 prefix, return as
  // text. Anything else: treat as text and let the daemon error.
  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  if (
    bytes.length >= 5 &&
    bytes[0] === 0x70 &&
    bytes[1] === 0x73 &&
    bytes[2] === 0x62 &&
    bytes[3] === 0x74 &&
    bytes[4] === 0xff
  ) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes).trim();
}

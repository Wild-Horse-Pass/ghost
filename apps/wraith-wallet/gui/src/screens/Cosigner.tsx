import { useEffect, useState } from "react";
import {
  multisigDescriptorAddresses,
  multisigDescriptorDelete,
  multisigDescriptorInspect,
  multisigDescriptorList,
  multisigDescriptorSave,
  walletExportXpub,
  type MultisigDescriptorInspected,
  type MultisigDescriptorListEntry,
  type WalletXpubResponse,
} from "../lib/tauri";

interface CosignerProps {
  activeWallet: string | null;
}

interface PathPreset {
  id: string;
  label: string;
  path: string;
  mainnet: boolean;
  hint: string;
  use_case: string;
}

/// Standard derivation paths a cosigner is asked for. The IDs map
/// to the Bitcoin / Ghost ecosystem conventions:
///
/// - BIP-86 mainnet (`m/86'/0'/0'`) → P2TR account; pair with
///   `tr(multi_a(K, A, B, …))` taproot multisig wrapper.
/// - BIP-86 testnet (`m/86'/1'/0'`) → P2TR testnet/signet/regtest
///   account.
/// - BIP-48 mainnet P2WSH (`m/48'/0'/0'/2'`) → traditional P2WSH
///   multisig (the path Sparrow / Specter / Bitcoin Core's
///   `wsh(sortedmulti(…))` expects).
/// - BIP-48 testnet P2WSH (`m/48'/1'/0'/2'`) → testnet equivalent.
/// - BIP-86 Ghost (`m/86'/531'/0'`) → Ghost-network taproot account;
///   for in-protocol multisig with other Wraith wallets on Ghost.
///
/// All paths are account-level (3 or 4 hardened components) so the
/// receiver / change branches can be derived deterministically by
/// the descriptor.
const PRESETS: PathPreset[] = [
  {
    id: "p2tr-mainnet",
    label: "Bitcoin mainnet — taproot (BIP-86)",
    path: "m/86'/0'/0'",
    mainnet: true,
    hint: "Account-level xpub for P2TR multisig.",
    use_case: "tr(multi_a(K, A, B, …)) taproot multisig",
  },
  {
    id: "p2tr-testnet",
    label: "Bitcoin testnet/signet — taproot (BIP-86)",
    path: "m/86'/1'/0'",
    mainnet: false,
    hint: "Account-level tpub for testnet/signet/regtest P2TR multisig.",
    use_case: "tr(multi_a(...)) on testnet",
  },
  {
    id: "p2wsh-mainnet",
    label: "Bitcoin mainnet — P2WSH (BIP-48)",
    path: "m/48'/0'/0'/2'",
    mainnet: true,
    hint: "Account-level xpub for traditional native-segwit multisig.",
    use_case: "wsh(sortedmulti(K, A, B, …))",
  },
  {
    id: "p2wsh-testnet",
    label: "Bitcoin testnet/signet — P2WSH (BIP-48)",
    path: "m/48'/1'/0'/2'",
    mainnet: false,
    hint: "Account-level tpub for testnet P2WSH multisig.",
    use_case: "wsh(sortedmulti(...)) on testnet",
  },
  {
    id: "ghost-tr",
    label: "Ghost network — taproot (BIP-86)",
    path: "m/86'/531'/0'",
    mainnet: true,
    hint: "Account-level xpub on Ghost's BIP-44 coin-type 531.",
    use_case: "Ghost-internal taproot multisig",
  },
];

/// Cosigner export screen.
///
/// Wraith holds the seed; the user wants to participate as a
/// cosigner in a multisig set up elsewhere (Sparrow, Specter,
/// Bitcoin Core descriptor wallet, another Wraith). The flow is
/// always the same:
///
///   1. Each cosigner exports an xpub at a standard derivation
///      path, plus their master fingerprint.
///   2. A coordinator collects the xpubs and assembles a descriptor
///      like `wsh(sortedmulti(2, [fp1/.../48'/0'/0'/2']xpub1...,
///      [fp2/.../48'/0'/0'/2']xpub2..., ...))`.
///   3. Each cosigner imports the descriptor and verifies their own
///      xpub is in it (fingerprint check).
///
/// This screen covers step 1. Steps 2 and 3 happen in the
/// coordinator's tool today; in-Wraith descriptor import + receive
/// + sign-as-cosigner is the next phase.
export function Cosigner({ activeWallet }: CosignerProps) {
  const [exportsByPreset, setExportsByPreset] = useState<
    Record<string, WalletXpubResponse>
  >({});
  const [loading, setLoading] = useState<Set<string>>(new Set());
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  // Custom-path state — power-user escape hatch for non-standard
  // derivation schemes. Coordinators occasionally request these.
  const [customPath, setCustomPath] = useState("m/86'/0'/0'");
  const [customMainnet, setCustomMainnet] = useState(true);
  const [customResult, setCustomResult] = useState<WalletXpubResponse | null>(
    null,
  );

  // Descriptor import state. The flow is: paste a descriptor →
  // inspect → save under a name → it joins the saved list and we
  // can derive addresses from it.
  const [descInput, setDescInput] = useState("");
  const [descInspect, setDescInspect] = useState<
    MultisigDescriptorInspected | null
  >(null);
  const [descSaveName, setDescSaveName] = useState("");
  const [savedDescs, setSavedDescs] = useState<MultisigDescriptorListEntry[]>([]);
  const [openDescName, setOpenDescName] = useState<string | null>(null);
  const [openDescAddrs, setOpenDescAddrs] = useState<
    { index: number; address: string }[]
  >([]);

  // Re-export presets across wallet switches so we never show
  // stale fingerprints belonging to a previous wallet.
  useEffect(() => {
    setExportsByPreset({});
    setCustomResult(null);
    setErr(null);
    setInfo(null);
    setDescInput("");
    setDescInspect(null);
    setDescSaveName("");
    setSavedDescs([]);
    setOpenDescName(null);
    setOpenDescAddrs([]);
    if (activeWallet) {
      multisigDescriptorList()
        .then((r) => setSavedDescs(r.descriptors))
        .catch(() => {});
    }
  }, [activeWallet]);

  const refreshSavedDescs = async () => {
    if (!activeWallet) return;
    try {
      const r = await multisigDescriptorList();
      setSavedDescs(r.descriptors);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  const onInspectDescriptor = async () => {
    setErr(null);
    setInfo(null);
    setDescInspect(null);
    if (!descInput.trim()) {
      setErr("Paste a descriptor first.");
      return;
    }
    try {
      const r = await multisigDescriptorInspect(descInput.trim(), 5);
      setDescInspect(r);
      // Default the save name from the descriptor's k-of-n shape.
      if (!descSaveName) {
        setDescSaveName(`${r.k}-of-${r.n}-multisig`);
      }
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  const onSaveDescriptor = async () => {
    setErr(null);
    setInfo(null);
    if (!descInspect) return;
    if (!descSaveName.trim()) {
      setErr("Give the descriptor a name first.");
      return;
    }
    if (!descInspect.contains_us) {
      setErr(
        "This descriptor doesn't contain the active wallet's fingerprint — refusing to save.",
      );
      return;
    }
    try {
      await multisigDescriptorSave(descSaveName.trim(), descInput.trim());
      setInfo(`Saved as "${descSaveName.trim()}".`);
      setDescInput("");
      setDescInspect(null);
      setDescSaveName("");
      await refreshSavedDescs();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  const onOpenDescriptor = async (name: string) => {
    setErr(null);
    setInfo(null);
    if (openDescName === name) {
      setOpenDescName(null);
      setOpenDescAddrs([]);
      return;
    }
    try {
      const r = await multisigDescriptorAddresses({
        name,
        start_index: 0,
        count: 5,
        internal: false,
      });
      setOpenDescName(name);
      setOpenDescAddrs(r.addresses);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  const onDeleteDescriptor = async (name: string) => {
    if (
      !window.confirm(
        `Remove the saved multisig descriptor "${name}" from this wallet?\n\nThis only deletes the local record — funds at multisig addresses are unaffected.`,
      )
    ) {
      return;
    }
    try {
      await multisigDescriptorDelete(name);
      if (openDescName === name) {
        setOpenDescName(null);
        setOpenDescAddrs([]);
      }
      await refreshSavedDescs();
      setInfo(`Removed "${name}".`);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  const exportPreset = async (preset: PathPreset) => {
    setLoading((prev) => new Set(prev).add(preset.id));
    setErr(null);
    try {
      const r = await walletExportXpub(preset.path, preset.mainnet);
      setExportsByPreset((prev) => ({ ...prev, [preset.id]: r }));
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setLoading((prev) => {
        const next = new Set(prev);
        next.delete(preset.id);
        return next;
      });
    }
  };

  const exportCustom = async () => {
    setErr(null);
    setInfo(null);
    if (!customPath.trim()) {
      setErr("Path required.");
      return;
    }
    try {
      const r = await walletExportXpub(customPath.trim(), customMainnet);
      setCustomResult(r);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setInfo(`${label} copied to clipboard.`);
    } catch {
      setErr(`Couldn't copy ${label} — clipboard access denied.`);
    }
  };

  if (!activeWallet) {
    return (
      <div className="screen">
        <div className="page-head">
          <div>
            <span className="eyebrow">multisig</span>
            <h1>Cosigner</h1>
            <p className="lead">
              Export your wallet's extended public keys for use in
              multisig setups. Select and unlock a wallet first.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">multisig</span>
          <h1>Cosigner</h1>
          <p className="lead">
            Export your wallet's extended public keys (xpub / tpub) so
            a coordinator can assemble a multisig descriptor with
            other cosigners. Public-only — private keys stay on the
            daemon.
          </p>
        </div>
      </div>

      {err && <div className="card error-card">{err}</div>}
      {info && (
        <div className="card" style={{ borderColor: "var(--pass)" }}>
          {info}
        </div>
      )}

      <div className="card">
        <h2>How multisig setup works</h2>
        <ol
          className="muted"
          style={{ fontSize: 13, lineHeight: 1.6, paddingLeft: 18 }}
        >
          <li>
            Each cosigner exports an xpub at a matching derivation
            path (use the same preset across all participants).
          </li>
          <li>
            One participant ("the coordinator") collects everyone's
            xpubs + master fingerprints and builds a descriptor
            string like{" "}
            <code className="mono">
              wsh(sortedmulti(2, [fp1/...]xpub1, [fp2/...]xpub2,
              [fp3/...]xpub3))
            </code>
            .
          </li>
          <li>
            Each cosigner imports the final descriptor in their own
            wallet and verifies their fingerprint is in it. Wraith's
            descriptor import is the next iteration; for now you can
            still verify by sight from the fingerprint shown below.
          </li>
        </ol>
      </div>

      <div className="card">
        <h2>Standard cosigner exports</h2>
        <p className="muted" style={{ fontSize: 12, margin: 0 }}>
          Most coordinators will ask for one of these. Click to
          derive — the daemon never reveals private keys.
        </p>
        <div className="col" style={{ gap: 12, marginTop: 8 }}>
          {PRESETS.map((p) => {
            const exported = exportsByPreset[p.id];
            const isLoading = loading.has(p.id);
            return (
              <div
                key={p.id}
                className="card"
                style={{ padding: 12, gap: 8, borderLeftWidth: 3 }}
              >
                <div className="row" style={{ alignItems: "baseline" }}>
                  <div style={{ flex: 1 }}>
                    <strong style={{ fontSize: 13 }}>{p.label}</strong>
                    <div
                      className="muted mono"
                      style={{ fontSize: 11, marginTop: 2 }}
                    >
                      {p.path}
                    </div>
                    <div
                      className="muted"
                      style={{ fontSize: 11, marginTop: 4 }}
                    >
                      {p.hint} <em>{p.use_case}</em>
                    </div>
                  </div>
                  <button
                    className="btn-secondary btn-sm"
                    onClick={() => exportPreset(p)}
                    disabled={isLoading}
                  >
                    {isLoading
                      ? "Deriving…"
                      : exported
                        ? "Re-derive"
                        : "Export"}
                  </button>
                </div>
                {exported && (
                  <ExportResult result={exported} onCopy={copy} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ===== Imported multisig descriptors ===== */}
      <div className="card">
        <div className="card-header">
          <h2>Imported multisig setups</h2>
          <span className="muted" style={{ fontSize: 11 }}>
            descriptors saved on this wallet
          </span>
        </div>
        {savedDescs.length === 0 ? (
          <p className="muted" style={{ fontSize: 12, margin: 0 }}>
            No multisig descriptors saved yet. Paste one in the
            "Import descriptor" section below to add receive
            addresses you can fund and spend from.
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Cosigners</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {savedDescs.map((d) => (
                <>
                  <tr key={d.name}>
                    <td>
                      <strong>{d.name}</strong>
                    </td>
                    <td>
                      <span className="pill mute" style={{ fontSize: 10 }}>
                        {d.k}-of-{d.n} {d.kind}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 10 }}>
                      {d.cosigner_fingerprints.join(" · ")}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn-secondary btn-sm"
                        onClick={() => onOpenDescriptor(d.name)}
                      >
                        {openDescName === d.name ? "Hide" : "Receive →"}
                      </button>{" "}
                      <button
                        className="btn-secondary btn-sm"
                        onClick={() => onDeleteDescriptor(d.name)}
                        title="Remove from local record (funds unaffected)"
                      >
                        ✕
                      </button>
                    </td>
                  </tr>
                  {openDescName === d.name && (
                    <tr>
                      <td colSpan={4} style={{ padding: 0 }}>
                        <div
                          style={{
                            background: "var(--surface-soft)",
                            padding: 12,
                          }}
                        >
                          <div
                            className="muted"
                            style={{ fontSize: 11, marginBottom: 8 }}
                          >
                            Receive addresses (external chain).
                            Send funds to these and they can be
                            spent via a coordinator-built PSBT —
                            wraith partial-signs in the Sign tab.
                          </div>
                          <table className="table">
                            <thead>
                              <tr>
                                <th style={{ width: 60 }}>Index</th>
                                <th>Address</th>
                                <th style={{ width: 60 }}></th>
                              </tr>
                            </thead>
                            <tbody>
                              {openDescAddrs.map((a) => (
                                <tr key={a.index}>
                                  <td className="mono">{a.index}</td>
                                  <td
                                    className="mono"
                                    style={{
                                      fontSize: 11,
                                      wordBreak: "break-all",
                                    }}
                                  >
                                    {a.address}
                                  </td>
                                  <td>
                                    <button
                                      className="btn-secondary btn-sm"
                                      onClick={() =>
                                        copy(a.address, "Address")
                                      }
                                      style={{ padding: "2px 8px" }}
                                    >
                                      Copy
                                    </button>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ===== Import a new descriptor ===== */}
      <div className="card">
        <div className="card-header">
          <h2>Import descriptor</h2>
          <span className="muted" style={{ fontSize: 11 }}>
            paste from your coordinator
          </span>
        </div>
        <p className="muted" style={{ fontSize: 12, margin: 0 }}>
          Drop in a <code className="mono">wsh(sortedmulti(K, ...))</code>{" "}
          descriptor your coordinator built. Wraith verifies one of
          its keys is in there before accepting it.
        </p>
        <textarea
          value={descInput}
          onChange={(e) => setDescInput(e.target.value)}
          placeholder="wsh(sortedmulti(2, [fp1/...]xpub1.../<0;1>/*, [fp2/...]xpub2.../<0;1>/*))#checksum"
          rows={3}
          spellCheck={false}
          style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}
        />
        <div className="row" style={{ gap: 8 }}>
          <button
            className="btn-secondary btn-sm"
            onClick={onInspectDescriptor}
            disabled={!descInput.trim()}
          >
            Inspect
          </button>
        </div>
        {descInspect && (
          <div className="card" style={{ padding: 12, gap: 6, marginTop: 6 }}>
            <div className="card-header">
              <h3>Parsed</h3>
              <span
                className={`pill ${descInspect.contains_us ? "pass" : "fail"}`}
                style={{ fontSize: 10 }}
              >
                {descInspect.contains_us
                  ? "this wallet IS a cosigner"
                  : "this wallet is NOT a cosigner — won't save"}
              </span>
            </div>
            <div className="kv" style={{ marginTop: 0 }}>
              <div className="k">Type</div>
              <div className="v">
                <strong>
                  {descInspect.k}-of-{descInspect.n} {descInspect.kind}
                </strong>
              </div>
              <div className="k">Cosigners</div>
              <div className="v">
                <table className="table" style={{ margin: 0 }}>
                  <tbody>
                    {descInspect.cosigners.map((c, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ fontSize: 10 }}>
                          {c.fingerprint_hex}
                        </td>
                        <td className="mono" style={{ fontSize: 10 }}>
                          {c.origin_path}
                        </td>
                        <td>
                          {c.is_us && (
                            <span
                              className="pill pass"
                              style={{ fontSize: 10 }}
                            >
                              you
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="k">Sample addresses</div>
              <div className="v">
                {descInspect.addresses.map((a, i) => (
                  <div
                    key={i}
                    className="mono"
                    style={{ fontSize: 10, wordBreak: "break-all" }}
                  >
                    {i}: {a}
                  </div>
                ))}
              </div>
            </div>
            <div className="row" style={{ gap: 8, alignItems: "center" }}>
              <input
                value={descSaveName}
                onChange={(e) => setDescSaveName(e.target.value)}
                placeholder="give it a name"
                style={{ flex: 1, maxWidth: 280 }}
              />
              <button
                className="btn-primary btn-sm"
                onClick={onSaveDescriptor}
                disabled={!descInspect.contains_us || !descSaveName.trim()}
                title={
                  descInspect.contains_us
                    ? "Save this descriptor for the active wallet"
                    : "Refusing — this wallet's key isn't in the descriptor"
                }
              >
                Save
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Custom path</h2>
          <span className="muted" style={{ fontSize: 11 }}>
            Power-user escape hatch — use only when a coordinator
            asks for a non-standard path
          </span>
        </div>
        <div className="row" style={{ alignItems: "flex-end", gap: 8 }}>
          <div className="col" style={{ flex: 1 }}>
            <label>Derivation path</label>
            <input
              className="mono"
              value={customPath}
              onChange={(e) => setCustomPath(e.target.value)}
              placeholder="m/48'/0'/0'/2'"
            />
          </div>
          <div className="col" style={{ flex: 0, minWidth: 120 }}>
            <label
              style={{
                fontSize: 11,
                display: "flex",
                alignItems: "center",
                gap: 6,
                cursor: "pointer",
                marginBottom: 4,
              }}
            >
              <input
                type="checkbox"
                checked={customMainnet}
                onChange={(e) => setCustomMainnet(e.target.checked)}
              />
              Mainnet (xpub)
            </label>
            <span className="muted" style={{ fontSize: 10 }}>
              {customMainnet ? "xpub prefix" : "tpub prefix"}
            </span>
          </div>
          <button className="btn-secondary btn-sm" onClick={exportCustom}>
            Export
          </button>
        </div>
        {customResult && (
          <ExportResult result={customResult} onCopy={copy} />
        )}
      </div>
    </div>
  );
}

interface ExportResultProps {
  result: WalletXpubResponse;
  onCopy: (text: string, label: string) => void;
}

/// Compact display of a single xpub export. Lays out the four
/// fields a coordinator needs (fingerprint, path, xpub, descriptor
/// fragment) with copy buttons on each. The descriptor fragment is
/// what most users actually paste into Sparrow / Specter / Bitcoin
/// Core, so it's surfaced first and most prominently.
function ExportResult({ result, onCopy }: ExportResultProps) {
  return (
    <div className="kv" style={{ marginTop: 4 }}>
      <div className="k">Fingerprint</div>
      <div className="v">
        <span className="mono">{result.master_fingerprint_hex}</span>
        <button
          className="btn-secondary btn-sm"
          onClick={() =>
            onCopy(result.master_fingerprint_hex, "Fingerprint")
          }
          style={{ marginLeft: 8, padding: "2px 8px" }}
        >
          Copy
        </button>
        <span className="muted" style={{ marginLeft: 12, fontSize: 11 }}>
          Cross-check this against your hardware wallet's "show
          fingerprint" screen, if you have one.
        </span>
      </div>

      <div className="k">Path</div>
      <div className="v mono" style={{ fontSize: 12 }}>
        {result.path}
        <span className="muted" style={{ marginLeft: 8, fontSize: 10 }}>
          ({result.network_label})
        </span>
      </div>

      <div className="k">xpub</div>
      <div className="v">
        <div
          className="mono"
          style={{
            fontSize: 10,
            wordBreak: "break-all",
            background: "var(--surface-soft)",
            padding: 6,
            borderRadius: 3,
          }}
        >
          {result.xpub}
        </div>
        <button
          className="btn-secondary btn-sm"
          onClick={() => onCopy(result.xpub, "xpub")}
          style={{ marginTop: 4 }}
        >
          Copy xpub
        </button>
      </div>

      <div className="k">
        Descriptor key
        <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>
          paste-ready
        </div>
      </div>
      <div className="v">
        <div
          className="mono"
          style={{
            fontSize: 10,
            wordBreak: "break-all",
            background: "var(--surface-soft)",
            padding: 6,
            borderRadius: 3,
            border: "1px solid var(--accent)",
          }}
        >
          {result.descriptor_key_fragment}
        </div>
        <button
          className="btn-primary btn-sm"
          onClick={() =>
            onCopy(result.descriptor_key_fragment, "Descriptor fragment")
          }
          style={{ marginTop: 4 }}
        >
          Copy fragment
        </button>
        <span className="muted" style={{ marginLeft: 8, fontSize: 11 }}>
          Drop this into a coordinator's "Add cosigner" slot — it's
          what tools like Sparrow / Specter / Bitcoin Core's
          <code className="mono"> importdescriptors</code> expect.
        </span>
      </div>
    </div>
  );
}

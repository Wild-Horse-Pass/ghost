import { useEffect, useRef } from "react";
import type { ChainStatusResponse } from "../lib/tauri";

interface SyncIndicatorProps {
  chain: ChainStatusResponse | null;
  /// Compact mode — single pill for the header. When false, renders
  /// a fuller two-line block (used by the dashboard hero).
  compact?: boolean;
}

interface SyncSample {
  ts: number;
  height: number;
}

/// Tracks the L1 height over time so we can compute blocks/sec
/// during IBD and turn that into an ETA. Two layers:
///   - L1: bitcoind verification progress + headers vs blocks
///   - L2: ghost-pay's finalized-block height (always at-tip
///         relative to chain_height; the wallet doesn't yet know
///         the L2 chain has its own headers/blocks split, so we
///         render it as a flat counter for now).
///
/// The component is render-cheap: parent polls chainStatus, we
/// just visualise. Sample history lives in a useRef so it survives
/// re-renders without causing them.
export function SyncIndicator({ chain, compact }: SyncIndicatorProps) {
  // Rolling 60s window of (timestamp, l1 height) samples.
  const samples = useRef<SyncSample[]>([]);
  useEffect(() => {
    if (!chain || chain.chain_height == null) return;
    const now = Date.now();
    samples.current.push({ ts: now, height: chain.chain_height });
    // Drop samples older than 90s; keep at most 30 entries.
    samples.current = samples.current
      .filter((s) => now - s.ts < 90_000)
      .slice(-30);
  }, [chain]);

  // ----- Derive state -----
  if (!chain) {
    return (
      <span className={compact ? "pill mute" : "pill mute live"}>connecting…</span>
    );
  }

  const blocks = chain.chain_height;
  const headers = chain.chain_headers;
  const progress = chain.chain_verification_progress;
  const ibd = chain.chain_initial_block_download;

  // L1 considered synced when:
  //  - blocks ≥ headers (the canonical "we've verified everything
  //    we know about")
  //  - AND IBD is false
  // verification_progress is intentionally NOT gating: regtest's
  // value stays well below 1.0 even when fully synced (Bitcoin
  // Core's heuristic uses chainwork, not block count). We only
  // surface progress in the syncing-state subtitle.
  const l1Synced =
    blocks != null &&
    (headers == null || blocks >= headers) &&
    ibd === false;

  // ----- Compact mode (header pill) -----
  if (compact) {
    if (l1Synced) {
      return (
        <span
          className="pill pass live"
          title={`L1 ${blocks?.toLocaleString()} · L2 ${chain.l2_height ?? "—"} · verification ${
            progress != null ? (progress * 100).toFixed(2) + "%" : "—"
          }`}
        >
          synced · #{blocks?.toLocaleString() ?? "—"}
        </span>
      );
    }
    // Syncing — show progress and ETA.
    const remaining =
      blocks != null && headers != null && headers > blocks
        ? headers - blocks
        : null;
    const eta = computeEta(samples.current, headers ?? null);
    const pct = progress != null ? Math.floor(progress * 100) : null;
    return (
      <span
        className="pill warn live"
        title={`L1 syncing — ${blocks?.toLocaleString() ?? "?"} of ${
          headers?.toLocaleString() ?? "?"
        }${pct != null ? ` · ${pct}%` : ""}${eta ? ` · ETA ${eta}` : ""}`}
      >
        syncing
        {pct != null ? ` · ${pct}%` : ""}
        {remaining != null ? ` · ${remaining.toLocaleString()} left` : ""}
      </span>
    );
  }

  // ----- Full mode (Network/dashboard) -----
  return (
    <div className="sync-block">
      <SyncRow
        label="L1"
        synced={l1Synced}
        height={blocks}
        target={headers}
        progress={progress}
        eta={
          !l1Synced ? computeEta(samples.current, headers ?? null) : null
        }
      />
      <SyncRow
        label="L2"
        synced={chain.l2_height != null}
        height={chain.l2_height}
        target={null}
        progress={null}
        eta={null}
        sublabel={chain.l2_epoch != null ? `epoch ${chain.l2_epoch}` : undefined}
      />
    </div>
  );
}

interface SyncRowProps {
  label: string;
  synced: boolean;
  height: number | null;
  target: number | null;
  progress: number | null;
  eta: string | null;
  sublabel?: string;
}

function SyncRow({
  label,
  synced,
  height,
  target,
  progress,
  eta,
  sublabel,
}: SyncRowProps) {
  return (
    <div className="sync-row">
      <div className="sync-row-label">
        <span className="eyebrow eyebrow-dim" style={{ fontSize: 10 }}>
          {label}
        </span>
      </div>
      <div className="sync-row-state">
        <span
          className={`pill ${synced ? "pass" : "warn"} live`}
          style={{ fontSize: 10 }}
        >
          {synced ? "synced" : "syncing"}
        </span>
        <span className="mono" style={{ fontSize: 13 }}>
          #{height?.toLocaleString() ?? "—"}
          {target != null && target > (height ?? 0) && (
            <span className="muted">
              {" "}/ {target.toLocaleString()}
            </span>
          )}
        </span>
        {progress != null && !synced && (
          <span className="muted" style={{ fontSize: 11 }}>
            {(progress * 100).toFixed(1)}%
          </span>
        )}
        {eta && (
          <span className="muted" style={{ fontSize: 11 }}>
            ETA {eta}
          </span>
        )}
        {sublabel && (
          <span className="muted" style={{ fontSize: 11 }}>
            {sublabel}
          </span>
        )}
      </div>
    </div>
  );
}

/// Compute a rough "X minutes" / "Y hours" remaining string from
/// the sample history. Returns null if we don't have enough data
/// to estimate (need ≥2 samples spanning ≥10s with positive
/// progress) or if we're already at the target.
function computeEta(samples: SyncSample[], target: number | null): string | null {
  if (target == null || samples.length < 2) return null;
  const first = samples[0];
  const last = samples[samples.length - 1];
  const spanSecs = (last.ts - first.ts) / 1000;
  if (spanSecs < 10) return null;
  const blocksDelta = last.height - first.height;
  if (blocksDelta <= 0) return null;
  const blocksPerSec = blocksDelta / spanSecs;
  const remaining = target - last.height;
  if (remaining <= 0) return null;
  const secsLeft = remaining / blocksPerSec;
  return formatDuration(secsLeft);
}

function formatDuration(secs: number): string {
  if (secs < 60) return `${Math.round(secs)}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) {
    const h = Math.floor(secs / 3600);
    const m = Math.round((secs % 3600) / 60);
    return m > 0 ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(secs / 86400);
  const h = Math.round((secs % 86400) / 3600);
  return h > 0 ? `${d}d ${h}h` : `${d}d`;
}

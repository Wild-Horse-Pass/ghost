import { useEffect, useState } from "react";
import {
  daemonEnv,
  daemonHealth,
  type DaemonEnvResponse,
  type HealthResponse,
} from "../lib/tauri";

interface SettingsProps {
  /// GUI-side kiosk toggle (per-install, persisted in localStorage).
  /// Hides the nav and locks the GUI to Merchant. The daemon
  /// itself stays unrestricted, so this is a UX shortcut not a
  /// hard security barrier — see `daemonKiosk` for that.
  guiKiosk: boolean;
  /// Daemon-side kiosk lock from `WRAITHD_KIOSK_MODE`. Read-only
  /// here: the daemon refuses wallet-management ops until it
  /// restarts without the env var. The "real" till lock.
  daemonKiosk: boolean;
  onToggleGuiKiosk: (next: boolean) => void;
}

/// Read-only inspection of the daemon's environment + endpoints,
/// plus a small set of GUI-only tunables (kiosk lock, theme via
/// header). Daemon-side knobs (Tor proxy, ghost-pay URLs, GSP
/// URLs, idle-lock, shroud window) are set via env vars at
/// wraithd boot — this screen surfaces what's currently active so
/// you can confirm what the daemon is using vs what you intended.
export function Settings({ guiKiosk, daemonKiosk, onToggleGuiKiosk }: SettingsProps) {
  const [env, setEnv] = useState<DaemonEnvResponse | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [e, h] = await Promise.all([daemonEnv(), daemonHealth()]);
        if (!alive) return;
        setEnv(e);
        setHealth(h);
        setErr(null);
      } catch (e) {
        if (!alive) return;
        setErr((e as Error).message ?? String(e));
      }
    };
    tick();
    const id = setInterval(tick, 8000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const fmtUptime = (secs: number | undefined): string => {
    if (secs == null) return "—";
    const m = Math.floor(secs / 60);
    const h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    return `${m}m ${secs % 60}s`;
  };

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">configuration</span>
          <h1>Settings</h1>
          <p className="lead">
            Daemon environment + endpoint config the running wraithd
            picked up at boot. To change any of these, restart wraithd
            with the relevant env var (see your stack startup script).
          </p>
        </div>
      </div>

      {err && (
        <div className="card error-card">
          <strong>Couldn't reach the daemon.</strong>
          <pre className="error-details">{err}</pre>
        </div>
      )}

      <div className="card">
        <h2>Daemon</h2>
        <div className="kv">
          <div className="k">Version</div>
          <div className="v mono">{health?.version ?? "—"}</div>
          <div className="k">Uptime</div>
          <div className="v">{fmtUptime(health?.uptime_secs)}</div>
          <div className="k">Network</div>
          <div className="v">
            <span className="pill mute">{env?.network ?? "—"}</span>
          </div>
          {env?.kiosk_mode && (
            <>
              <div className="k">Mode</div>
              <div className="v">
                <span className="pill warn">kiosk</span>
                <span className="muted" style={{ marginLeft: 8 }}>
                  wallet management is disabled
                </span>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="card">
        <h2>Storage</h2>
        <div className="kv">
          <div className="k">Wallets dir</div>
          <div className="v mono">{env?.wallets_dir ?? "—"}</div>
          <div className="k">IPC socket</div>
          <div className="v mono">{env?.socket_path ?? "—"}</div>
        </div>
      </div>

      <div className="card">
        <h2>Endpoints</h2>
        <div className="kv">
          <div className="k">ghost-pay</div>
          <div className="v mono">{env?.ghost_pay_urls.join(", ") ?? "—"}</div>
          <div className="k">GSP</div>
          <div className="v mono">{env?.gsp_urls.join(", ") ?? "—"}</div>
          <div className="k">Tor proxy</div>
          <div className="v mono">{env?.tor_proxy ?? "—"}</div>
        </div>
      </div>

      <div className="card">
        <h2>Privacy + lock</h2>
        <div className="kv">
          <div className="k">Idle auto-lock</div>
          <div className="v">
            {env == null
              ? "—"
              : env.idle_lock_secs === 0
                ? "disabled"
                : `${env.idle_lock_secs}s`}
          </div>
          <div className="k">Shroud window</div>
          <div className="v">
            {env == null
              ? "—"
              : env.shroud_max_ms === 0
                ? "disabled"
                : `0–${env.shroud_max_ms}ms`}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Merchant kiosk mode</h2>
          {(guiKiosk || daemonKiosk) && (
            <span className={`pill ${daemonKiosk ? "warn" : "warn"}`}>
              {daemonKiosk ? "daemon-locked" : "active"}
            </span>
          )}
        </div>
        <p>
          Locks the GUI to the Merchant screen, hides the
          wallet-management nav. Use this on a machine running as a
          dedicated till — staff can take payments but can't
          create / unlock / switch wallets.
        </p>
        <div className="kv">
          <div className="k">Daemon lock</div>
          <div className="v">
            <span className={`pill ${daemonKiosk ? "warn" : "mute"}`}>
              {daemonKiosk ? "active" : "off"}
            </span>
            <span
              className="muted"
              style={{ marginLeft: 8, fontSize: 12 }}
            >
              set via <code>WRAITHD_KIOSK_MODE</code>; daemon refuses
              wallet-management ops while it's set. Exit by
              restarting wraithd without the env var.
            </span>
          </div>
          <div className="k">GUI lock</div>
          <div className="v">
            <button
              className={guiKiosk ? "btn-secondary" : "btn-primary"}
              onClick={() => onToggleGuiKiosk(!guiKiosk)}
              disabled={daemonKiosk}
              title={
                daemonKiosk
                  ? "Daemon kiosk is already active — its lock supersedes the GUI toggle"
                  : guiKiosk
                    ? "Click to leave kiosk mode"
                    : "Click to enter kiosk mode (per-install, persisted)"
              }
            >
              {guiKiosk ? "Leave kiosk mode" : "Enter kiosk mode"}
            </button>
            <span
              className="muted"
              style={{ marginLeft: 8, fontSize: 12 }}
            >
              GUI-only — daemon stays unrestricted. Persisted in
              localStorage so it survives reload. For a real
              till deployment, also set the daemon lock above.
            </span>
          </div>
        </div>
      </div>

      <div className="card surface">
        <h2>About</h2>
        <p>
          Wraith Wallet is the desktop interface for{" "}
          <strong>Bitcoin Ghost</strong> — incentivised nodes,
          decentralised mining, private payments. Open source,
          self-custodial, ossifying.
        </p>
        <div className="row" style={{ marginTop: 8 }}>
          <a
            className="btn-secondary"
            href="https://bitcoinghost.org"
            target="_blank"
            rel="noreferrer noopener"
          >
            bitcoinghost.org
          </a>
          <a
            className="btn-secondary"
            href="https://github.com/bitcoin-ghost/ghost"
            target="_blank"
            rel="noreferrer noopener"
          >
            GitHub
          </a>
          <a
            className="btn-secondary"
            href="https://bitcoinghost.org/docs/"
            target="_blank"
            rel="noreferrer noopener"
          >
            Docs
          </a>
        </div>
      </div>
    </div>
  );
}

export interface DaemonEnvResponseExtended extends DaemonEnvResponse {
  idle_lock_secs: number;
  shroud_max_ms: number;
}

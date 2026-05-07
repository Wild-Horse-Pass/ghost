import { useEffect, useState } from "react";
import {
  daemonHealth,
  daemonEnv,
  daemonDoctor,
  gspAuth,
  gspSessionStatus,
  type DaemonEnvResponse,
  type HealthResponse,
} from "../lib/tauri";

export function Network() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [env, setEnv] = useState<DaemonEnvResponse | null>(null);
  const [doctor, setDoctor] = useState<unknown>(null);
  const [session, setSession] = useState<unknown>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    setErr(null);
    try {
      setHealth(await daemonHealth());
      setEnv(await daemonEnv());
      setSession(await gspSessionStatus());
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 8000);
    return () => clearInterval(id);
  }, []);

  const onAuth = async () => {
    setBusy(true);
    setErr(null);
    try {
      await gspAuth();
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onDoctor = async () => {
    setBusy(true);
    setErr(null);
    try {
      setDoctor(await daemonDoctor());
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const fmtUptime = (secs: number | undefined) => {
    if (!secs && secs !== 0) return "—";
    const m = Math.floor(secs / 60);
    const h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    return `${m}m ${secs % 60}s`;
  };

  return (
    <div className="screen">
      <h1>Network</h1>
      {err && (
        <div className="card" style={{ borderColor: "var(--fail)" }}>
          {err}
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2>Daemon</h2>
          <span className={`pill ${health ? "pass" : "fail"}`}>
            {health ? "ok" : "offline"}
          </span>
        </div>
        <div className="kv">
          <div className="k">Status</div>
          <div className="v">{health?.status ?? "—"}</div>
          <div className="k">Version</div>
          <div className="v">{health?.version ?? "—"}</div>
          <div className="k">Uptime</div>
          <div className="v">{fmtUptime(health?.uptime_secs)}</div>
          <div className="k">Network</div>
          <div className="v">{env?.network ?? "—"}</div>
          <div className="k">Socket</div>
          <div className="v">{env?.socket_path ?? "—"}</div>
          <div className="k">Wallets dir</div>
          <div className="v">{env?.wallets_dir ?? "—"}</div>
        </div>
      </div>

      <div className="card">
        <h2>Endpoints</h2>
        <div className="kv">
          <div className="k">ghost-pay</div>
          <div className="v">{env?.ghost_pay_urls.join(", ") ?? "—"}</div>
          <div className="k">GSP</div>
          <div className="v">{env?.gsp_urls.join(", ") ?? "—"}</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>GSP session</h2>
          <button className="secondary" onClick={onAuth} disabled={busy}>
            Re-auth
          </button>
        </div>
        <pre
          className="mono"
          style={{
            margin: 0,
            background: "var(--bg)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: 12,
            maxHeight: 200,
            overflow: "auto",
          }}
        >
          {session ? JSON.stringify(session, null, 2) : "—"}
        </pre>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Doctor</h2>
          <button className="secondary" onClick={onDoctor} disabled={busy}>
            Run check
          </button>
        </div>
        <pre
          className="mono"
          style={{
            margin: 0,
            background: "var(--bg)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: 12,
            maxHeight: 240,
            overflow: "auto",
          }}
        >
          {doctor ? JSON.stringify(doctor, null, 2) : "Run a connectivity sweep across daemon, ghost-pay, and GSP."}
        </pre>
      </div>
    </div>
  );
}

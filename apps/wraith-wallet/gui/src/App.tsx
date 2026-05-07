import { useEffect, useState } from "react";
import { daemonEnv, walletStatus } from "./lib/tauri";
import { Wallet } from "./screens/Wallet";
import { Receive } from "./screens/Receive";
import { Send } from "./screens/Send";
import { Locks } from "./screens/Locks";
import { History } from "./screens/History";
import { Network } from "./screens/Network";

type Screen = "wallet" | "receive" | "send" | "locks" | "history" | "network";

const NAV: Array<{ id: Screen; label: string }> = [
  { id: "wallet", label: "Wallet" },
  { id: "receive", label: "Receive" },
  { id: "send", label: "Send" },
  { id: "locks", label: "Locks" },
  { id: "history", label: "History" },
  { id: "network", label: "Network" },
];

export default function App() {
  const [screen, setScreen] = useState<Screen>("wallet");
  const [statusText, setStatusText] = useState("connecting…");
  const [activeWallet, setActiveWallet] = useState<string | null>(null);

  // Refresh the header status every 4s. Cheap — both calls are
  // local IPC round-trips.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const env = await daemonEnv();
        const w = await walletStatus();
        if (!alive) return;
        setActiveWallet(w.active);
        const wpart = w.active
          ? `${w.active}${w.unlocked ? "" : " (locked)"}`
          : "no wallet";
        setStatusText(`${env.network} • ${wpart}`);
      } catch (e) {
        if (!alive) return;
        setStatusText(`daemon offline (${(e as Error).message ?? e})`);
      }
    };
    tick();
    const id = setInterval(tick, 4000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="app">
      <header className="app-header">
        <div className="title">Wraith Wallet</div>
        <div className="spacer" />
        <div className="status">{statusText}</div>
      </header>

      <aside className="app-sidebar">
        <nav>
          {NAV.map((item) => (
            <button
              key={item.id}
              className={screen === item.id ? "active" : ""}
              onClick={() => setScreen(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </aside>

      <main className="app-main">
        {screen === "wallet" && <Wallet />}
        {screen === "receive" && <Receive />}
        {screen === "send" && (
          <Send activeWallet={activeWallet} />
        )}
        {screen === "locks" && <Locks />}
        {screen === "history" && <History />}
        {screen === "network" && <Network />}
      </main>
    </div>
  );
}

import { useEffect, useState } from "react";
import {
  daemonEnv,
  onPaymentDetected,
  onWatchError,
  startWatch,
  walletStatus,
  type DetectedPayment,
} from "./lib/tauri";
import { Wallet } from "./screens/Wallet";
import { Receive } from "./screens/Receive";
import { Send } from "./screens/Send";
import { Mix } from "./screens/Mix";
import { Merchant } from "./screens/Merchant";
import { Locks } from "./screens/Locks";
import { History } from "./screens/History";
import { Network } from "./screens/Network";

type Screen =
  | "wallet"
  | "receive"
  | "send"
  | "mix"
  | "merchant"
  | "locks"
  | "history"
  | "network";

const NAV: Array<{ id: Screen; label: string }> = [
  { id: "wallet", label: "Wallet" },
  { id: "receive", label: "Receive" },
  { id: "send", label: "Send" },
  { id: "mix", label: "Mix" },
  { id: "merchant", label: "Merchant" },
  { id: "locks", label: "Locks" },
  { id: "history", label: "History" },
  { id: "network", label: "Network" },
];

export default function App() {
  const [screen, setScreen] = useState<Screen>("wallet");
  const [statusText, setStatusText] = useState("connecting…");
  const [activeWallet, setActiveWallet] = useState<string | null>(null);
  // Bumped each time the daemon pushes a `PaymentDetected` event.
  // Screens that care about live updates (e.g. History) treat this
  // as a useEffect dep and re-fetch immediately, so the user sees
  // incoming sats land without waiting for the next 5s poll tick.
  const [paymentTick, setPaymentTick] = useState(0);
  const [lastDetect, setLastDetect] = useState<DetectedPayment | null>(null);
  const [watchErr, setWatchErr] = useState<string | null>(null);
  // Kiosk mode locks the GUI to the Merchant screen and hides
  // wallet-management nav. Set by the daemon via WRAITHD_KIOSK_MODE
  // and surfaced through DaemonEnv. The daemon also refuses
  // wallet-management ops when this is set, so the lock is
  // enforced server-side too.
  const [kioskMode, setKioskMode] = useState(false);

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
        if (env.kiosk_mode && !kioskMode) {
          // Daemon entered kiosk mode (or we just learned about it
          // on first env fetch). Snap to Merchant — the only screen
          // that's meant to be reachable in kiosk mode.
          setKioskMode(true);
          setScreen("merchant");
        } else if (!env.kiosk_mode && kioskMode) {
          setKioskMode(false);
        }
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

  // Live BIP-352 receive notifications. The Tauri side keeps a
  // long-lived IPC connection to the daemon and forwards each
  // `PaymentDetected` push as a `wraith://payment-detected` event.
  // We pair `startWatch` (idempotent on the Rust side) with two
  // event subscriptions and clean up both on unmount.
  useEffect(() => {
    let alive = true;
    let unlistenDetect: (() => void) | undefined;
    let unlistenError: (() => void) | undefined;
    (async () => {
      try {
        unlistenDetect = await onPaymentDetected((p) => {
          if (!alive) return;
          setLastDetect(p);
          setPaymentTick((n) => n + 1);
        });
        unlistenError = await onWatchError((e) => {
          if (!alive) return;
          setWatchErr(e.message);
        });
        await startWatch();
      } catch (e) {
        if (!alive) return;
        setWatchErr((e as Error).message ?? String(e));
      }
    })();
    return () => {
      alive = false;
      if (unlistenDetect) unlistenDetect();
      if (unlistenError) unlistenError();
    };
  }, []);

  return (
    <div className={kioskMode ? "app kiosk" : "app"}>
      <header className="app-header">
        <div className="title">Wraith Wallet</div>
        <div className="spacer" />
        {kioskMode && (
          <div
            className="pill mute"
            style={{ marginRight: 8 }}
            title="Kiosk mode active — wallet management disabled. Restart wraithd without WRAITHD_KIOSK_MODE to exit."
          >
            kiosk mode
          </div>
        )}
        {lastDetect && (
          <div
            className="pill pass"
            style={{ marginRight: 8 }}
            title={`txid ${lastDetect.txid.slice(0, 12)}…  vout ${lastDetect.vout}`}
          >
            +{lastDetect.amount_sats.toLocaleString()} sats
          </div>
        )}
        {watchErr && (
          <div
            className="pill fail"
            style={{ marginRight: 8 }}
            title={watchErr}
          >
            watch offline
          </div>
        )}
        <div className="status">{statusText}</div>
      </header>

      {!kioskMode && (
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
      )}

      <main className="app-main">
        {screen === "wallet" && <Wallet paymentTick={paymentTick} />}
        {screen === "receive" && <Receive />}
        {screen === "send" && (
          <Send activeWallet={activeWallet} />
        )}
        {screen === "mix" && <Mix activeWallet={activeWallet} />}
        {screen === "merchant" && (
          <Merchant
            activeWallet={activeWallet}
            paymentTick={paymentTick}
          />
        )}
        {screen === "locks" && <Locks />}
        {screen === "history" && <History paymentTick={paymentTick} />}
        {screen === "network" && <Network />}
      </main>
    </div>
  );
}

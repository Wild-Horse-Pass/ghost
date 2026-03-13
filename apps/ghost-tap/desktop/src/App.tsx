import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { hasWallet, hasPin, loadWallet, verifyPin } from "./api/commands";
import { ConnectionProvider } from "./contexts/ConnectionContext";
import ToastProvider from "./components/ToastProvider";
import PinEntry from "./components/PinEntry";
import Layout from "./components/Layout";
import WalletSetup from "./pages/WalletSetup";
import Dashboard from "./pages/Dashboard";
import Terminal from "./pages/Terminal";
import Send from "./pages/Send";
import Receive from "./pages/Receive";
import History from "./pages/History";
import Invoices from "./pages/Invoices";
import Receipts from "./pages/Receipts";
import Export from "./pages/Export";
import WraithWash from "./pages/WraithWash";
import GlyphDesigner from "./pages/GlyphDesigner";
import Settings from "./pages/Settings";
import AddressBook from "./pages/AddressBook";
import SignVerify from "./pages/SignVerify";
import PSBTPage from "./pages/PSBT";
import CoinControl from "./pages/CoinControl";
import GhostLocks from "./pages/GhostLocks";
import CreateLock from "./pages/CreateLock";
import WithdrawWizard from "./pages/WithdrawWizard";
import SendL2 from "./pages/SendL2";
import GhostIdWizard from "./pages/GhostIdWizard";

type AppState = "loading" | "setup" | "pin" | "ready";

function AppRoutes() {
  const [appState, setAppState] = useState<AppState>("loading");
  const [pinError, setPinError] = useState("");

  useEffect(() => {
    // Browser preview mode — skip Tauri commands that don't exist outside the native shell
    const isBrowser = !(window as any).__TAURI_INTERNALS__;
    if (isBrowser) {
      setAppState("ready");
      return;
    }

    (async () => {
      const walletExists = await hasWallet();
      if (!walletExists) {
        setAppState("setup");
        return;
      }
      const pinSet = await hasPin();
      if (pinSet) {
        setAppState("pin");
      } else {
        // No PIN — load wallet with default PIN
        try {
          await loadWallet("000000");
        } catch {
          // Storage doesn't exist yet or wrong key — go to setup
        }
        setAppState("ready");
      }
    })();
  }, []);

  const handlePinSubmit = async (pin: string) => {
    setPinError("");
    const valid = await verifyPin(pin);
    if (!valid) {
      setPinError("Incorrect PIN");
      return;
    }
    try {
      await loadWallet(pin);
      setAppState("ready");
    } catch {
      setPinError("Failed to decrypt wallet");
    }
  };

  if (appState === "loading") {
    return null;
  }

  if (appState === "pin") {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100vh",
          flexDirection: "column",
        }}
      >
        <h1
          style={{
            color: "var(--accent)",
            fontSize: 28,
            marginBottom: 8,
          }}
        >
          GhostTap
        </h1>
        <p
          style={{
            color: "var(--text-secondary)",
            marginBottom: 32,
            fontSize: 13,
          }}
        >
          Merchant Terminal
        </p>
        <PinEntry onSubmit={handlePinSubmit} label="Enter PIN to unlock" />
        {pinError && (
          <div className="error-text" style={{ marginTop: 16 }}>
            {pinError}
          </div>
        )}
      </div>
    );
  }

  return (
    <Routes>
      <Route
        path="/setup"
        element={<WalletSetup onComplete={() => setAppState("ready")} />}
      />
      <Route element={<Layout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/terminal" element={<Terminal />} />
        <Route path="/send" element={<Send />} />
        <Route path="/receive" element={<Receive />} />
        <Route path="/history" element={<History />} />
        <Route path="/invoices" element={<Invoices />} />
        <Route path="/receipts" element={<Receipts />} />
        <Route path="/export" element={<Export />} />
        <Route path="/address-book" element={<AddressBook />} />
        <Route path="/coin-control" element={<CoinControl />} />
        <Route path="/psbt" element={<PSBTPage />} />
        <Route path="/sign-verify" element={<SignVerify />} />
        <Route path="/ghost-locks" element={<GhostLocks />} />
        <Route path="/create-lock" element={<CreateLock />} />
        <Route path="/withdraw" element={<WithdrawWizard />} />
        <Route path="/send-l2" element={<SendL2 />} />
        <Route path="/ghost-id" element={<GhostIdWizard />} />
        <Route path="/wraith" element={<WraithWash />} />
        <Route path="/glyph" element={<GlyphDesigner />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route
        path="*"
        element={
          <Navigate
            to={appState === "ready" ? "/dashboard" : "/setup"}
            replace
          />
        }
      />
    </Routes>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <ConnectionProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </ConnectionProvider>
    </ToastProvider>
  );
}

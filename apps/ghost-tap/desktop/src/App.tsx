import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { hasWallet } from "./api/commands";
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
import Settings from "./pages/Settings";

function AppRoutes() {
  const [walletExists, setWalletExists] = useState<boolean | null>(null);

  useEffect(() => {
    hasWallet().then(setWalletExists);
  }, []);

  if (walletExists === null) {
    return null; // loading
  }

  return (
    <Routes>
      <Route path="/setup" element={<WalletSetup />} />
      <Route element={<Layout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/terminal" element={<Terminal />} />
        <Route path="/send" element={<Send />} />
        <Route path="/receive" element={<Receive />} />
        <Route path="/history" element={<History />} />
        <Route path="/invoices" element={<Invoices />} />
        <Route path="/receipts" element={<Receipts />} />
        <Route path="/export" element={<Export />} />
        <Route path="/wraith" element={<WraithWash />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route
        path="*"
        element={<Navigate to={walletExists ? "/dashboard" : "/setup"} replace />}
      />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
}

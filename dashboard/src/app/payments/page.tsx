"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { getPayments } from "@/lib/api";
import type { Payment, PaymentStatus, PaymentType } from "@/types/api";

function getStatusBadgeVariant(status: PaymentStatus): "success" | "warning" | "error" | "default" {
  switch (status) {
    case "Confirmed":
      return "success";
    case "Pending":
      return "warning";
    case "Failed":
      return "error";
    default:
      return "default";
  }
}

function getTypeBadgeVariant(type: PaymentType): "success" | "error" {
  return type === "IN" ? "success" : "error";
}

function truncateId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 6)}...${id.slice(-6)}`;
}

function formatAmount(amount: number | null, type: PaymentType): string {
  if (amount === null) return "(hidden - ZK)";
  const btc = amount / 100_000_000;
  const prefix = type === "IN" ? "+" : "-";
  return `${prefix}${btc.toFixed(8)} BTC`;
}

function formatDate(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function PaymentsPage() {
  const [payments, setPayments] = useState<Payment[]>([]);
  const [total, setTotal] = useState(0);
  const [, setPendingCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "in" | "out" | "pending">("all");
  const [limit] = useState(50);
  const [offset, setOffset] = useState(0);

  const fetchData = useCallback(async () => {
    try {
      const data = await getPayments(limit, offset);
      setPayments(data.payments ?? []);
      setTotal(data.total ?? 0);
      setPendingCount(data.pending_count ?? 0);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
    } finally {
      setLoading(false);
    }
  }, [limit, offset]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const filteredPayments = payments.filter((p) => {
    if (filter === "all") return true;
    if (filter === "in") return p.type === "IN";
    if (filter === "out") return p.type === "OUT";
    if (filter === "pending") return p.status === "Pending";
    return true;
  });

  const pendingPayments = payments.filter((p) => p.status === "Pending");

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-100 mb-6">Payments</h1>
          <div className="animate-pulse space-y-6">
            <div className="h-24 bg-gray-800 rounded-lg"></div>
            <div className="h-64 bg-gray-800 rounded-lg"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-2xl font-bold text-gray-100 mb-6">Payments</h1>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-800 rounded-lg">
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {/* Info Banner */}
        <Card className="mb-6">
          <div className="flex items-center justify-between p-4 bg-orange-900/20 border border-orange-800 rounded-lg">
            <p className="text-orange-300 text-sm">
              To send or receive payments, use the Ghost Wallet app.
              This page shows payment history for your registered locks.
            </p>
            <button className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded text-sm whitespace-nowrap ml-4">
              Open Wallet
            </button>
          </div>
        </Card>

        {/* Pending Payments */}
        {pendingPayments.length > 0 && (
          <Card className="mb-6">
            <CardHeader
              title="Pending Payments"
              subtitle={`${pendingPayments.length} payments awaiting confirmation`}
            />
            <div className="space-y-3">
              {pendingPayments.map((payment) => (
                <div
                  key={payment.payment_id}
                  className="p-4 bg-yellow-900/20 border border-yellow-800 rounded-lg"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant={getTypeBadgeVariant(payment.type)}>
                          {payment.type}
                        </Badge>
                        <span className="font-mono text-gray-100">
                          {truncateId(payment.payment_id)}
                        </span>
                      </div>
                      <div className="text-sm text-gray-400">
                        {payment.type === "OUT" ? "To" : "From"}:{" "}
                        <span className="font-mono">{truncateId(payment.counterparty_id)}</span>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`font-mono ${payment.type === "IN" ? "text-green-400" : "text-red-400"}`}>
                        {formatAmount(payment.amount, payment.type)}
                      </div>
                      <div className="text-sm text-gray-500">
                        {formatDate(payment.timestamp)}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Payment History */}
        <Card>
          <CardHeader
            title="Payment History"
            action={
              <div className="flex gap-1">
                {(["all", "in", "out", "pending"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`px-3 py-1 rounded text-sm ${
                      filter === f
                        ? "bg-gray-700 text-white"
                        : "bg-gray-800 text-gray-400 hover:text-gray-200"
                    }`}
                  >
                    {f === "all" ? "All" : f === "in" ? "Received" : f === "out" ? "Sent" : "Pending"}
                  </button>
                ))}
              </div>
            }
          />

          {filteredPayments.length === 0 ? (
            <p className="text-gray-400">No payments found</p>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-gray-400 text-sm border-b border-gray-800">
                      <th className="pb-3 font-medium">Date</th>
                      <th className="pb-3 font-medium">Type</th>
                      <th className="pb-3 font-medium">Lock</th>
                      <th className="pb-3 font-medium">Counterparty</th>
                      <th className="pb-3 font-medium">Status</th>
                      <th className="pb-3 font-medium text-right">Amount</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {filteredPayments.map((payment) => (
                      <tr key={payment.payment_id} className="text-gray-100">
                        <td className="py-3 text-gray-400">
                          {formatDate(payment.timestamp)}
                        </td>
                        <td className="py-3">
                          <Badge variant={getTypeBadgeVariant(payment.type)}>
                            {payment.type}
                          </Badge>
                        </td>
                        <td className="py-3 font-mono text-sm">
                          {truncateId(payment.lock_id ?? "")}
                        </td>
                        <td className="py-3 font-mono text-sm">
                          {truncateId(payment.counterparty_id)}
                        </td>
                        <td className="py-3">
                          <Badge variant={getStatusBadgeVariant(payment.status ?? "pending")}>
                            {payment.status ?? "pending"}
                          </Badge>
                        </td>
                        <td className={`py-3 font-mono text-right ${
                          payment.type === "IN" ? "text-green-400" : "text-red-400"
                        }`}>
                          {formatAmount(payment.amount, payment.type)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="mt-4 flex items-center justify-between text-sm text-gray-400">
                <span>
                  Showing {filteredPayments.length} of {total} payments
                </span>
                {total > limit && (
                  <div className="flex gap-2">
                    <button
                      onClick={() => setOffset(Math.max(0, offset - limit))}
                      disabled={offset === 0}
                      className="px-3 py-1 bg-gray-800 rounded disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => setOffset(offset + limit)}
                      disabled={offset + limit >= total}
                      className="px-3 py-1 bg-gray-800 rounded disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}

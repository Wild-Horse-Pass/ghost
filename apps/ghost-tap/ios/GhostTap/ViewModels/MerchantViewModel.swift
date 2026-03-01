import Foundation
import Combine
import SwiftUI

// MARK: - Data Models

/// Wash status for a merchant transaction.
enum MerchantWashStatus: Equatable {
    case queued
    case inProgress
    case completed
    case failed

    var label: String {
        switch self {
        case .queued: return "Queued"
        case .inProgress: return "In Progress"
        case .completed: return "Completed"
        case .failed: return "Failed"
        }
    }

    var color: Color {
        switch self {
        case .queued: return .gray
        case .inProgress: return .blue
        case .completed: return .green
        case .failed: return .red
        }
    }
}

/// A merchant transaction for the UI layer.
struct MerchantTransaction: Identifiable {
    let id: String       // txId
    let txId: String
    let amount: UInt64
    let timestamp: UInt64
    let status: String
    let memo: String?
    var washStatus: MerchantWashStatus?

    var relativeTime: String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

/// Wash queue statistics.
struct WashStats {
    var queued: Int = 0
    var inProgress: Int = 0
    var completed: Int = 0
    var failed: Int = 0

    var totalCount: Int {
        queued + inProgress + completed + failed
    }
}

// MARK: - ViewModel

/// Observable view model for all merchant mode state.
@MainActor
final class MerchantViewModel: ObservableObject {

    // MARK: - Profile

    @Published var businessName: String = ""
    @Published var businessAddress: String = ""
    @Published var taxId: String? = nil
    @Published var ghostAddress: String = ""
    @Published var profileCreatedAt: UInt64 = 0

    // MARK: - Sales Aggregation

    @Published var dailyTotal: UInt64 = 0
    @Published var dailyCount: Int = 0
    @Published var weeklyTotal: UInt64 = 0
    @Published var weeklyCount: Int = 0
    @Published var monthlyTotal: UInt64 = 0
    @Published var monthlyCount: Int = 0

    // MARK: - Wash Queue

    @Published var washStats = WashStats()

    // MARK: - Transactions

    @Published var recentTransactions: [MerchantTransaction] = []

    // MARK: - Payment Terminal

    @Published var currentReceiveAddress: String = ""
    @Published var currentPaymentUri: String = ""

    // MARK: - Settings

    @Published var autoWashEnabled: Bool = false
    @Published var ringSize: Int = 12
    @Published var receiptAutoGenerate: Bool = true
    @Published var receiptShowLogo: Bool = true

    // MARK: - Error

    @Published var errorMessage: String?

    // MARK: - Internal Storage

    private var allTransactions: [MerchantTransaction] = []
    private var washQueue: [WashEntry] = []
    private var receipts: [String: String] = [:]  // id -> html
    private var invoices: [String: String] = [:]   // id -> html

    private struct WashEntry {
        let txId: String
        let amount: UInt64
        var status: MerchantWashStatus
        let createdAt: UInt64
    }

    // MARK: - Profile

    func updateProfile(
        businessName: String,
        businessAddress: String,
        taxId: String?,
        ghostAddress: String
    ) {
        self.businessName = businessName
        self.businessAddress = businessAddress
        self.taxId = taxId
        self.ghostAddress = ghostAddress
        if profileCreatedAt == 0 {
            profileCreatedAt = UInt64(Date().timeIntervalSince1970)
        }
    }

    // MARK: - Sales Aggregation

    func refreshSalesAggregation() {
        let now = UInt64(Date().timeIntervalSince1970)
        let dayAgo = now - 86400
        let weekAgo = now - 7 * 86400
        let monthAgo = now - 30 * 86400

        let daily = allTransactions.filter { $0.timestamp >= dayAgo }
        let weekly = allTransactions.filter { $0.timestamp >= weekAgo }
        let monthly = allTransactions.filter { $0.timestamp >= monthAgo }

        dailyTotal = daily.reduce(0) { $0 + $1.amount }
        dailyCount = daily.count
        weeklyTotal = weekly.reduce(0) { $0 + $1.amount }
        weeklyCount = weekly.count
        monthlyTotal = monthly.reduce(0) { $0 + $1.amount }
        monthlyCount = monthly.count

        recentTransactions = allTransactions
            .sorted { $0.timestamp > $1.timestamp }
            .prefix(20)
            .map { $0 }
    }

    // MARK: - Payment Terminal

    func preparePaymentRequest(amount: UInt64) {
        let addr = ghostAddress.isEmpty
            ? "GhGeneratedAddr\(Int(Date().timeIntervalSince1970))"
            : ghostAddress
        currentReceiveAddress = addr
        currentPaymentUri = "ghost:\(addr)?amount=\(amount)&label=\(businessName)"
    }

    func recordPayment(txId: String, amount: UInt64) {
        let tx = MerchantTransaction(
            id: txId,
            txId: txId,
            amount: amount,
            timestamp: UInt64(Date().timeIntervalSince1970),
            status: "confirmed",
            memo: nil,
            washStatus: nil
        )
        allTransactions.append(tx)

        if autoWashEnabled {
            queueWash(txId: txId, amount: amount)
        }

        refreshSalesAggregation()
        refreshWashStats()
    }

    // MARK: - Wraith Wash

    func queueWash(txId: String, amount: UInt64) {
        washQueue.append(WashEntry(
            txId: txId,
            amount: amount,
            status: .queued,
            createdAt: UInt64(Date().timeIntervalSince1970)
        ))

        // Update the transaction's wash status
        if let idx = allTransactions.firstIndex(where: { $0.txId == txId }) {
            allTransactions[idx].washStatus = .queued
        }

        refreshWashStats()
        refreshSalesAggregation()
    }

    private func refreshWashStats() {
        washStats = WashStats(
            queued: washQueue.filter { $0.status == .queued }.count,
            inProgress: washQueue.filter { $0.status == .inProgress }.count,
            completed: washQueue.filter { $0.status == .completed }.count,
            failed: washQueue.filter { $0.status == .failed }.count
        )
    }

    // MARK: - Receipts

    func generateReceipt(txId: String, amount: UInt64) {
        let receiptId = "R-\(UUID().uuidString.prefix(8).uppercased())"
        let now = UInt64(Date().timeIntervalSince1970)

        let html = buildReceiptHtml(
            receiptId: receiptId,
            businessName: businessName,
            businessAddress: businessAddress,
            amount: amount,
            txId: txId,
            timestamp: now
        )

        receipts[receiptId] = html
    }

    func getReceiptHtml(receiptId: String) -> String? {
        receipts[receiptId]
    }

    private func buildReceiptHtml(
        receiptId: String,
        businessName: String,
        businessAddress: String,
        amount: UInt64,
        txId: String,
        timestamp: UInt64
    ) -> String {
        let amountStr = WalletViewModel.formatBalance(amount)
        let dateStr = formatTimestamp(timestamp)

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Receipt \(escapeHtml(receiptId))</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                 background: #fafafa; color: #222; padding: 24px; }
          .receipt { max-width: 400px; margin: 0 auto; background: #fff;
                     border: 1px solid #ddd; border-radius: 8px; padding: 24px;
                     box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
          .header { text-align: center; margin-bottom: 20px;
                    border-bottom: 2px solid #6B4EE6; padding-bottom: 16px; }
          .header h1 { font-size: 20px; color: #6B4EE6; margin-bottom: 4px; }
          .header .address { font-size: 12px; color: #666; }
          .meta { font-size: 12px; color: #888; margin-bottom: 16px; }
          .meta div { margin-bottom: 4px; }
          .total { display: flex; justify-content: space-between; font-size: 18px;
                   font-weight: 700; padding: 12px 0; border-top: 2px solid #222; }
          .total .value { color: #6B4EE6; }
          .txid { font-size: 11px; color: #aaa; word-break: break-all;
                  margin-top: 16px; padding-top: 12px; border-top: 1px dashed #ddd; }
          .footer { text-align: center; font-size: 11px; color: #bbb; margin-top: 20px; }
        </style>
        </head>
        <body>
        <div class="receipt">
          <div class="header">
            <h1>\(escapeHtml(businessName))</h1>
            <div class="address">\(escapeHtml(businessAddress))</div>
          </div>
          <div class="meta">
            <div><strong>Receipt:</strong> \(escapeHtml(receiptId))</div>
            <div><strong>Date:</strong> \(dateStr)</div>
          </div>
          <div class="total">
            <span>Total</span>
            <span class="value">\(amountStr) GHOST</span>
          </div>
          <div class="txid"><strong>TxID:</strong> \(escapeHtml(txId))</div>
          <div class="footer">Powered by GhostTap</div>
        </div>
        </body>
        </html>
        """
    }

    // MARK: - Invoices

    func createInvoice(
        totalAmount: UInt64,
        dueDate: UInt64,
        lineItems: [(String, UInt64)],
        memo: String?
    ) -> String {
        let invoiceId = "INV-\(UUID().uuidString.prefix(8).uppercased())"

        let html = buildInvoiceHtml(
            invoiceId: invoiceId,
            businessName: businessName,
            businessAddress: businessAddress,
            ghostAddress: ghostAddress,
            totalAmount: totalAmount,
            dueDate: dueDate,
            lineItems: lineItems,
            memo: memo
        )

        invoices[invoiceId] = html
        return invoiceId
    }

    func getInvoiceHtml(invoiceId: String) -> String? {
        invoices[invoiceId]
    }

    private func buildInvoiceHtml(
        invoiceId: String,
        businessName: String,
        businessAddress: String,
        ghostAddress: String,
        totalAmount: UInt64,
        dueDate: UInt64,
        lineItems: [(String, UInt64)],
        memo: String?
    ) -> String {
        let itemsHtml = lineItems.map { desc, amt in
            "<tr><td>\(escapeHtml(desc))</td><td style=\"text-align:right\">\(WalletViewModel.formatBalance(amt)) GHOST</td></tr>"
        }.joined()

        let memoSection = memo.map { m in
            "<div style=\"font-size:13px;color:#555;margin-bottom:12px;padding:10px;background:#f9f9f9;border-radius:4px;\"><strong>Notes:</strong> \(escapeHtml(m))</div>"
        } ?? ""

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Invoice \(escapeHtml(invoiceId))</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, sans-serif; background: #fafafa;
                 color: #222; padding: 24px; }
          .invoice { max-width: 600px; margin: 0 auto; background: #fff;
                     border: 1px solid #ddd; border-radius: 8px; padding: 32px; }
          .header { border-bottom: 2px solid #6B4EE6; padding-bottom: 16px;
                    margin-bottom: 20px; }
          .header h1 { font-size: 22px; color: #6B4EE6; }
          .header .addr { font-size: 12px; color: #666; margin-top: 4px; }
          .meta { font-size: 13px; color: #555; margin-bottom: 16px; }
          table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
          th { text-align: left; font-size: 11px; color: #999;
               text-transform: uppercase; border-bottom: 1px solid #eee; padding: 8px 0; }
          td { padding: 10px 0; border-bottom: 1px solid #f5f5f5; font-size: 14px; }
          .total { display: flex; justify-content: space-between; font-size: 20px;
                   font-weight: 700; padding: 14px 0; border-top: 2px solid #222; }
          .total .value { color: #6B4EE6; }
          .pay-to { font-size: 12px; color: #888; word-break: break-all;
                    margin-top: 20px; padding-top: 16px; border-top: 1px dashed #ddd; }
          .footer { text-align: center; font-size: 11px; color: #bbb; margin-top: 24px; }
        </style>
        </head>
        <body>
        <div class="invoice">
          <div class="header">
            <h1>\(escapeHtml(businessName))</h1>
            <div class="addr">\(escapeHtml(businessAddress))</div>
          </div>
          <div class="meta">
            <strong>Invoice:</strong> \(escapeHtml(invoiceId))<br>
            <strong>Due Date:</strong> \(formatDate(dueDate))
          </div>
          \(memoSection)
          <table>
            <thead><tr><th>Description</th><th style="text-align:right">Amount</th></tr></thead>
            <tbody>\(itemsHtml)</tbody>
          </table>
          <div class="total">
            <span>Amount Due</span>
            <span class="value">\(WalletViewModel.formatBalance(totalAmount)) GHOST</span>
          </div>
          <div class="pay-to"><strong>Pay to:</strong> \(escapeHtml(ghostAddress))</div>
          <div class="footer">Powered by GhostTap</div>
        </div>
        </body>
        </html>
        """
    }

    // MARK: - Export

    func getTransactionCountInRange(from: UInt64, to: UInt64) -> Int {
        allTransactions.filter { $0.timestamp >= from && $0.timestamp < to }.count
    }

    func exportCsv(from: UInt64, to: UInt64) -> String {
        let filtered = allTransactions.filter { $0.timestamp >= from && $0.timestamp < to }
        var csv = "Date,TxID,Direction,Amount,Fee,Address,Status,Memo\n"

        for tx in filtered {
            csv += "\(formatTimestamp(tx.timestamp)),\(tx.txId),Received,"
            csv += "\(WalletViewModel.formatBalance(tx.amount)),,,"
            csv += "\(tx.status),\(tx.memo ?? "")\n"
        }

        return csv
    }

    func exportHtmlReport(from: UInt64, to: UInt64) -> String {
        let filtered = allTransactions
            .filter { $0.timestamp >= from && $0.timestamp < to }
            .sorted { $0.timestamp > $1.timestamp }

        let totalReceived = filtered.reduce(UInt64(0)) { $0 + $1.amount }

        let rowsHtml = filtered.map { tx in
            """
            <tr>
              <td>\(formatTimestamp(tx.timestamp))</td>
              <td style="font-family:monospace;font-size:10px">\(String(tx.txId.prefix(16)))...</td>
              <td style="color:#28a745;font-weight:600">Received</td>
              <td style="text-align:right">\(WalletViewModel.formatBalance(tx.amount))</td>
              <td>\(tx.status)</td>
              <td>\(tx.memo ?? "-")</td>
            </tr>
            """
        }.joined()

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Transaction Report - \(escapeHtml(businessName))</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, sans-serif; padding: 24px; font-size: 12px; }
          .header { border-bottom: 3px solid #6B4EE6; padding-bottom: 16px; margin-bottom: 24px; }
          .header h1 { font-size: 24px; color: #6B4EE6; }
          .summary { display: flex; gap: 16px; margin-bottom: 24px; }
          .summary-card { background: #f7f7f7; border-radius: 8px; padding: 16px;
                          text-align: center; flex: 1; }
          .summary-card .label { font-size: 11px; color: #888; text-transform: uppercase; }
          .summary-card .value { font-size: 18px; font-weight: 700; margin-top: 4px; }
          table { width: 100%; border-collapse: collapse; }
          th { text-align: left; font-size: 10px; color: #999; text-transform: uppercase;
               border-bottom: 2px solid #eee; padding: 8px 4px; }
          td { padding: 8px 4px; border-bottom: 1px solid #f0f0f0; }
          .footer { text-align: center; font-size: 10px; color: #ccc; margin-top: 32px; }
        </style>
        </head>
        <body>
        <div class="header">
          <h1>\(escapeHtml(businessName))</h1>
          <div style="color:#666;margin-top:4px">Transaction Report &mdash; \(formatDate(from)) to \(formatDate(to))</div>
        </div>
        <div class="summary">
          <div class="summary-card"><div class="label">Transactions</div><div class="value">\(filtered.count)</div></div>
          <div class="summary-card"><div class="label">Total Received</div><div class="value" style="color:#28a745">\(WalletViewModel.formatBalance(totalReceived)) GHOST</div></div>
        </div>
        <table>
          <thead><tr><th>Date</th><th>TxID</th><th>Direction</th><th style="text-align:right">Amount</th><th>Status</th><th>Memo</th></tr></thead>
          <tbody>\(rowsHtml)</tbody>
        </table>
        <div class="footer">Generated by GhostTap</div>
        </body>
        </html>
        """
    }

    // MARK: - Settings

    func setAutoWash(_ enabled: Bool) {
        autoWashEnabled = enabled
    }

    func setRingSize(_ size: Int) {
        ringSize = min(max(size, 3), 32)
    }

    func setReceiptAutoGenerate(_ enabled: Bool) {
        receiptAutoGenerate = enabled
    }

    func setReceiptShowLogo(_ enabled: Bool) {
        receiptShowLogo = enabled
    }

    // MARK: - Formatting

    private func formatTimestamp(_ ts: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ts))
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }

    private func formatDate(_ ts: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ts))
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }

    private func escapeHtml(_ input: String) -> String {
        input
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}

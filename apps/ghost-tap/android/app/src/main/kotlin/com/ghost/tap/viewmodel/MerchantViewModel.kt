package com.ghost.tap.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID

// ---------------------------------------------------------------------------
// Data models for the merchant UI layer
// ---------------------------------------------------------------------------

enum class WashStatus(val label: String) {
    Queued("Queued"),
    InProgress("In Progress"),
    Completed("Completed"),
    Failed("Failed")
}

data class MerchantTransaction(
    val txId: String,
    val amount: Long,
    val timestamp: Long,
    val status: String,
    val memo: String? = null,
    val washStatus: WashStatus? = null
)

data class MerchantUiState(
    // Profile
    val businessName: String = "",
    val businessAddress: String = "",
    val taxId: String = "",
    val ghostAddress: String = "",
    val profileCreatedAt: Long = 0,

    // Sales aggregation
    val dailyTotal: Long = 0,
    val dailyCount: Int = 0,
    val weeklyTotal: Long = 0,
    val weeklyCount: Int = 0,
    val monthlyTotal: Long = 0,
    val monthlyCount: Int = 0,

    // Wash queue
    val washQueuedCount: Int = 0,
    val washInProgressCount: Int = 0,
    val washCompletedCount: Int = 0,
    val washFailedCount: Int = 0,

    // Recent transactions
    val recentTransactions: List<MerchantTransaction> = emptyList(),

    // Payment terminal
    val currentReceiveAddress: String = "",
    val currentPaymentUri: String = "",

    // Settings
    val autoWashEnabled: Boolean = false,
    val ringSize: Int = 12,
    val receiptAutoGenerate: Boolean = true,
    val receiptShowLogo: Boolean = true,

    // Receipts & invoices store (id -> html)
    val receipts: Map<String, String> = emptyMap(),
    val invoices: Map<String, String> = emptyMap(),

    // Errors
    val error: String? = null
)

// ---------------------------------------------------------------------------
// ViewModel
// ---------------------------------------------------------------------------

class MerchantViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(MerchantUiState())
    val uiState: StateFlow<MerchantUiState> = _uiState.asStateFlow()

    // In-memory transaction store for export/aggregation.
    private val allTransactions = mutableListOf<MerchantTransaction>()

    // ------------------------------------------------------------------
    // Profile
    // ------------------------------------------------------------------

    fun updateProfile(
        businessName: String,
        businessAddress: String,
        taxId: String?,
        ghostAddress: String
    ) {
        _uiState.update {
            it.copy(
                businessName = businessName,
                businessAddress = businessAddress,
                taxId = taxId ?: "",
                ghostAddress = ghostAddress,
                profileCreatedAt = if (it.profileCreatedAt == 0L) {
                    System.currentTimeMillis() / 1000
                } else {
                    it.profileCreatedAt
                }
            )
        }
    }

    // ------------------------------------------------------------------
    // Sales aggregation
    // ------------------------------------------------------------------

    fun refreshSalesAggregation() {
        val now = System.currentTimeMillis() / 1000
        val dayAgo = now - 86400
        val weekAgo = now - 7 * 86400
        val monthAgo = now - 30 * 86400

        val daily = allTransactions.filter { it.timestamp >= dayAgo }
        val weekly = allTransactions.filter { it.timestamp >= weekAgo }
        val monthly = allTransactions.filter { it.timestamp >= monthAgo }

        _uiState.update {
            it.copy(
                dailyTotal = daily.sumOf { tx -> tx.amount },
                dailyCount = daily.size,
                weeklyTotal = weekly.sumOf { tx -> tx.amount },
                weeklyCount = weekly.size,
                monthlyTotal = monthly.sumOf { tx -> tx.amount },
                monthlyCount = monthly.size,
                recentTransactions = allTransactions
                    .sortedByDescending { tx -> tx.timestamp }
                    .take(20)
            )
        }
    }

    fun addTransaction(tx: MerchantTransaction) {
        allTransactions.add(tx)

        // Auto-wash if enabled
        if (_uiState.value.autoWashEnabled) {
            queueWash(tx.txId, tx.amount)
        }

        refreshSalesAggregation()
        refreshWashStats()
    }

    // ------------------------------------------------------------------
    // Payment terminal
    // ------------------------------------------------------------------

    fun preparePaymentRequest(amountSatoshis: Long) {
        // In production, this would call into Rust core to generate
        // a receive address and build a ghost: payment URI.
        val address = _uiState.value.ghostAddress.ifEmpty { "GhGeneratedAddr${System.nanoTime()}" }
        val uri = "ghost:$address?amount=$amountSatoshis&label=${_uiState.value.businessName}"

        _uiState.update {
            it.copy(
                currentReceiveAddress = address,
                currentPaymentUri = uri
            )
        }
    }

    // ------------------------------------------------------------------
    // Wraith wash
    // ------------------------------------------------------------------

    private val washQueue = mutableListOf<WashQueueEntry>()

    private data class WashQueueEntry(
        val txId: String,
        val amount: Long,
        var status: WashStatus,
        val createdAt: Long = System.currentTimeMillis() / 1000
    )

    fun queueWash(txId: String, amount: Long) {
        washQueue.add(WashQueueEntry(txId, amount, WashStatus.Queued))

        // Update the transaction's wash status
        val idx = allTransactions.indexOfFirst { it.txId == txId }
        if (idx >= 0) {
            allTransactions[idx] = allTransactions[idx].copy(washStatus = WashStatus.Queued)
        }

        refreshWashStats()
        refreshSalesAggregation()
    }

    private fun refreshWashStats() {
        _uiState.update {
            it.copy(
                washQueuedCount = washQueue.count { e -> e.status == WashStatus.Queued },
                washInProgressCount = washQueue.count { e -> e.status == WashStatus.InProgress },
                washCompletedCount = washQueue.count { e -> e.status == WashStatus.Completed },
                washFailedCount = washQueue.count { e -> e.status == WashStatus.Failed }
            )
        }
    }

    // ------------------------------------------------------------------
    // Receipts
    // ------------------------------------------------------------------

    fun generateReceipt(txId: String, amount: Long): String {
        val state = _uiState.value
        val receiptId = "R-${UUID.randomUUID().toString().take(8).uppercase()}"
        val now = System.currentTimeMillis() / 1000

        // Build receipt HTML (mirrors Rust Receipt::to_html output)
        val html = buildReceiptHtml(
            receiptId = receiptId,
            businessName = state.businessName,
            businessAddress = state.businessAddress,
            amount = amount,
            txId = txId,
            timestamp = now
        )

        _uiState.update { it.copy(receipts = it.receipts + (receiptId to html)) }
        return receiptId
    }

    fun getReceiptHtml(receiptId: String): String {
        return _uiState.value.receipts[receiptId] ?: ""
    }

    private fun buildReceiptHtml(
        receiptId: String,
        businessName: String,
        businessAddress: String,
        amount: Long,
        txId: String,
        timestamp: Long
    ): String {
        val amountStr = formatGhost(amount)
        val dateStr = formatTimestamp(timestamp)

        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Receipt $receiptId</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #fafafa; color: #222; padding: 24px; }
  .receipt { max-width: 400px; margin: 0 auto; background: #fff;
             border: 1px solid #ddd; border-radius: 8px; padding: 24px;
             box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .header { text-align: center; margin-bottom: 20px; border-bottom: 2px solid #6B4EE6;
            padding-bottom: 16px; }
  .header h1 { font-size: 20px; color: #6B4EE6; margin-bottom: 4px; }
  .header .address { font-size: 12px; color: #666; }
  .meta { font-size: 12px; color: #888; margin-bottom: 16px; }
  .meta div { margin-bottom: 4px; }
  .total { display: flex; justify-content: space-between; font-size: 18px;
           font-weight: 700; padding: 12px 0; border-top: 2px solid #222; }
  .total .value { color: #6B4EE6; }
  .txid { font-size: 11px; color: #aaa; word-break: break-all; margin-top: 16px;
          padding-top: 12px; border-top: 1px dashed #ddd; }
  .footer { text-align: center; font-size: 11px; color: #bbb; margin-top: 20px; }
</style>
</head>
<body>
<div class="receipt">
  <div class="header">
    <h1>${escapeHtml(businessName)}</h1>
    <div class="address">${escapeHtml(businessAddress)}</div>
  </div>
  <div class="meta">
    <div><strong>Receipt:</strong> $receiptId</div>
    <div><strong>Date:</strong> $dateStr</div>
  </div>
  <div class="total">
    <span>Total</span>
    <span class="value">$amountStr GHOST</span>
  </div>
  <div class="txid"><strong>TxID:</strong> $txId</div>
  <div class="footer">Powered by GhostTap</div>
</div>
</body>
</html>
        """.trimIndent()
    }

    // ------------------------------------------------------------------
    // Invoices
    // ------------------------------------------------------------------

    fun createInvoice(
        totalAmount: Long,
        dueDate: Long,
        lineItems: List<Pair<String, Long>>,
        memo: String?
    ): String {
        val state = _uiState.value
        val invoiceId = "INV-${UUID.randomUUID().toString().take(8).uppercase()}"

        val html = buildInvoiceHtml(
            invoiceId = invoiceId,
            businessName = state.businessName,
            businessAddress = state.businessAddress,
            ghostAddress = state.ghostAddress,
            totalAmount = totalAmount,
            dueDate = dueDate,
            lineItems = lineItems,
            memo = memo
        )

        _uiState.update { it.copy(invoices = it.invoices + (invoiceId to html)) }
        return invoiceId
    }

    fun getInvoiceHtml(invoiceId: String): String {
        return _uiState.value.invoices[invoiceId] ?: ""
    }

    private fun buildInvoiceHtml(
        invoiceId: String,
        businessName: String,
        businessAddress: String,
        ghostAddress: String,
        totalAmount: Long,
        dueDate: Long,
        lineItems: List<Pair<String, Long>>,
        memo: String?
    ): String {
        val itemsHtml = lineItems.joinToString("") { (desc, amt) ->
            "<tr><td>${escapeHtml(desc)}</td><td style=\"text-align:right\">${formatGhost(amt)} GHOST</td></tr>"
        }
        val memoSection = if (memo != null) {
            "<div style=\"font-size:13px;color:#555;margin-bottom:12px;padding:10px;background:#f9f9f9;border-radius:4px;\"><strong>Notes:</strong> ${escapeHtml(memo)}</div>"
        } else ""

        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Invoice $invoiceId</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #fafafa; color: #222; padding: 24px; }
  .invoice { max-width: 600px; margin: 0 auto; background: #fff;
             border: 1px solid #ddd; border-radius: 8px; padding: 32px;
             box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .header { border-bottom: 2px solid #6B4EE6; padding-bottom: 16px; margin-bottom: 20px; }
  .header h1 { font-size: 22px; color: #6B4EE6; }
  .header .addr { font-size: 12px; color: #666; margin-top: 4px; }
  .meta { font-size: 13px; color: #555; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
  th { text-align: left; font-size: 11px; color: #999; text-transform: uppercase;
       border-bottom: 1px solid #eee; padding: 8px 0; }
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
    <h1>${escapeHtml(businessName)}</h1>
    <div class="addr">${escapeHtml(businessAddress)}</div>
  </div>
  <div class="meta">
    <strong>Invoice:</strong> $invoiceId<br>
    <strong>Due Date:</strong> ${formatDate(dueDate)}
  </div>
  $memoSection
  <table>
    <thead><tr><th>Description</th><th style="text-align:right">Amount</th></tr></thead>
    <tbody>$itemsHtml</tbody>
  </table>
  <div class="total">
    <span>Amount Due</span>
    <span class="value">${formatGhost(totalAmount)} GHOST</span>
  </div>
  <div class="pay-to"><strong>Pay to:</strong> $ghostAddress</div>
  <div class="footer">Powered by GhostTap</div>
</div>
</body>
</html>
        """.trimIndent()
    }

    // ------------------------------------------------------------------
    // Export
    // ------------------------------------------------------------------

    fun getTransactionCountInRange(from: Long, to: Long): Int {
        return allTransactions.count { it.timestamp in from until to }
    }

    fun exportCsv(from: Long, to: Long): String {
        val filtered = allTransactions.filter { it.timestamp in from until to }
        val sb = StringBuilder("Date,TxID,Direction,Amount,Fee,Address,Status,Memo\n")
        for (tx in filtered) {
            sb.append("${formatTimestamp(tx.timestamp)},")
            sb.append("${tx.txId},")
            sb.append("Received,") // Merchant mode is receive-only for sales
            sb.append("${formatGhost(tx.amount)},")
            sb.append(",") // Fee not tracked in merchant mode
            sb.append(",") // Address
            sb.append("${tx.status},")
            sb.append("${tx.memo ?: ""}\n")
        }
        return sb.toString()
    }

    fun exportHtmlReport(from: Long, to: Long): String {
        val state = _uiState.value
        val filtered = allTransactions
            .filter { it.timestamp in from until to }
            .sortedByDescending { it.timestamp }

        val totalReceived = filtered.sumOf { it.amount }
        val rowsHtml = filtered.joinToString("") { tx ->
            """
            <tr>
              <td>${formatTimestamp(tx.timestamp)}</td>
              <td style="font-family:monospace;font-size:10px">${tx.txId.take(16)}...</td>
              <td style="color:#28a745;font-weight:600">Received</td>
              <td style="text-align:right">${formatGhost(tx.amount)}</td>
              <td>${tx.status}</td>
              <td>${tx.memo ?: "-"}</td>
            </tr>
            """.trimIndent()
        }

        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Transaction Report - ${escapeHtml(state.businessName)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; padding: 24px; font-size: 12px; }
  .header { border-bottom: 3px solid #6B4EE6; padding-bottom: 16px; margin-bottom: 24px; }
  .header h1 { font-size: 24px; color: #6B4EE6; }
  .summary { display: flex; gap: 16px; margin-bottom: 24px; }
  .summary-card { background: #f7f7f7; border-radius: 8px; padding: 16px; text-align: center; flex: 1; }
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
  <h1>${escapeHtml(state.businessName)}</h1>
  <div style="color:#666;margin-top:4px">Transaction Report &mdash; ${formatDate(from)} to ${formatDate(to)}</div>
</div>
<div class="summary">
  <div class="summary-card"><div class="label">Transactions</div><div class="value">${filtered.size}</div></div>
  <div class="summary-card"><div class="label">Total Received</div><div class="value" style="color:#28a745">${formatGhost(totalReceived)} GHOST</div></div>
</div>
<table>
  <thead><tr><th>Date</th><th>TxID</th><th>Direction</th><th style="text-align:right">Amount</th><th>Status</th><th>Memo</th></tr></thead>
  <tbody>$rowsHtml</tbody>
</table>
<div class="footer">Generated by GhostTap</div>
</body>
</html>
        """.trimIndent()
    }

    // ------------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------------

    fun setAutoWash(enabled: Boolean) {
        _uiState.update { it.copy(autoWashEnabled = enabled) }
    }

    fun setRingSize(size: Int) {
        _uiState.update { it.copy(ringSize = size.coerceIn(3, 32)) }
    }

    fun setReceiptAutoGenerate(enabled: Boolean) {
        _uiState.update { it.copy(receiptAutoGenerate = enabled) }
    }

    fun setReceiptShowLogo(enabled: Boolean) {
        _uiState.update { it.copy(receiptShowLogo = enabled) }
    }

    // ------------------------------------------------------------------
    // Formatting helpers
    // ------------------------------------------------------------------

    private fun formatGhost(satoshis: Long): String {
        val whole = satoshis / 100_000_000
        val frac = satoshis % 100_000_000
        return "$whole.${"%08d".format(frac)}"
    }

    private fun formatTimestamp(ts: Long): String {
        val date = java.util.Date(ts * 1000)
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault())
        return fmt.format(date)
    }

    private fun formatDate(ts: Long): String {
        val date = java.util.Date(ts * 1000)
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.getDefault())
        return fmt.format(date)
    }

    private fun escapeHtml(input: String): String {
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;")
    }
}

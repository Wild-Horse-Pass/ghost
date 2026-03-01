//! Transaction export for merchant accounting
//!
//! Exports wallet transaction history as CSV or an HTML report
//! suitable for conversion to PDF.

use super::util::{csv_escape, days_to_ymd, format_ghost_amount, html_escape};
use crate::wallet::{HistoryEntry, TxDirection, TxStatus};

/// Transaction exporter with date-range filtering.
pub struct TransactionExporter;

impl TransactionExporter {
    /// Create a new exporter.
    pub fn new() -> Self {
        Self
    }

    /// Filter entries by the half-open time range `[from, to)`.
    fn filter_range(
        entries: &[HistoryEntry],
        from: u64,
        to: u64,
    ) -> Vec<&HistoryEntry> {
        entries
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp < to)
            .collect()
    }

    /// Format a unix timestamp as an ISO-8601 date string.
    fn format_date(ts: u64) -> String {
        let days = ts / 86400;
        let time_of_day = ts % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;
        let (year, month, day) = days_to_ymd(days);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            year, month, day, hours, minutes, seconds
        )
    }

    /// Format the direction as a human-readable string.
    fn format_direction(dir: TxDirection) -> &'static str {
        match dir {
            TxDirection::Incoming => "Received",
            TxDirection::Outgoing => "Sent",
        }
    }

    /// Format the status as a human-readable string.
    fn format_status(status: &TxStatus) -> String {
        match status {
            TxStatus::Pending => "Pending".to_string(),
            TxStatus::Confirmed(n) => format!("Confirmed ({})", n),
            TxStatus::Failed => "Failed".to_string(),
        }
    }

    /// Export transactions to CSV format.
    ///
    /// Filters to the time range `[from, to)` and produces columns:
    /// Date, TxID, Direction, Amount, Fee, Address, Status, Memo
    ///
    /// Returns the complete CSV file content as a String (including header row).
    pub fn to_csv(entries: &[HistoryEntry], from: u64, to: u64) -> String {
        let filtered = Self::filter_range(entries, from, to);

        let mut csv = String::from("Date,TxID,Direction,Amount,Fee,Address,Status,Memo\n");

        for entry in &filtered {
            let fee_str = match entry.fee {
                Some(f) => format_ghost_amount(f),
                None => String::new(),
            };
            let memo_str = entry
                .memo
                .as_deref()
                .map(csv_escape)
                .unwrap_or_default();

            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                Self::format_date(entry.timestamp),
                &entry.txid,
                Self::format_direction(entry.direction),
                format_ghost_amount(entry.amount),
                fee_str,
                csv_escape(&entry.address),
                Self::format_status(&entry.status),
                memo_str,
            ));
        }

        csv
    }

    /// Export transactions to an HTML report suitable for PDF rendering.
    ///
    /// Filters to the time range `[from, to)` and produces a styled
    /// HTML document with a summary header and transaction table.
    pub fn to_html_report(
        entries: &[HistoryEntry],
        from: u64,
        to: u64,
        business_name: &str,
    ) -> String {
        let filtered = Self::filter_range(entries, from, to);

        // Compute summary
        let total_incoming: u64 = filtered
            .iter()
            .filter(|e| e.direction == TxDirection::Incoming)
            .map(|e| e.amount)
            .sum();
        let total_outgoing: u64 = filtered
            .iter()
            .filter(|e| e.direction == TxDirection::Outgoing)
            .map(|e| e.amount)
            .sum();
        let total_fees: u64 = filtered
            .iter()
            .filter_map(|e| e.fee)
            .sum();
        let tx_count = filtered.len();

        // Build table rows
        let mut rows_html = String::new();
        for entry in &filtered {
            let fee_str = match entry.fee {
                Some(f) => format_ghost_amount(f),
                None => "-".to_string(),
            };
            let memo_str = entry.memo.as_deref().unwrap_or("-");
            let direction_class = match entry.direction {
                TxDirection::Incoming => "dir-in",
                TxDirection::Outgoing => "dir-out",
            };

            rows_html.push_str(&format!(
                r#"<tr>
  <td>{date}</td>
  <td class="txid">{txid}</td>
  <td class="{dir_class}">{direction}</td>
  <td class="amt">{amount}</td>
  <td class="amt">{fee}</td>
  <td class="addr">{address}</td>
  <td>{status}</td>
  <td>{memo}</td>
</tr>"#,
                date = Self::format_date(entry.timestamp),
                txid = html_escape(&entry.txid),
                dir_class = direction_class,
                direction = Self::format_direction(entry.direction),
                amount = format_ghost_amount(entry.amount),
                fee = fee_str,
                address = html_escape(&entry.address),
                status = Self::format_status(&entry.status),
                memo = html_escape(memo_str),
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Transaction Report - {business_name}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #fff; color: #222; padding: 24px; font-size: 12px; }}
  .report {{ max-width: 900px; margin: 0 auto; }}
  .header {{ border-bottom: 3px solid #6B4EE6; padding-bottom: 16px; margin-bottom: 24px; }}
  .header h1 {{ font-size: 24px; color: #6B4EE6; }}
  .header .subtitle {{ font-size: 14px; color: #666; margin-top: 4px; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
              margin-bottom: 24px; }}
  .summary-card {{ background: #f7f7f7; border-radius: 8px; padding: 16px; text-align: center; }}
  .summary-card .label {{ font-size: 11px; color: #888; text-transform: uppercase;
                          letter-spacing: 0.5px; }}
  .summary-card .value {{ font-size: 18px; font-weight: 700; margin-top: 4px; }}
  .summary-card .value.incoming {{ color: #28a745; }}
  .summary-card .value.outgoing {{ color: #dc3545; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; font-size: 10px; color: #999; text-transform: uppercase;
       letter-spacing: 0.5px; border-bottom: 2px solid #eee; padding: 8px 6px; }}
  td {{ padding: 8px 6px; border-bottom: 1px solid #f0f0f0; font-size: 12px; }}
  .txid {{ font-family: monospace; font-size: 10px; max-width: 100px;
           overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .addr {{ font-family: monospace; font-size: 10px; max-width: 120px;
           overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .amt {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .dir-in {{ color: #28a745; font-weight: 600; }}
  .dir-out {{ color: #dc3545; font-weight: 600; }}
  .footer {{ text-align: center; font-size: 10px; color: #ccc; margin-top: 32px;
             padding-top: 12px; border-top: 1px solid #eee; }}
</style>
</head>
<body>
<div class="report">
  <div class="header">
    <h1>{business_name}</h1>
    <div class="subtitle">Transaction Report &mdash; {from_date} to {to_date}</div>
  </div>

  <div class="summary">
    <div class="summary-card">
      <div class="label">Transactions</div>
      <div class="value">{tx_count}</div>
    </div>
    <div class="summary-card">
      <div class="label">Total Received</div>
      <div class="value incoming">{total_in} GHOST</div>
    </div>
    <div class="summary-card">
      <div class="label">Total Sent</div>
      <div class="value outgoing">{total_out} GHOST</div>
    </div>
    <div class="summary-card">
      <div class="label">Total Fees</div>
      <div class="value">{total_fees} GHOST</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Date</th><th>TxID</th><th>Direction</th><th style="text-align:right">Amount</th>
        <th style="text-align:right">Fee</th><th>Address</th><th>Status</th><th>Memo</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <div class="footer">Generated by GhostTap</div>
</div>
</body>
</html>"#,
            business_name = html_escape(business_name),
            from_date = Self::format_date(from),
            to_date = Self::format_date(to),
            tx_count = tx_count,
            total_in = format_ghost_amount(total_incoming),
            total_out = format_ghost_amount(total_outgoing),
            total_fees = format_ghost_amount(total_fees),
            rows = rows_html,
        )
    }
}

impl Default for TransactionExporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<HistoryEntry> {
        vec![
            HistoryEntry {
                txid: "tx_aaa".to_string(),
                direction: TxDirection::Incoming,
                amount: 100_000_000,
                fee: None,
                address: "GhAddr1".to_string(),
                status: TxStatus::Confirmed(10),
                timestamp: 1000,
                memo: Some("Payment for coffee".to_string()),
            },
            HistoryEntry {
                txid: "tx_bbb".to_string(),
                direction: TxDirection::Outgoing,
                amount: 50_000_000,
                fee: Some(1_000),
                address: "GhAddr2".to_string(),
                status: TxStatus::Confirmed(5),
                timestamp: 2000,
                memo: None,
            },
            HistoryEntry {
                txid: "tx_ccc".to_string(),
                direction: TxDirection::Incoming,
                amount: 200_000_000,
                fee: None,
                address: "GhAddr3".to_string(),
                status: TxStatus::Pending,
                timestamp: 5000, // outside range [0, 3000)
                memo: None,
            },
        ]
    }

    #[test]
    fn test_csv_export_with_range() {
        let entries = sample_entries();
        let csv = TransactionExporter::to_csv(&entries, 0, 3000);

        // Header
        assert!(csv.starts_with("Date,TxID,Direction,Amount,Fee,Address,Status,Memo\n"));
        // Should include tx_aaa and tx_bbb but NOT tx_ccc
        assert!(csv.contains("tx_aaa"));
        assert!(csv.contains("tx_bbb"));
        assert!(!csv.contains("tx_ccc"));
        // Check direction labels
        assert!(csv.contains("Received"));
        assert!(csv.contains("Sent"));
    }

    #[test]
    fn test_csv_export_empty_range() {
        let entries = sample_entries();
        let csv = TransactionExporter::to_csv(&entries, 9000, 10000);
        // Should only have the header
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_html_report() {
        let entries = sample_entries();
        let html =
            TransactionExporter::to_html_report(&entries, 0, 3000, "Ghost Cafe");

        assert!(html.contains("Ghost Cafe"));
        assert!(html.contains("tx_aaa"));
        assert!(html.contains("tx_bbb"));
        assert!(!html.contains("tx_ccc"));
        assert!(html.contains("1.00000000 GHOST")); // total received
        assert!(html.contains("0.50000000 GHOST")); // total sent
        assert!(html.contains("<!DOCTYPE html>"));
    }

}

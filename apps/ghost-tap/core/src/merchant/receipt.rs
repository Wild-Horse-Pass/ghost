//! Receipt generation for merchant transactions
//!
//! Produces styled HTML receipts suitable for rendering in a WebView
//! or conversion to PDF via a print/share dialog.

use super::util::{days_to_ymd, format_ghost_amount, html_escape};
use serde::{Deserialize, Serialize};

/// A single line item on a receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineItem {
    /// Description of the item or service.
    pub description: String,
    /// Amount in the smallest currency unit (satoshis).
    pub amount: u64,
}

impl LineItem {
    pub fn new(description: impl Into<String>, amount: u64) -> Self {
        Self {
            description: description.into(),
            amount,
        }
    }
}

/// A payment receipt issued by a merchant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Unique receipt identifier (typically a UUID or sequential number).
    pub receipt_id: String,
    /// Business name from the merchant profile.
    pub business_name: String,
    /// Business address from the merchant profile.
    pub business_address: String,
    /// Total payment amount in satoshis.
    pub amount: u64,
    /// Transaction ID on the Ghost blockchain.
    pub txid: String,
    /// Unix timestamp of the payment.
    pub timestamp: u64,
    /// Optional memo / note for the transaction.
    pub memo: Option<String>,
    /// Individual line items that make up the total.
    pub items: Vec<LineItem>,
}

impl Receipt {
    /// Create a new receipt.
    pub fn new(
        receipt_id: impl Into<String>,
        business_name: impl Into<String>,
        business_address: impl Into<String>,
        amount: u64,
        txid: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            business_name: business_name.into(),
            business_address: business_address.into(),
            amount,
            txid: txid.into(),
            timestamp,
            memo: None,
            items: Vec::new(),
        }
    }

    /// Add a line item.
    pub fn add_item(&mut self, item: LineItem) {
        self.items.push(item);
    }

    /// Builder-style setter for memo.
    pub fn with_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }

    /// Format a unix timestamp as a human-readable date/time string.
    fn format_timestamp(ts: u64) -> String {
        let secs_per_day = 86400u64;
        let days_since_epoch = ts / secs_per_day;
        let time_of_day = ts % secs_per_day;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;
        let (year, month, day) = days_to_ymd(days_since_epoch);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            year, month, day, hours, minutes, seconds
        )
    }

    /// Render the receipt as styled HTML.
    ///
    /// The output is a self-contained HTML document with inline CSS,
    /// ready for display in a WebView or conversion to PDF.
    pub fn to_html(&self) -> String {
        let mut items_html = String::new();
        for item in &self.items {
            items_html.push_str(&format!(
                r#"<tr><td class="item-desc">{}</td><td class="item-amt">{} GHOST</td></tr>"#,
                html_escape(&item.description),
                format_ghost_amount(item.amount),
            ));
        }

        let memo_section = match &self.memo {
            Some(m) => format!(
                r#"<div class="memo"><strong>Memo:</strong> {}</div>"#,
                html_escape(m)
            ),
            None => String::new(),
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Receipt {receipt_id}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #fafafa; color: #222; padding: 24px; }}
  .receipt {{ max-width: 400px; margin: 0 auto; background: #fff;
              border: 1px solid #ddd; border-radius: 8px; padding: 24px;
              box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .header {{ text-align: center; margin-bottom: 20px; border-bottom: 2px solid #6B4EE6;
             padding-bottom: 16px; }}
  .header h1 {{ font-size: 20px; color: #6B4EE6; margin-bottom: 4px; }}
  .header .address {{ font-size: 12px; color: #666; }}
  .meta {{ font-size: 12px; color: #888; margin-bottom: 16px; }}
  .meta div {{ margin-bottom: 4px; }}
  .items {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
  .items th {{ text-align: left; font-size: 11px; color: #999;
               text-transform: uppercase; border-bottom: 1px solid #eee;
               padding: 6px 0; }}
  .items td {{ padding: 8px 0; border-bottom: 1px solid #f5f5f5; font-size: 14px; }}
  .item-amt {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .total {{ display: flex; justify-content: space-between; font-size: 18px;
            font-weight: 700; padding: 12px 0; border-top: 2px solid #222; }}
  .total .label {{ color: #222; }}
  .total .value {{ color: #6B4EE6; }}
  .txid {{ font-size: 11px; color: #aaa; word-break: break-all; margin-top: 16px;
           padding-top: 12px; border-top: 1px dashed #ddd; }}
  .memo {{ font-size: 13px; color: #555; margin-bottom: 12px;
           padding: 8px; background: #f9f9f9; border-radius: 4px; }}
  .footer {{ text-align: center; font-size: 11px; color: #bbb; margin-top: 20px; }}
</style>
</head>
<body>
<div class="receipt">
  <div class="header">
    <h1>{business_name}</h1>
    <div class="address">{business_address}</div>
  </div>

  <div class="meta">
    <div><strong>Receipt:</strong> {receipt_id}</div>
    <div><strong>Date:</strong> {date}</div>
  </div>

  {memo_section}

  <table class="items">
    <thead><tr><th>Item</th><th style="text-align:right">Amount</th></tr></thead>
    <tbody>{items_html}</tbody>
  </table>

  <div class="total">
    <span class="label">Total</span>
    <span class="value">{total} GHOST</span>
  </div>

  <div class="txid">
    <strong>TxID:</strong> {txid}
  </div>

  <div class="footer">Powered by GhostTap</div>
</div>
</body>
</html>"#,
            receipt_id = html_escape(&self.receipt_id),
            business_name = html_escape(&self.business_name),
            business_address = html_escape(&self.business_address),
            date = Self::format_timestamp(self.timestamp),
            memo_section = memo_section,
            items_html = items_html,
            total = format_ghost_amount(self.amount),
            txid = html_escape(&self.txid),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_html_generation() {
        let mut receipt = Receipt::new(
            "R-0001",
            "Ghost Cafe",
            "123 Main St",
            150_000_000, // 1.5 GHOST
            "abc123def456",
            1709164800,
        )
        .with_memo("Thanks for your purchase!");

        receipt.add_item(LineItem::new("Espresso", 50_000_000));
        receipt.add_item(LineItem::new("Croissant", 100_000_000));

        let html = receipt.to_html();

        assert!(html.contains("Ghost Cafe"));
        assert!(html.contains("123 Main St"));
        assert!(html.contains("R-0001"));
        assert!(html.contains("1.50000000 GHOST"));
        assert!(html.contains("Espresso"));
        assert!(html.contains("Croissant"));
        assert!(html.contains("abc123def456"));
        assert!(html.contains("Thanks for your purchase!"));
        assert!(html.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_receipt_html_escaping() {
        let receipt = Receipt::new(
            "R-002",
            "Bob's <Shop> & Grill",
            "1 \"Main\" St",
            100_000_000,
            "txid",
            0,
        );

        let html = receipt.to_html();
        assert!(html.contains("Bob&#39;s &lt;Shop&gt; &amp; Grill"));
        assert!(html.contains("1 &quot;Main&quot; St"));
    }

    #[test]
    fn test_format_amount() {
        assert_eq!(format_ghost_amount(100_000_000), "1.00000000");
        assert_eq!(format_ghost_amount(50_000), "0.00050000");
        assert_eq!(format_ghost_amount(0), "0.00000000");
    }

    #[test]
    fn test_line_item() {
        let item = LineItem::new("Coffee", 25_000_000);
        assert_eq!(item.description, "Coffee");
        assert_eq!(item.amount, 25_000_000);
    }
}

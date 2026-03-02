//! Invoice generation for merchant payments
//!
//! Supports creating invoices with line items, rendering to HTML,
//! and generating ghost: payment URIs for QR code display.

use super::receipt::LineItem;
use super::util::{days_to_ymd, format_ghost_amount, html_escape};
use serde::{Deserialize, Serialize};
use crate::payment::qr::PaymentRequest;

/// A single payment received against an invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoicePayment {
    /// Transaction ID of the payment.
    pub txid: String,
    /// Amount paid in satoshis.
    pub amount: u64,
    /// Unix timestamp when this payment was received.
    pub timestamp: u64,
}

/// Invoice lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceStatus {
    /// Invoice has been created but not yet sent to the customer.
    Draft,
    /// Invoice has been sent / presented to the customer.
    Sent,
    /// Payment received and confirmed.
    Paid,
    /// Due date has passed without payment.
    Overdue,
    /// Invoice was manually cancelled.
    Cancelled,
}

impl std::fmt::Display for InvoiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvoiceStatus::Draft => write!(f, "Draft"),
            InvoiceStatus::Sent => write!(f, "Sent"),
            InvoiceStatus::Paid => write!(f, "Paid"),
            InvoiceStatus::Overdue => write!(f, "Overdue"),
            InvoiceStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

/// A merchant invoice requesting payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    /// Unique invoice identifier.
    pub invoice_id: String,
    /// Business name from the merchant profile.
    pub business_name: String,
    /// Business address from the merchant profile.
    pub business_address: String,
    /// Total amount due in satoshis.
    pub amount: u64,
    /// Ghost address to send payment to.
    pub ghost_address: String,
    /// Due date as a Unix timestamp.
    pub due_date: u64,
    /// Individual line items.
    pub line_items: Vec<LineItem>,
    /// Optional memo / notes.
    pub memo: Option<String>,
    /// Current invoice status.
    pub status: InvoiceStatus,
    /// Payments received against this invoice.
    #[serde(default)]
    pub payments: Vec<InvoicePayment>,
}

impl Invoice {
    /// Create a new draft invoice.
    pub fn new(
        invoice_id: impl Into<String>,
        business_name: impl Into<String>,
        business_address: impl Into<String>,
        amount: u64,
        ghost_address: impl Into<String>,
        due_date: u64,
    ) -> Self {
        Self {
            invoice_id: invoice_id.into(),
            business_name: business_name.into(),
            business_address: business_address.into(),
            amount,
            ghost_address: ghost_address.into(),
            due_date,
            line_items: Vec::new(),
            memo: None,
            status: InvoiceStatus::Draft,
            payments: Vec::new(),
        }
    }

    /// Add a line item to the invoice.
    pub fn add_item(&mut self, item: LineItem) {
        self.line_items.push(item);
    }

    /// Builder-style setter for memo.
    pub fn with_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }

    /// Update the invoice status.
    ///
    /// Only the following transitions are allowed:
    /// - Draft -> Sent
    /// - Draft -> Cancelled
    /// - Sent -> Paid
    /// - Sent -> Overdue
    /// - Sent -> Cancelled
    pub fn set_status(&mut self, status: InvoiceStatus) -> Result<(), &'static str> {
        let valid = matches!(
            (self.status, status),
            (InvoiceStatus::Draft, InvoiceStatus::Sent)
                | (InvoiceStatus::Draft, InvoiceStatus::Cancelled)
                | (InvoiceStatus::Sent, InvoiceStatus::Paid)
                | (InvoiceStatus::Sent, InvoiceStatus::Overdue)
                | (InvoiceStatus::Sent, InvoiceStatus::Cancelled)
        );

        if !valid {
            return Err("invalid invoice status transition");
        }

        self.status = status;
        Ok(())
    }

    /// Total amount paid so far across all payments.
    pub fn amount_paid(&self) -> u64 {
        self.payments.iter().map(|p| p.amount).sum()
    }

    /// Remaining amount needed to fully pay this invoice.
    pub fn amount_remaining(&self) -> u64 {
        self.amount.saturating_sub(self.amount_paid())
    }

    /// Whether the invoice is fully paid (total payments >= amount).
    pub fn is_fully_paid(&self) -> bool {
        self.amount_paid() >= self.amount
    }

    /// Record a payment against this invoice.
    ///
    /// Automatically transitions status to `Paid` when fully paid.
    /// Returns `false` if the payment was rejected (duplicate txid or
    /// invoice is cancelled). Returns `true` if the payment was recorded.
    pub fn add_payment(&mut self, txid: impl Into<String>, amount: u64, timestamp: u64) -> bool {
        if self.status == InvoiceStatus::Cancelled {
            return false;
        }

        let txid = txid.into();

        // Reject duplicate txids
        if self.payments.iter().any(|p| p.txid == txid) {
            return false;
        }

        self.payments.push(InvoicePayment {
            txid,
            amount,
            timestamp,
        });
        if self.is_fully_paid() {
            self.status = InvoiceStatus::Paid;
        }
        true
    }

    /// Generate a `ghost:` payment URI for this invoice.
    ///
    /// The URI encodes the ghost address, amount, and a label
    /// constructed from the business name and invoice ID.
    pub fn to_payment_uri(&self) -> String {
        let label = format!("{} - Invoice {}", self.business_name, self.invoice_id);
        let mut req = PaymentRequest::new(&self.ghost_address)
            .with_amount(self.amount_remaining())
            .with_label(label);

        if let Some(ref memo) = self.memo {
            req = req.with_memo(memo.clone());
        }

        req.to_uri()
    }

    /// Format a unix timestamp to a date string.
    fn format_date(ts: u64) -> String {
        let days = ts / 86400;
        let (year, month, day) = days_to_ymd(days);
        format!("{:04}-{:02}-{:02}", year, month, day)
    }

    /// Render the invoice as styled HTML.
    ///
    /// Produces a self-contained HTML document with inline CSS that is
    /// suitable for display in a WebView or conversion to PDF.
    pub fn to_html(&self) -> String {
        let mut items_html = String::new();
        for item in &self.line_items {
            items_html.push_str(&format!(
                r#"<tr><td class="item-desc">{}</td><td class="item-amt">{} GHOST</td></tr>"#,
                html_escape(&item.description),
                format_ghost_amount(item.amount),
            ));
        }

        let payments_section = if self.payments.is_empty() {
            String::new()
        } else {
            let mut rows = String::new();
            for p in &self.payments {
                rows.push_str(&format!(
                    r#"<tr><td class="item-desc">{}</td><td class="item-amt">{} GHOST</td></tr>"#,
                    html_escape(&p.txid),
                    format_ghost_amount(p.amount),
                ));
            }
            format!(
                r#"<h3 style="font-size:14px;margin:16px 0 8px;">Payments Received</h3>
  <table class="items">
    <thead><tr><th>Transaction</th><th>Amount</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="meta" style="margin-bottom:12px;">
    <div><strong>Paid:</strong> {paid} GHOST</div>
    <div><strong>Remaining:</strong> {remaining} GHOST</div>
  </div>"#,
                rows = rows,
                paid = format_ghost_amount(self.amount_paid()),
                remaining = format_ghost_amount(self.amount_remaining()),
            )
        };

        let memo_section = match &self.memo {
            Some(m) => format!(
                r#"<div class="memo"><strong>Notes:</strong> {}</div>"#,
                html_escape(m)
            ),
            None => String::new(),
        };

        let status_class = match self.status {
            InvoiceStatus::Paid => "status-paid",
            InvoiceStatus::Overdue => "status-overdue",
            InvoiceStatus::Cancelled => "status-cancelled",
            _ => "status-default",
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Invoice {invoice_id}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #fafafa; color: #222; padding: 24px; }}
  .invoice {{ max-width: 600px; margin: 0 auto; background: #fff;
              border: 1px solid #ddd; border-radius: 8px; padding: 32px;
              box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start;
             margin-bottom: 24px; padding-bottom: 20px; border-bottom: 2px solid #6B4EE6; }}
  .header h1 {{ font-size: 22px; color: #6B4EE6; }}
  .header .business-addr {{ font-size: 12px; color: #666; margin-top: 4px; }}
  .invoice-badge {{ font-size: 13px; font-weight: 700; padding: 4px 12px;
                    border-radius: 12px; text-transform: uppercase; }}
  .status-default {{ background: #e8e8e8; color: #555; }}
  .status-paid {{ background: #d4edda; color: #155724; }}
  .status-overdue {{ background: #f8d7da; color: #721c24; }}
  .status-cancelled {{ background: #fff3cd; color: #856404; }}
  .meta {{ display: grid; grid-template-columns: 1fr 1fr;
           gap: 8px; font-size: 13px; color: #555; margin-bottom: 20px; }}
  .meta strong {{ color: #333; }}
  .items {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
  .items th {{ text-align: left; font-size: 11px; color: #999;
               text-transform: uppercase; border-bottom: 1px solid #eee;
               padding: 8px 0; }}
  .items th:last-child {{ text-align: right; }}
  .items td {{ padding: 10px 0; border-bottom: 1px solid #f5f5f5; font-size: 14px; }}
  .item-amt {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .total {{ display: flex; justify-content: space-between; font-size: 20px;
            font-weight: 700; padding: 14px 0; border-top: 2px solid #222; }}
  .total .value {{ color: #6B4EE6; }}
  .memo {{ font-size: 13px; color: #555; margin-bottom: 16px;
           padding: 10px; background: #f9f9f9; border-radius: 4px; }}
  .pay-to {{ font-size: 12px; color: #888; word-break: break-all;
             margin-top: 20px; padding-top: 16px; border-top: 1px dashed #ddd; }}
  .footer {{ text-align: center; font-size: 11px; color: #bbb; margin-top: 24px; }}
</style>
</head>
<body>
<div class="invoice">
  <div class="header">
    <div>
      <h1>{business_name}</h1>
      <div class="business-addr">{business_address}</div>
    </div>
    <span class="invoice-badge {status_class}">{status}</span>
  </div>

  <div class="meta">
    <div><strong>Invoice:</strong> {invoice_id}</div>
    <div><strong>Due Date:</strong> {due_date}</div>
  </div>

  {memo_section}

  <table class="items">
    <thead><tr><th>Description</th><th>Amount</th></tr></thead>
    <tbody>{items_html}</tbody>
  </table>

  <div class="total">
    <span>Amount Due</span>
    <span class="value">{total} GHOST</span>
  </div>

  {payments_section}

  <div class="pay-to">
    <strong>Pay to:</strong> {ghost_address}
  </div>

  <div class="footer">Powered by GhostTap</div>
</div>
</body>
</html>"#,
            invoice_id = html_escape(&self.invoice_id),
            business_name = html_escape(&self.business_name),
            business_address = html_escape(&self.business_address),
            status_class = status_class,
            status = self.status,
            due_date = Self::format_date(self.due_date),
            memo_section = memo_section,
            items_html = items_html,
            total = format_ghost_amount(self.amount),
            payments_section = payments_section,
            ghost_address = html_escape(&self.ghost_address),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invoice_html() {
        let mut inv = Invoice::new(
            "INV-001",
            "Ghost Cafe",
            "123 Main St",
            250_000_000, // 2.5 GHOST
            "GhAddr987zyx",
            1710374400, // some future date
        )
        .with_memo("Thank you for your business");

        inv.add_item(LineItem::new("Consulting (2 hrs)", 200_000_000));
        inv.add_item(LineItem::new("Materials", 50_000_000));

        let html = inv.to_html();

        assert!(html.contains("Ghost Cafe"));
        assert!(html.contains("INV-001"));
        assert!(html.contains("2.50000000 GHOST"));
        assert!(html.contains("Consulting (2 hrs)"));
        assert!(html.contains("Materials"));
        assert!(html.contains("GhAddr987zyx"));
        assert!(html.contains("Thank you for your business"));
    }

    #[test]
    fn test_payment_uri() {
        let inv = Invoice::new(
            "INV-002",
            "Bob's Shop",
            "456 Elm Ave",
            100_000_000,
            "GhAddrABC",
            1710374400,
        );

        let uri = inv.to_payment_uri();
        assert!(uri.starts_with("ghost:GhAddrABC"));
        assert!(uri.contains("amount=100000000"));
        assert!(uri.contains("label="));
    }

    #[test]
    fn test_invoice_status_display() {
        assert_eq!(InvoiceStatus::Draft.to_string(), "Draft");
        assert_eq!(InvoiceStatus::Paid.to_string(), "Paid");
        assert_eq!(InvoiceStatus::Overdue.to_string(), "Overdue");
        assert_eq!(InvoiceStatus::Cancelled.to_string(), "Cancelled");
    }

    #[test]
    fn test_invoice_status_transitions() {
        let mut inv = Invoice::new("I-1", "Shop", "Addr", 1000, "GhA", 0);
        assert_eq!(inv.status, InvoiceStatus::Draft);

        inv.set_status(InvoiceStatus::Sent).unwrap();
        assert_eq!(inv.status, InvoiceStatus::Sent);

        inv.set_status(InvoiceStatus::Paid).unwrap();
        assert_eq!(inv.status, InvoiceStatus::Paid);
    }

    #[test]
    fn test_invalid_status_transition() {
        let mut inv = Invoice::new("I-T", "Shop", "Addr", 1000, "GhA", 0);
        // Draft -> Paid is not allowed (must go through Sent)
        assert!(inv.set_status(InvoiceStatus::Paid).is_err());
        // Draft -> Overdue is not allowed
        assert!(inv.set_status(InvoiceStatus::Overdue).is_err());
    }

    #[test]
    fn test_duplicate_payment_rejected() {
        let mut inv = Invoice::new("I-D", "Shop", "Addr", 100_000_000, "GhA", 0);
        assert!(inv.add_payment("tx1", 40_000_000, 1000));
        // Duplicate txid should be rejected
        assert!(!inv.add_payment("tx1", 40_000_000, 2000));
        assert_eq!(inv.amount_paid(), 40_000_000);
    }

    #[test]
    fn test_payment_rejected_when_cancelled() {
        let mut inv = Invoice::new("I-C", "Shop", "Addr", 100_000_000, "GhA", 0);
        inv.set_status(InvoiceStatus::Cancelled).unwrap();
        assert!(!inv.add_payment("tx1", 40_000_000, 1000));
        assert_eq!(inv.amount_paid(), 0);
    }

    #[test]
    fn test_partial_payment() {
        let mut inv = Invoice::new("I-P1", "Shop", "Addr", 100_000_000, "GhA", 0);
        inv.add_payment("tx1", 40_000_000, 1000);
        assert_eq!(inv.amount_paid(), 40_000_000);
        assert_eq!(inv.amount_remaining(), 60_000_000);
        assert!(!inv.is_fully_paid());
        assert_ne!(inv.status, InvoiceStatus::Paid);

        inv.add_payment("tx2", 60_000_000, 2000);
        assert_eq!(inv.amount_paid(), 100_000_000);
        assert_eq!(inv.amount_remaining(), 0);
        assert!(inv.is_fully_paid());
        assert_eq!(inv.status, InvoiceStatus::Paid);
    }

    #[test]
    fn test_payment_uri_reflects_remaining() {
        let mut inv = Invoice::new("I-P2", "Shop", "Addr", 100_000_000, "GhAddr", 0);
        inv.add_payment("tx1", 30_000_000, 1000);

        let uri = inv.to_payment_uri();
        // Should contain remaining amount (70_000_000), not full amount
        assert!(uri.contains("amount=70000000"));
    }

    #[test]
    fn test_overpayment() {
        let mut inv = Invoice::new("I-P3", "Shop", "Addr", 50_000, "GhA", 0);
        inv.add_payment("tx1", 60_000, 1000);
        assert!(inv.is_fully_paid());
        // saturating_sub means remaining is 0, not negative
        assert_eq!(inv.amount_remaining(), 0);
        assert_eq!(inv.status, InvoiceStatus::Paid);
    }

    #[test]
    fn test_html_shows_payments() {
        let mut inv = Invoice::new("I-P4", "Shop", "123 St", 100_000_000, "GhA", 0);
        inv.add_item(LineItem::new("Service", 100_000_000));
        inv.add_payment("tx_abc", 40_000_000, 1000);

        let html = inv.to_html();
        assert!(html.contains("Payments Received"));
        assert!(html.contains("tx_abc"));
        assert!(html.contains("Paid:"));
        assert!(html.contains("Remaining:"));
    }

    #[test]
    fn test_backward_compat_empty_payments() {
        let inv = Invoice::new("I-BC", "Shop", "Addr", 1000, "GhA", 0);
        assert!(inv.payments.is_empty());
        assert_eq!(inv.amount_paid(), 0);
        assert_eq!(inv.amount_remaining(), 1000);
        assert!(!inv.is_fully_paid());

        let html = inv.to_html();
        assert!(!html.contains("Payments Received"));
    }
}

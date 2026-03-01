use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ghost_tap_core::merchant::export::TransactionExporter;
use ghost_tap_core::merchant::invoice::Invoice;
use ghost_tap_core::merchant::receipt::{LineItem, Receipt};
use ghost_tap_core::wallet::TxDirection;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Serialize)]
pub struct DashboardSummary {
    pub total_received: u64,
    pub total_sent: u64,
    pub total_fees: u64,
    pub tx_count: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InvoiceResponse {
    pub invoice_id: String,
    pub business_name: String,
    pub amount: u64,
    pub ghost_address: String,
    pub due_date: u64,
    pub status: String,
    pub amount_paid: u64,
    pub payment_uri: String,
    pub memo: Option<String>,
}

#[derive(Serialize)]
pub struct ReceiptResponse {
    pub receipt_id: String,
    pub html: String,
}

#[derive(Deserialize)]
pub struct LineItemInput {
    pub description: String,
    pub amount: u64,
}

#[tauri::command]
pub fn compute_dashboard(
    state: State<'_, AppState>,
    since: u64,
    until: u64,
) -> AppResult<DashboardSummary> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let history = wallet.get_history();
    let filtered: Vec<_> = history
        .iter()
        .filter(|e| e.timestamp >= since && e.timestamp < until)
        .collect();

    let total_received: u64 = filtered
        .iter()
        .filter(|e| matches!(e.direction, TxDirection::Incoming))
        .map(|e| e.amount)
        .sum();

    let total_sent: u64 = filtered
        .iter()
        .filter(|e| matches!(e.direction, TxDirection::Outgoing))
        .map(|e| e.amount)
        .sum();

    let total_fees: u64 = filtered.iter().filter_map(|e| e.fee).sum();

    Ok(DashboardSummary {
        total_received,
        total_sent,
        total_fees,
        tx_count: filtered.len(),
    })
}

#[tauri::command]
pub fn create_invoice(
    state: State<'_, AppState>,
    address: String,
    amount: u64,
    business_name: Option<String>,
    memo: Option<String>,
    due_date: Option<u64>,
    items: Option<Vec<LineItemInput>>,
) -> AppResult<InvoiceResponse> {
    let invoice_id = format!(
        "INV-{}",
        uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
    );
    let biz_name = business_name.unwrap_or_else(|| "Merchant".to_string());
    let due = due_date.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 86400 * 30
    });

    let mut invoice = Invoice::new(&invoice_id, &biz_name, "", amount, &address, due);

    if let Some(m) = memo {
        invoice = invoice.with_memo(m);
    }

    if let Some(line_items) = items {
        for item in line_items {
            invoice.add_item(LineItem::new(item.description, item.amount));
        }
    }

    let payment_uri = invoice.to_payment_uri();
    let amount_paid = invoice.amount_paid();
    let status = invoice.status.to_string();

    let response = InvoiceResponse {
        invoice_id: invoice.invoice_id,
        business_name: invoice.business_name,
        amount: invoice.amount,
        ghost_address: invoice.ghost_address,
        due_date: invoice.due_date,
        status,
        amount_paid,
        payment_uri,
        memo: invoice.memo,
    };

    // Persist invoice to storage
    let guard = state.wallet.lock();
    if let Some(instance) = guard.as_ref() {
        if let Ok(s) = instance.storage.lock() {
            let key = format!("invoice:{}", response.invoice_id);
            if let Ok(json) = serde_json::to_vec(&response) {
                let _ = s.set(&key, &json);
            }
        }
    }

    Ok(response)
}

#[tauri::command]
pub fn list_invoices(state: State<'_, AppState>) -> AppResult<Vec<InvoiceResponse>> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let storage = instance
        .storage
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let keys = storage.list_keys("invoice:")?;
    let mut invoices = Vec::new();
    for key in keys {
        if let Ok(data) = storage.get(&key) {
            if let Ok(inv) = serde_json::from_slice::<InvoiceResponse>(&data) {
                invoices.push(inv);
            }
        }
    }

    // Sort by due_date descending (newest first)
    invoices.sort_by(|a, b| b.due_date.cmp(&a.due_date));
    Ok(invoices)
}

#[tauri::command]
pub fn delete_invoice(state: State<'_, AppState>, invoice_id: String) -> AppResult<()> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let storage = instance
        .storage
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;
    let key = format!("invoice:{}", invoice_id);
    storage.delete(&key)?;
    Ok(())
}

#[tauri::command]
pub fn generate_receipt(
    txid: String,
    amount: u64,
    items: Vec<LineItemInput>,
    merchant_name: Option<String>,
    memo: Option<String>,
) -> AppResult<ReceiptResponse> {
    let receipt_id = format!(
        "R-{}",
        uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
    );
    let biz_name = merchant_name.unwrap_or_else(|| "Merchant".to_string());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut receipt = Receipt::new(&receipt_id, &biz_name, "", amount, &txid, now);

    if let Some(m) = memo {
        receipt = receipt.with_memo(m);
    }

    for item in items {
        receipt.add_item(LineItem::new(item.description, item.amount));
    }

    let html = receipt.to_html();

    Ok(ReceiptResponse {
        receipt_id: receipt.receipt_id,
        html,
    })
}

#[tauri::command]
pub fn export_csv(state: State<'_, AppState>, since: u64, until: u64) -> AppResult<String> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let history = wallet.get_history();
    Ok(TransactionExporter::to_csv(history, since, until))
}

#[tauri::command]
pub fn export_html(
    state: State<'_, AppState>,
    since: u64,
    until: u64,
    business_name: Option<String>,
) -> AppResult<String> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let history = wallet.get_history();
    let biz = business_name.unwrap_or_else(|| "Merchant".to_string());
    Ok(TransactionExporter::to_html_report(
        history, since, until, &biz,
    ))
}

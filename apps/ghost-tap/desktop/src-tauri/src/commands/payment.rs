use crate::error::AppResult;
use ghost_tap_core::payment::qr::PaymentRequest;
use serde::Serialize;

#[derive(Serialize)]
pub struct PaymentRequestResponse {
    pub address: String,
    pub amount: Option<u64>,
    pub memo: Option<String>,
    pub label: Option<String>,
    pub exp: Option<u64>,
    pub net: Option<String>,
}

#[derive(Serialize)]
pub struct CheckedPaymentResponse {
    pub request: PaymentRequestResponse,
    pub warnings: Vec<String>,
}

impl From<&PaymentRequest> for PaymentRequestResponse {
    fn from(req: &PaymentRequest) -> Self {
        Self {
            address: req.address.clone(),
            amount: req.amount,
            memo: req.memo.clone(),
            label: req.label.clone(),
            exp: req.exp,
            net: req.net.clone(),
        }
    }
}

#[tauri::command]
pub fn parse_payment_uri(uri: String) -> AppResult<PaymentRequestResponse> {
    let req = PaymentRequest::from_uri(&uri)?;
    Ok(PaymentRequestResponse::from(&req))
}

#[tauri::command]
pub fn parse_payment_uri_checked(
    uri: String,
    now: u64,
    network: Option<String>,
) -> AppResult<CheckedPaymentResponse> {
    let parsed = PaymentRequest::from_uri_checked(&uri, now, network.as_deref())?;
    Ok(CheckedPaymentResponse {
        request: PaymentRequestResponse::from(&parsed.request),
        warnings: parsed.warnings.iter().map(|w| w.to_string()).collect(),
    })
}

#[tauri::command]
pub fn create_payment_uri(
    address: String,
    amount: Option<u64>,
    memo: Option<String>,
    label: Option<String>,
    exp: Option<u64>,
    network: Option<String>,
) -> String {
    let mut req = PaymentRequest::new(address);
    if let Some(amt) = amount {
        req = req.with_amount(amt);
    }
    if let Some(m) = memo {
        req = req.with_memo(m);
    }
    if let Some(l) = label {
        req = req.with_label(l);
    }
    if let Some(e) = exp {
        req = req.with_expiry(e);
    }
    if let Some(n) = network {
        req = req.with_network(n);
    }
    req.to_uri()
}

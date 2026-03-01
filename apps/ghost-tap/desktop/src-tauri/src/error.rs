use serde::Serialize;

/// Tauri-compatible error type that serializes to JSON for the frontend.
#[derive(Debug, Serialize)]
pub struct AppError {
    pub message: String,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<ghost_tap_core::GhostTapError> for AppError {
    fn from(e: ghost_tap_core::GhostTapError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<ghost_tap_core::wallet::WalletError> for AppError {
    fn from(e: ghost_tap_core::wallet::WalletError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<ghost_tap_core::network::NetworkError> for AppError {
    fn from(e: ghost_tap_core::network::NetworkError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<ghost_tap_core::transaction::TransactionError> for AppError {
    fn from(e: ghost_tap_core::transaction::TransactionError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<ghost_tap_core::storage::StorageError> for AppError {
    fn from(e: ghost_tap_core::storage::StorageError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<ghost_tap_core::payment::qr::PaymentUriError> for AppError {
    fn from(e: ghost_tap_core::payment::qr::PaymentUriError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        Self { message: s }
    }
}

impl From<&str> for AppError {
    fn from(s: &str) -> Self {
        Self {
            message: s.to_string(),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

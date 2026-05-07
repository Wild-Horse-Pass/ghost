//! HTTP endpoint handlers. One submodule per endpoint family so each
//! file stays focused on its own request/response contract.

pub mod blind_sig;
pub mod discover;
pub mod find_or_create;
pub mod health;
pub mod session_inputs;
pub mod session_status;

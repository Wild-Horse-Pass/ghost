mod commands;
mod error;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            // Wallet
            commands::wallet::create_wallet,
            commands::wallet::restore_wallet,
            commands::wallet::get_mnemonic,
            commands::wallet::get_balance,
            commands::wallet::new_receive_address,
            commands::wallet::get_all_addresses,
            commands::wallet::get_history,
            commands::wallet::lock_wallet,
            commands::wallet::unlock_wallet,
            commands::wallet::is_locked,
            commands::wallet::has_wallet,
            // Transaction
            commands::transaction::build_transaction,
            commands::transaction::sign_and_broadcast,
            commands::transaction::estimate_fee,
            // Payment
            commands::payment::parse_payment_uri,
            commands::payment::parse_payment_uri_checked,
            commands::payment::create_payment_uri,
            // Connection
            commands::connection::set_connection_mode,
            commands::connection::set_rpc_config,
            commands::connection::get_connection_status,
            commands::connection::sync,
            // Merchant
            commands::merchant::compute_dashboard,
            commands::merchant::create_invoice,
            commands::merchant::generate_receipt,
            commands::merchant::export_csv,
            commands::merchant::export_html,
            // Wraith
            commands::wraith::wash_payment,
            commands::wraith::get_wash_queue,
            commands::wraith::get_wash_stats,
            commands::wraith::start_wash_processor,
            commands::wraith::stop_wash_processor,
            commands::wraith::retry_wash,
        ])
        .run(tauri::generate_context!())
        .expect("error running GhostTap Desktop");
}

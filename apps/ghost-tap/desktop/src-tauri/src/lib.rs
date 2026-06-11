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
            commands::wallet::set_pin,
            commands::wallet::verify_pin,
            commands::wallet::has_pin,
            commands::wallet::load_wallet,
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
            commands::connection::set_ghost_pay_config,
            commands::connection::get_connection_status,
            commands::connection::get_node_info,
            commands::connection::test_connection,
            commands::connection::sync,
            // Merchant
            commands::merchant::compute_dashboard,
            commands::merchant::create_invoice,
            commands::merchant::list_invoices,
            commands::merchant::delete_invoice,
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
            // Glyph
            commands::glyph::claim_glyph,
            commands::glyph::get_glyph,
            commands::glyph::check_glyph_availability,
            commands::glyph::render_glyph,
            commands::glyph::get_glyph_palette,
            commands::glyph::validate_glyph_pixels,
            // L2 Confidential
            commands::l2::l2_balance,
            commands::l2::l2_notes,
            commands::l2::l2_scan,
            commands::l2::l2_transfer,
            commands::l2::l2_consolidate,
            commands::l2::l2_unshield,
            commands::l2::l2_shield,
            commands::l2::l2_sync_status,
            // Ghost Locks
            commands::locks::list_locks,
            commands::locks::get_lock,
            commands::locks::create_lock,
            commands::locks::jump_lock,
            commands::locks::reconcile_lock,
            // Ghost ID
            commands::locks::get_ghost_id,
            commands::locks::generate_ghost_id,
            // L2 Payments
            commands::locks::send_l2_payment,
            // Withdrawals
            commands::locks::list_withdrawals,
            commands::locks::get_withdrawal,
            // Address Book
            commands::addressbook::list_address_labels,
            commands::addressbook::get_addresses_for_label,
            commands::addressbook::set_address_label,
            commands::addressbook::validate_address_info,
            commands::addressbook::list_received_addresses,
            // Signing
            commands::signing::sign_message,
            commands::signing::verify_message,
            // PSBT
            commands::psbt::decode_psbt,
            commands::psbt::analyze_psbt,
            commands::psbt::sign_psbt,
            commands::psbt::combine_psbts,
            commands::psbt::finalize_psbt,
            commands::psbt::broadcast_psbt,
            // Coin Control
            commands::coincontrol::list_unspent,
            commands::coincontrol::lock_unspent_output,
            commands::coincontrol::list_locked_outputs,
            commands::coincontrol::send_with_inputs,
            // RPC Console
            commands::rpc_console::execute_rpc,
            // Node Wallet
            commands::node_wallet::node_encrypt_wallet,
            commands::node_wallet::node_unlock_wallet,
            commands::node_wallet::node_lock_wallet,
            commands::node_wallet::node_change_passphrase,
            commands::node_wallet::get_node_wallet_info,
        ])
        .run(tauri::generate_context!())
        .expect("error running GhostTap Desktop");
}

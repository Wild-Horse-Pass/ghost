//! Build a synthetic BIP-352 candidate-transaction payload addressed to a given
//! wallet's scan + spend pubkeys, ready to POST at
//! `/api/v1/admin/inject-candidate-tx` on a dev ghost-gsp.
//!
//! Usage:
//!   cargo run -p wraith-wallet-core --example synthetic_candidate -- \
//!       <scan_pubkey_hex_33b> <spend_pubkey_hex_33b> [amount_sats] [vout]
//!
//! Prints a single line of JSON to stdout. Pipe into curl:
//!   curl -sS -X POST -H 'content-type: application/json' \
//!     http://127.0.0.1:8900/api/v1/admin/inject-candidate-tx \
//!     -d "$(cargo run -p wraith-wallet-core --example synthetic_candidate -- ...)"

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use ghost_keys::{derive_payment_address_v2, derive_shared_secret};
use rand::RngCore;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <scan_pubkey_hex_33b> <spend_pubkey_hex_33b> [amount_sats] [vout]",
            args[0]
        );
        std::process::exit(2);
    }
    let scan_hex = &args[1];
    let spend_hex = &args[2];
    let amount: u64 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);
    let vout: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);

    let scan_bytes = hex::decode(scan_hex).expect("scan_pubkey hex");
    let spend_bytes = hex::decode(spend_hex).expect("spend_pubkey hex");
    let scan_pubkey = PublicKey::from_slice(&scan_bytes).expect("scan_pubkey curve");
    let spend_pubkey = PublicKey::from_slice(&spend_bytes).expect("spend_pubkey curve");

    let secp = Secp256k1::new();
    let mut eph_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut eph_bytes);
    let eph_secret = SecretKey::from_slice(&eph_bytes).expect("nonzero scalar");
    let ephemeral_pub = PublicKey::from_secret_key(&secp, &eph_secret);

    // ECDH(eph_secret, scan_pubkey) — same secret the receiver computes via
    // ECDH(scan_secret, ephemeral_pub).
    let shared_secret = derive_shared_secret(&eph_secret, &scan_pubkey);

    let k: u32 = 0;
    let (output_pubkey, _tweak) =
        derive_payment_address_v2(&spend_pubkey, &shared_secret, k).expect("derive output");

    // x-only encoding (taproot output).
    let serialized = output_pubkey.serialize();
    let xonly = &serialized[1..];

    // Random 32-byte txid for the synthetic tx.
    let mut txid_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut txid_bytes);

    let payload = serde_json::json!({
        "ephemeral_pubkey": hex::encode(ephemeral_pub.serialize()),
        "outputs": [
            {
                "output_pubkey": hex::encode(xonly),
                "amount_sats": amount,
                "vout": vout,
            }
        ],
        "txid": hex::encode(txid_bytes),
        "block_height": 250,
    });
    println!("{}", payload);
}

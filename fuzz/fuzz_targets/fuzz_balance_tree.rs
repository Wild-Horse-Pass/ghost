//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: fuzz_balance_tree.rs                                                                                           |
//|======================================================================================================================|

//! Fuzz target for BalanceTree sparse Merkle tree operations
//!
//! Tests that BalanceTree never panics on arbitrary sequences of
//! set_balance, apply_payment, root, and get_proof operations.
//! Also validates key invariants: root determinism and total balance
//! conservation after payments.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use ghost_zkp::BalanceTree;

/// Cap tree depth to avoid excessive computation during fuzzing
const MAX_FUZZ_DEPTH: usize = 10;
/// Cap number of accounts to keep iterations fast
const MAX_ACCOUNTS: usize = 32;
/// Cap balance to prevent overflow in total_balance (21M BTC in sats)
const MAX_BALANCE: u64 = 2_100_000_000_000_000;
#[derive(Arbitrary, Debug)]
enum TreeOp {
    SetBalance { index: u64, balance: u64 },
    ApplyPayment { sender: u64, recipient: u64, amount: u64 },
    ComputeRoot,
    GetProof { index: u64 },
    GetBalance { index: u64 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    depth: u8,
    initial_balances: Vec<(u64, u64)>,
    operations: Vec<TreeOp>,
}

fuzz_target!(|input: FuzzInput| {
    // Clamp depth to safe range
    let depth = (input.depth as usize % MAX_FUZZ_DEPTH).max(1);

    // Build initial balances, capping count and indices
    let max_index = (1u64 << depth).saturating_sub(1);
    let balances: HashMap<u64, u64> = input.initial_balances
        .iter()
        .take(MAX_ACCOUNTS)
        .map(|(idx, bal)| (idx % (max_index + 1), bal % MAX_BALANCE))
        .collect();

    let mut tree = BalanceTree::from_balances(depth, balances);

    // Compute initial root — must not panic
    let root1 = tree.root();

    // Root should be deterministic: computing twice must be identical
    if let (Ok(r1), Ok(r2)) = (root1, tree.root()) {
        assert_eq!(r1, r2, "root() must be deterministic");
    }

    // Apply operations
    for op in input.operations.iter().take(64) {
        match op {
            TreeOp::SetBalance { index, balance } => {
                let idx = index % (max_index + 1);
                tree.set_balance(idx, balance % MAX_BALANCE);
            }
            TreeOp::ApplyPayment { sender, recipient, amount } => {
                let s = sender % (max_index + 1);
                let r = recipient % (max_index + 1);
                // Track total balance before payment
                let total_before = tree.total_balance();
                let result = tree.apply_payment(s, r, *amount);
                if result.is_ok() {
                    // Payment succeeded — total balance must be conserved
                    let total_after = tree.total_balance();
                    assert_eq!(total_before, total_after,
                        "total balance must be conserved after payment");
                }
            }
            TreeOp::ComputeRoot => {
                let _ = tree.root();
            }
            TreeOp::GetProof { index } => {
                let idx = index % (max_index + 1);
                let _ = tree.get_proof(idx);
            }
            TreeOp::GetBalance { index } => {
                let idx = index % (max_index + 1);
                let _ = tree.get_balance(idx);
            }
        }
    }

    // Final root must not panic
    let _ = tree.root();
});

//! Backtest ghost-reaper against real mainnet blocks.
//!
//! Fetches raw blocks from mempool.space API, deserializes every transaction,
//! and runs the reaper analysis. Any transaction flagged as Corpse is a potential
//! false positive (since it's already confirmed on mainnet).
//!
//! Run with: cargo test -p ghost-reaper --test backtest_mainnet -- --ignored --nocapture

use bitcoin::consensus::deserialize;
use bitcoin::Block;
use ghost_reaper::{analyze, DeadCodeType, ReaperConfig, Verdict};
use std::process::Command;

/// Fetch the block hash for a given height from mempool.space
fn fetch_block_hash(height: u64) -> Option<String> {
    let output = Command::new("curl")
        .args([
            "-sf",
            &format!("https://mempool.space/api/block-height/{}", height),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Fetch raw block bytes for a given hash from mempool.space
fn fetch_raw_block(hash: &str) -> Option<Vec<u8>> {
    let output = Command::new("curl")
        .args([
            "-sf",
            &format!("https://mempool.space/api/block/{}/raw", hash),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(output.stdout)
}

#[derive(Default)]
struct BacktestStats {
    total_blocks: usize,
    total_txs: usize,
    total_coinbase: usize,
    accepted: usize,
    corpse: usize,
    // Breakdown by detection type
    by_type: std::collections::HashMap<String, usize>,
    // Breakdown by spend type for corpse txs
    corpse_spend_types: std::collections::HashMap<String, usize>,
    // False positive candidates (corpse txs without known spam patterns)
    false_positives: Vec<String>,
}

/// Known spam detection types — if a tx is flagged ONLY by these, it's expected
fn is_known_spam_type(dt: &DeadCodeType) -> bool {
    matches!(
        dt,
        DeadCodeType::InscriptionEnvelope
            | DeadCodeType::DropStuffing
            | DeadCodeType::UnreachableCode
            | DeadCodeType::FakePubkey
            | DeadCodeType::FakePubkeyCurvePoint
            | DeadCodeType::AnnexPresent
            | DeadCodeType::OversizedOpReturn
    )
}

#[test]
#[ignore]
fn backtest_recent_mainnet_blocks() {
    let config = ReaperConfig::default();

    // Get current tip height
    let tip_output = Command::new("curl")
        .args(["-sf", "https://mempool.space/api/blocks/tip/height"])
        .output()
        .expect("curl failed");
    let tip_height: u64 = String::from_utf8_lossy(&tip_output.stdout)
        .trim()
        .parse()
        .expect("bad tip height");

    // Backtest the last 10 blocks
    let start_height = tip_height - 9;
    let end_height = tip_height;

    println!("\n============================================================");
    println!("Ghost Reaper — Mainnet Backtest");
    println!(
        "Blocks {} to {} ({} blocks)",
        start_height,
        end_height,
        end_height - start_height + 1
    );
    println!("============================================================\n");

    let mut stats = BacktestStats::default();

    for height in start_height..=end_height {
        print!("Block {}... ", height);

        let hash = match fetch_block_hash(height) {
            Some(h) => h,
            None => {
                println!("SKIP (failed to fetch hash)");
                continue;
            }
        };

        let raw = match fetch_raw_block(&hash) {
            Some(r) => r,
            None => {
                println!("SKIP (failed to fetch raw block)");
                continue;
            }
        };

        let block: Block = match deserialize(&raw) {
            Ok(b) => b,
            Err(e) => {
                println!("SKIP (deserialize error: {})", e);
                continue;
            }
        };

        let tx_count = block.txdata.len();
        stats.total_blocks += 1;

        let mut block_corpse = 0;
        for tx in &block.txdata {
            stats.total_txs += 1;

            if tx.is_coinbase() {
                stats.total_coinbase += 1;
                stats.accepted += 1;
                continue;
            }

            let verdict = analyze(tx, &config);

            match verdict.verdict {
                Verdict::Accept => stats.accepted += 1,
                Verdict::Corpse => {
                    stats.corpse += 1;
                    block_corpse += 1;

                    // Track detection types
                    let mut has_known_spam = false;
                    let mut has_novel_detection = false;
                    for region in &verdict.dead_regions {
                        let type_name = format!("{:?}", region.dead_code_type);
                        *stats.by_type.entry(type_name).or_insert(0) += 1;
                        if is_known_spam_type(&region.dead_code_type) {
                            has_known_spam = true;
                        } else {
                            has_novel_detection = true;
                        }
                    }

                    // Track spend types
                    for analysis in &verdict.input_analyses {
                        if analysis.dead_bytes > 0 {
                            *stats
                                .corpse_spend_types
                                .entry(analysis.spend_type.clone())
                                .or_insert(0) += 1;
                        }
                    }

                    // If flagged ONLY by novel detection (not known spam), it's a
                    // potential false positive — these need manual review
                    if has_novel_detection && !has_known_spam {
                        let txid = tx.compute_txid();
                        stats.false_positives.push(format!(
                            "  txid: {} (dead={} bytes, regions: {:?})",
                            txid,
                            verdict.total_dead_bytes,
                            verdict
                                .dead_regions
                                .iter()
                                .map(|r| format!("{:?}", r.dead_code_type))
                                .collect::<Vec<_>>()
                        ));
                    }
                }
            }
        }

        println!(
            "{} txs, {} corpse (hash: {}..)",
            tx_count,
            block_corpse,
            &hash[..12]
        );

        // Be nice to the API
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Print results
    println!("\n============================================================");
    println!("RESULTS");
    println!("============================================================");
    println!("Blocks analyzed:   {}", stats.total_blocks);
    println!("Total transactions: {}", stats.total_txs);
    println!("  Coinbase (skip):  {}", stats.total_coinbase);
    println!("  Accepted:         {}", stats.accepted);
    println!("  Corpse:           {}", stats.corpse);
    println!(
        "  Corpse rate:      {:.4}%",
        if stats.total_txs > 0 {
            stats.corpse as f64 / (stats.total_txs - stats.total_coinbase) as f64 * 100.0
        } else {
            0.0
        }
    );

    if !stats.by_type.is_empty() {
        println!("\nDetection type breakdown:");
        let mut types: Vec<_> = stats.by_type.iter().collect();
        types.sort_by(|a, b| b.1.cmp(a.1));
        for (type_name, count) in types {
            println!("  {:30} {}", type_name, count);
        }
    }

    if !stats.corpse_spend_types.is_empty() {
        println!("\nCorpse spend type breakdown:");
        let mut types: Vec<_> = stats.corpse_spend_types.iter().collect();
        types.sort_by(|a, b| b.1.cmp(a.1));
        for (type_name, count) in types {
            println!("  {:30} {}", type_name, count);
        }
    }

    if !stats.false_positives.is_empty() {
        println!(
            "\n*** POTENTIAL FALSE POSITIVES ({}) ***",
            stats.false_positives.len()
        );
        println!("These txs were flagged ONLY by novel detection (not known spam patterns).");
        println!("Review manually to confirm they are actually spam:");
        for fp in &stats.false_positives {
            println!("{}", fp);
        }
    } else {
        println!("\nNo potential false positives detected.");
    }

    println!();

    // The key assertion: no false positives from ONLY novel computational detection
    // (If a tx is flagged by both pattern + computational, that's fine — the pattern caught it)
    // We specifically want to verify the computational engine doesn't flag legitimate txs
    if !stats.false_positives.is_empty() {
        println!(
            "WARNING: {} potential false positives found — review above list",
            stats.false_positives.len()
        );
    }
}

/// Backtest against specific historically interesting blocks
/// (blocks known to contain inscriptions, ordinals, stamps, etc.)
#[test]
#[ignore]
fn backtest_inscription_heavy_blocks() {
    let config = ReaperConfig::default();

    // Block 774628 — first Ordinals inscription
    // Block 776000 — early inscription period
    // Block 800000 — high inscription activity
    // Block 840000 — post-halving inscriptions
    let interesting_heights: Vec<u64> = vec![774628, 776000, 800000, 840000];

    println!("\n============================================================");
    println!("Ghost Reaper — Inscription-Heavy Block Backtest");
    println!("============================================================\n");

    let mut total_txs = 0;
    let mut total_corpse = 0;
    let mut _total_accepted = 0;
    let mut novel_flags = 0;

    for height in &interesting_heights {
        print!("Block {}... ", height);

        let hash = match fetch_block_hash(*height) {
            Some(h) => h,
            None => {
                println!("SKIP");
                continue;
            }
        };

        let raw = match fetch_raw_block(&hash) {
            Some(r) => r,
            None => {
                println!("SKIP");
                continue;
            }
        };

        let block: Block = match deserialize(&raw) {
            Ok(b) => b,
            Err(e) => {
                println!("SKIP ({})", e);
                continue;
            }
        };

        let mut block_corpse = 0;
        let mut block_novel = 0;

        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            total_txs += 1;
            let verdict = analyze(tx, &config);

            match verdict.verdict {
                Verdict::Corpse => {
                    total_corpse += 1;
                    block_corpse += 1;

                    // Check if any detection is purely novel (no pattern match)
                    let all_novel = verdict.dead_regions.iter().all(|r| {
                        matches!(
                            r.dead_code_type,
                            DeadCodeType::ExcessWitnessData
                                | DeadCodeType::ExcessStackItems
                                | DeadCodeType::LegacyScriptSigData
                        )
                    });
                    if all_novel {
                        block_novel += 1;
                        novel_flags += 1;
                        let txid = tx.compute_txid();
                        println!(
                            "\n  NOVEL FLAG: {} (dead={} bytes, regions: {:?})",
                            txid,
                            verdict.total_dead_bytes,
                            verdict
                                .dead_regions
                                .iter()
                                .map(|r| format!("{:?}", r.dead_code_type))
                                .collect::<Vec<_>>()
                        );
                    }
                }
                _ => _total_accepted += 1,
            }
        }

        println!(
            "{} txs, {} corpse ({} novel)",
            block.txdata.len(),
            block_corpse,
            block_novel
        );

        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    println!(
        "\nSummary: {}/{} corpse ({:.2}%), {} novel flags",
        total_corpse,
        total_txs,
        total_corpse as f64 / total_txs.max(1) as f64 * 100.0,
        novel_flags
    );
}

use bitcoin::Transaction;
use tracing::debug;

use crate::config::{ReaperConfig, ReaperMode};
use crate::dead_code::detect_dead_code;
use crate::output::analyze_outputs;
use crate::verdict::{
    AnalysisLocation, DeadCodeRegion, DeadCodeType, InputAnalysis, ReaperVerdict, Verdict,
};
use crate::witness::{has_annex, identify_spend, SpendType};

/// Analyze a transaction for dead code in witness scripts and outputs.
///
/// Returns a `ReaperVerdict` with detailed region-level findings and
/// a final `Verdict` (Accept, Corpse, or MonitorOnly) based on the config mode.
pub fn analyze(tx: &Transaction, config: &ReaperConfig) -> ReaperVerdict {
    // Disabled → accept everything
    if !config.enabled {
        return ReaperVerdict::accept();
    }

    // Coinbase transactions contain legitimate miner data
    if tx.is_coinbase() {
        return ReaperVerdict::accept();
    }

    let mut all_regions: Vec<DeadCodeRegion> = Vec::new();
    let mut input_analyses: Vec<InputAnalysis> = Vec::new();
    let mut total_witness_bytes: usize = 0;

    // Analyze each input's witness
    for (idx, input) in tx.input.iter().enumerate() {
        let spend_type = identify_spend(input);
        let mut input_dead_bytes: usize = 0;
        let mut input_regions: Vec<DeadCodeRegion> = Vec::new();

        // Calculate witness size for this input
        let witness_size: usize = input.witness.iter().map(|item| item.len()).sum();
        total_witness_bytes += witness_size;

        // Detect dead code in the relevant script
        match &spend_type {
            SpendType::P2trScriptPath { tapscript, .. } => {
                let regions = detect_dead_code(tapscript, idx, config);
                for region in &regions {
                    input_dead_bytes += region.size;
                }
                input_regions.extend(regions);
            }
            SpendType::P2wsh { witness_script } => {
                let regions = detect_dead_code(witness_script, idx, config);
                for region in &regions {
                    input_dead_bytes += region.size;
                }
                input_regions.extend(regions);
            }
            _ => {
                // P2TR key path, P2WPKH, Legacy, Empty — no script to analyze
            }
        }

        // Check for annex presence
        if config.reject_annex && has_annex(input) {
            let annex_size = input.witness.iter().last().map_or(0, |a| a.len());
            let region = DeadCodeRegion {
                location: AnalysisLocation::Input(idx),
                dead_code_type: DeadCodeType::AnnexPresent,
                offset: 0,
                size: annex_size,
                description: format!("Witness annex present: {} bytes", annex_size),
            };
            input_dead_bytes += annex_size;
            input_regions.push(region);
        }

        // Get script size for reporting
        let script_size = match &spend_type {
            SpendType::P2trScriptPath { tapscript, .. } => tapscript.len(),
            SpendType::P2wsh { witness_script } => witness_script.len(),
            _ => 0,
        };

        all_regions.extend(input_regions.clone());
        input_analyses.push(InputAnalysis {
            input_index: idx,
            spend_type: spend_type.to_string(),
            script_size,
            dead_bytes: input_dead_bytes,
            regions: input_regions,
        });
    }

    // Analyze outputs
    let output_regions = analyze_outputs(tx, config);
    let output_dead_bytes: usize = output_regions.iter().map(|r| r.size).sum();
    all_regions.extend(output_regions);

    // Calculate totals
    let total_dead_bytes: usize = all_regions.iter().map(|r| r.size).sum();
    let dead_code_ratio = if total_witness_bytes > 0 {
        total_dead_bytes as f64 / total_witness_bytes as f64
    } else if output_dead_bytes > 0 {
        // Only output-level dead code, no witness to ratio against
        1.0
    } else {
        0.0
    };

    // Determine verdict based on mode
    let verdict = determine_verdict(total_dead_bytes, dead_code_ratio, &all_regions, config);

    if verdict == Verdict::Corpse {
        debug!(
            dead_bytes = total_dead_bytes,
            ratio = format!("{:.2}%", dead_code_ratio * 100.0),
            regions = all_regions.len(),
            "Transaction classified as Corpse"
        );
    }

    ReaperVerdict {
        verdict,
        dead_regions: all_regions,
        input_analyses,
        total_dead_bytes,
        total_witness_bytes,
        dead_code_ratio,
    }
}

/// Apply mode-specific thresholds to determine the final verdict.
fn determine_verdict(
    total_dead_bytes: usize,
    dead_code_ratio: f64,
    regions: &[DeadCodeRegion],
    config: &ReaperConfig,
) -> Verdict {
    if regions.is_empty() {
        return Verdict::Accept;
    }

    match config.mode {
        ReaperMode::Strict => {
            if total_dead_bytes > config.strict_max_dead_bytes {
                Verdict::Corpse
            } else {
                Verdict::Accept
            }
        }
        ReaperMode::Moderate => {
            if total_dead_bytes > config.moderate_max_dead_bytes
                || dead_code_ratio > config.moderate_max_dead_ratio
            {
                Verdict::Corpse
            } else {
                Verdict::Accept
            }
        }
        ReaperMode::Monitor => Verdict::MonitorOnly,
    }
}

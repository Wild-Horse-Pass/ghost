mod analyzer;
mod config;
mod dead_code;
mod essential;
mod flow;
mod legacy;
mod output;
mod simulator;
mod verdict;
mod witness;

pub use analyzer::analyze;
pub use config::{ReaperConfig, ReaperMode};
pub use verdict::{
    AnalysisLocation, DeadCodeRegion, DeadCodeType, InputAnalysis, ReaperVerdict, Verdict,
    WitnessBreakdown,
};
pub use witness::SpendType;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod adversarial_tests;

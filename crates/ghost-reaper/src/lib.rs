mod analyzer;
mod config;
mod dead_code;
mod output;
mod verdict;
mod witness;

pub use analyzer::analyze;
pub use config::{ReaperConfig, ReaperMode};
pub use verdict::{
    AnalysisLocation, DeadCodeRegion, DeadCodeType, InputAnalysis, ReaperVerdict, Verdict,
};
pub use witness::SpendType;

#[cfg(test)]
mod tests;

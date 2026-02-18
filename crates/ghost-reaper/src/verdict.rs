use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accept,
    Corpse,
    MonitorOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadCodeType {
    InscriptionEnvelope,
    DropStuffing,
    UnreachableCode,
    FakePubkey,
    AnnexPresent,
    OversizedOpReturn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisLocation {
    Input(usize),
    Output(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeRegion {
    pub location: AnalysisLocation,
    pub dead_code_type: DeadCodeType,
    pub offset: usize,
    pub size: usize,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputAnalysis {
    pub input_index: usize,
    pub spend_type: String,
    pub script_size: usize,
    pub dead_bytes: usize,
    pub regions: Vec<DeadCodeRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaperVerdict {
    pub verdict: Verdict,
    pub dead_regions: Vec<DeadCodeRegion>,
    pub input_analyses: Vec<InputAnalysis>,
    pub total_dead_bytes: usize,
    pub total_witness_bytes: usize,
    pub dead_code_ratio: f64,
}

impl ReaperVerdict {
    pub fn is_corpse(&self) -> bool {
        self.verdict == Verdict::Corpse
    }

    pub fn is_accepted(&self) -> bool {
        self.verdict == Verdict::Accept
    }

    pub fn accept() -> Self {
        Self {
            verdict: Verdict::Accept,
            dead_regions: Vec::new(),
            input_analyses: Vec::new(),
            total_dead_bytes: 0,
            total_witness_bytes: 0,
            dead_code_ratio: 0.0,
        }
    }
}

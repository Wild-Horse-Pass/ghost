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
//| FILE: verdict.rs                                                                                                     |
//|======================================================================================================================|

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accept,
    Corpse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadCodeType {
    InscriptionEnvelope,
    DropStuffing,
    UnreachableCode,
    FakePubkey,
    FakePubkeyCurvePoint,
    AnnexPresent,
    OversizedOpReturn,
    ExcessWitnessData,
    ExcessStackItems,
    LegacyScriptSigData,
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
pub struct WitnessBreakdown {
    pub essential_bytes: usize,
    pub dead_bytes: usize,
    pub essential_script_bytes: usize,
    pub original_script_bytes: usize,
    pub control_block_bytes: usize,
    pub essential_stack_items: usize,
    pub actual_stack_items: usize,
    pub excess_stack_items: usize,
    pub excess_stack_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputAnalysis {
    pub input_index: usize,
    pub spend_type: String,
    pub script_size: usize,
    pub dead_bytes: usize,
    pub regions: Vec<DeadCodeRegion>,
    pub witness_breakdown: Option<WitnessBreakdown>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaperVerdict {
    pub verdict: Verdict,
    pub dead_regions: Vec<DeadCodeRegion>,
    pub input_analyses: Vec<InputAnalysis>,
    pub total_dead_bytes: usize,
    pub total_witness_bytes: usize,
    pub dead_code_ratio: f64,
    pub total_essential_bytes: usize,
    pub total_excess_bytes: usize,
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
            total_essential_bytes: 0,
            total_excess_bytes: 0,
        }
    }
}

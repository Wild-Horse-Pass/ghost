//! Ghost MPC - Rolling Multi-Party Computation Ceremony
//!
//! This crate implements a rolling MPC ceremony for generating trusted setup
//! parameters for Ghost's ZK proofs. Each new elder (up to 101) contributes
//! to the ceremony during registration.
//!
//! # Security Model
//!
//! The ceremony provides 1-of-N security: only ONE honest participant is needed
//! to ensure the toxic waste (tau, alpha, beta) is never recoverable. With 101
//! elders contributing, this provides extremely strong security guarantees.
//!
//! # Ceremony Lifecycle
//!
//! ```text
//! Elder 1  → Genesis params (founder contribution)
//! Elder 2  → Contributes → Parameters v2 active immediately
//! ...
//! Elder 100 → Contributes → Parameters v100 active immediately
//! Elder 101 → Contributes → OSSIFICATION (parameters permanent forever)
//! Elder 102+ → Normal registration, no MPC (ceremony closed)
//! ```
//!
//! # Integration with Elder Registration
//!
//! The MPC ceremony runs PARALLEL to elder registration:
//! 1. Candidate generates MPC contribution
//! 2. Candidate broadcasts contribution to network
//! 3. Elders verify contribution (>67% BFT approval required)
//! 4. On epoch transition, contribution is applied
//! 5. Parameters update immediately
//!
//! If MPC contribution fails, elder registration still proceeds - they just
//! don't contribute to the ceremony.
//!
//! # Ossification
//!
//! At elder 101, the ceremony ossifies permanently:
//! - No more contributions accepted
//! - Parameters become immutable
//! - New elders skip MPC step entirely

pub mod contribution;
pub mod errors;
pub mod manager;
pub mod params;
pub mod sync;

// Re-export main types
pub use contribution::{ContributionProof, MpcContribution};
pub use errors::{MpcError, MpcResult};
pub use manager::{CeremonyManager, CeremonyState};
pub use params::{MpcParameters, ParameterFiles};
pub use sync::ParameterSync;

/// Maximum number of elders that contribute to the ceremony.
/// After this, the ceremony ossifies and parameters are permanent.
pub const MAX_CEREMONY_CONTRIBUTORS: u32 = 101;

/// Chunk size for P2P parameter transfer (1MB)
pub const PARAM_CHUNK_SIZE: usize = 1024 * 1024;

/// BFT threshold for contribution approval (67%)
pub const MPC_BFT_THRESHOLD_PERCENT: u32 = 67;

# MPC Ceremony & Elder System

## Rolling Multi-Party Computation for ZK Parameter Generation

**Version 1.0** | Bitcoin Ghost Project

---

## 1. Overview

Bitcoin Ghost uses Groth16 zero-knowledge proofs for block validity and payout distribution proofs. Groth16 requires a trusted setup ceremony to generate proving and verifying keys. Ghost implements a **rolling MPC ceremony** where the first 101 nodes to contribute become **Elders**, earning +1 share in the 5-4-3-2-1 node capability system.

**Key properties:**
- Open participation: any node can contribute (first 101 get in)
- 1-of-N security: only one honest participant needed for soundness
- Genesis auto-approval: position 1 is auto-approved locally on the genesis node
- Subsequent positions require 67% BFT approval from existing MPC contributors
- Permanent, non-transferable positions (lost if elder goes offline >7 days)
- Parameters ossify permanently after 101 contributions
- MPC messages route through Noise encryption, never plaintext ZMQ

---

## 2. Ceremony Architecture

### 2.1 Rolling MPC

Unlike traditional ceremonies that happen once, Ghost's MPC rolls forward as contributors join:

```
Contributor 1:  Genesis parameters (auto-approved)
Contributor 2:  Applies randomness to contributor 1's output (BFT vote required)
Contributor 3:  Applies randomness to contributor 2's output (BFT vote required)
...
Contributor 101: Final contribution → parameters OSSIFY permanently
```

Each contribution cryptographically chains to the previous, forming a hash-linked sequence. Parameters improve with each contribution -- security only requires that **one** contributor honestly destroyed their toxic waste.

### 2.2 CeremonyManager

```rust
pub struct CeremonyManager {
    state: RwLock<CeremonyState>,
    files: ParameterFiles,
    block_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
    payout_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
}

pub struct CeremonyState {
    contribution_count: u32,       // 0-101
    current_params_hash: [u8; 32],
    is_ossified: bool,
    ceremony_id: [u8; 32],        // Unique per ceremony
}
```

The CeremonyManager tracks ceremony state, stores parameter files, and provides access to the current proving/verifying keys.

### 2.3 Contribution Structure

```rust
pub struct MpcContributionMessage {
    pub candidate: NodeId,           // Contributor's Ed25519 public key
    pub elder_position: u32,         // 1-101
    pub prev_params_hash: [u8; 32],  // Chain link to previous params
    pub new_params_hash: [u8; 32],   // Hash after this contribution
    pub contribution_proof: Vec<u8>, // Schnorr PoK for tau, alpha, beta
    pub signature: [u8; 64],         // Ed25519 signature
    pub timestamp: u64,
}
```

Signing domain: `MpcContribution/v1`

---

## 3. Contribution Flow

### 3.1 Node Startup

On startup, each node waits 15 seconds then checks whether it should contribute to the MPC ceremony:

```
Node starts
    ↓ (15 second delay)
Check: already contributed? → done
Check: ceremony ossified? → done
Check: ceremony full (101 contributors)? → done
    ↓
Sync existing contributors via /api/v1/mpc/contributors
    ↓
Generate contribution (apply randomness to current params)
    ↓
Broadcast MpcContribution message to peers
    ↓
Wait for BFT vote result
    ↓
If approved: position assigned, parameters updated
If rejected: contribution discarded
```

### 3.2 Genesis (Position 1)

The genesis node (started with `--genesis` flag) auto-approves its own contribution locally. This bootstraps the ceremony -- no BFT vote is possible when there are zero existing contributors.

Only one node in the network should run with `--genesis`. If multiple nodes run with this flag, they each independently generate genesis parameters and all attempt to claim position 1, causing UNIQUE constraint failures.

### 3.3 Positions 2-101

Every subsequent contribution requires BFT approval:

```
Candidate broadcasts MpcContribution
    ↓
Existing MPC contributors receive and validate:
    ├── Verify contribution signature
    ├── Verify prev_params_hash matches current params
    ├── Verify contribution proof (Schnorr PoK)
    └── Cast MpcVerificationVote (approve/reject)
    ↓
67% approval threshold reached → contribution applied
```

### 3.4 Verification Vote

```rust
pub struct MpcVerificationVoteMessage {
    pub contribution_hash: [u8; 32],
    pub voter: NodeId,
    pub approve: bool,
    pub rejection_reason: Option<String>,
    pub signature: [u8; 64],
    pub timestamp: u64,
}
```

Signing domain: `MpcVerificationVote/v1`

Only nodes that have already contributed to the MPC ceremony (existing elders) can vote on new contributions.

---

## 4. Ossification

### 4.1 Contributor Cap

The ceremony closes permanently after 101 contributions. This hard cap matches the elder limit and ensures a finite ceremony window.

### 4.2 Post-Ossification

Once ossified:
- No new contributions accepted
- Parameters are frozen permanently
- Proving and verifying keys derived from final parameters
- Elder positions are permanent (no new elders can be created)

---

## 5. Toxic Waste Security

Each contributor generates random values (tau, alpha, beta) used to transform the parameters. These values constitute "toxic waste" -- if any single contributor's values were known, that contributor's contribution would be compromised (but the ceremony remains secure if any *other* contributor was honest).

```rust
impl Drop for ToxicWaste {
    fn drop(&mut self) {
        self.tau_bytes.zeroize();     // Volatile write
        self.alpha_bytes.zeroize();
        self.beta_bytes.zeroize();
        compiler_fence(SeqCst);       // Memory barrier
    }
}
```

Toxic waste is:
- Zeroed with volatile writes (prevents compiler optimization)
- Protected by a memory barrier (prevents reordering)
- Never written to disk
- Generated fresh for each contribution

---

## 6. Parameter Files

Parameters are stored in the node's data directory:

```
~/.ghost/mpc_params/
├── block_params_v0.bin        # Genesis parameters
├── block_params_v1.bin        # After elder 2
├── ...
├── block_params_v100.bin      # After elder 101 (ossified)
├── block_params_current.bin   # Symlink to latest
├── payout_params_v*.bin       # Same versioning for payout circuit
├── block_vk.bin               # Block verifying key
└── payout_vk.bin              # Payout verifying key
```

Parameter files use magic markers and version gaps to detect corruption. Each version is a complete parameter set (~200MB), transferred between peers in 1MB chunks via `MpcParametersRequest`/`MpcParametersResponse` messages.

---

## 7. P2P Communication

### 7.1 Message Types

| Message | Purpose | Port |
|---------|---------|------|
| `MpcContribution` (MPC-C1) | New contribution broadcast | 8560 (Elder management) |
| `MpcVerificationVote` (MPC-C2) | Vote on contribution | 8560 |
| `MpcParametersRequest` (MPC-C3) | Request parameter files | 8560 |
| `MpcParametersResponse` (MPC-C4) | Chunked parameter transfer | 8560 |

### 7.2 Noise Encryption Requirement

All MPC messages **must** route through Noise Protocol encryption, not plaintext ZMQ:

```
MPC message → mesh.send_to_peer()
    ↓
should_use_noise() → true for MPC messages
    ↓
send_encrypted() → Noise_XX channel (port 8563)
```

This prevents eavesdropping on contribution proofs and vote messages. The `broadcast_sync()` method (which sends via ZMQ) must **never** be used for MPC messages.

### 7.3 P2P Sync

On startup, nodes sync existing contributor lists from peers:

```
GET /api/v1/mpc/contributors

Response:
[
    { "position": 1, "node_id": "abc...", "params_hash": "def...", "timestamp": 1234 },
    { "position": 2, "node_id": "ghi...", "params_hash": "jkl...", "timestamp": 1235 },
    ...
]
```

This allows new nodes to discover the current ceremony state before deciding whether to contribute.

---

## 8. Elder Status

### 8.1 Definition

An Elder is any node that successfully contributed to the MPC ceremony (positions 1-101). Elder status is determined entirely by the `mpc_contributions` database table.

### 8.2 Share Bonus

Elder status grants +1 share in the 5-4-3-2-1 system:

| Capability | Shares |
|------------|--------|
| Archive Mode | +5 |
| Ghost Pay | +4 |
| Public Mining | +3 |
| Bitcoin Pure | +2 |
| **Elder Status** | **+1** |
| **Maximum** | **15** |

A node with all capabilities including Elder status earns 15/15 shares. Without Elder status, maximum is 14/15.

### 8.3 Voting Power

Elder status does **not** grant special voting power. All nodes participate equally in BFT consensus. The only context where elder status matters for voting is MPC contribution approval -- only existing MPC contributors can vote on new contributions.

### 8.4 Permanence and Revocation

- Elder positions are **permanent** and **non-transferable**
- If an elder goes offline for >7 continuous days, a 67% BFT vote can revoke their status
- **Burned slots**: revoked elder positions are never reassigned
- The elder count can only decrease (through revocation), never increase beyond the ceremony's final count

### 8.5 Implementation

```sql
-- Elder status check
SELECT position FROM mpc_contributions
WHERE node_id = ? AND position BETWEEN 1 AND 101;

-- Elder count
SELECT COUNT(*) FROM mpc_contributions WHERE position BETWEEN 1 AND 101;
```

On startup, `ghost-pool` checks the `mpc_contributions` table to set `capabilities.elder_status` in the node's health ping broadcast.

---

## 9. Groth16 Proof Types

The MPC ceremony generates parameters for two circuit types:

### 9.1 BlockCircuit

Proves block validity (state transitions):

```rust
pub struct BlockCircuit<F: PrimeField> {
    payments: Vec<PaymentCircuit<F>>,
    state_transitions: Vec<PaymentStateTransitionCircuit<F>>,
    prev_state_root: Option<F>,
    new_state_root: Option<F>,
}
```

Public inputs: `prev_root`, `new_root`
Proof size: 192 bytes (A: 48 G1, B: 96 G2, C: 48 G1)

### 9.2 PayoutCircuit

Proves payout distribution validity:
- Sum preservation: miners + nodes + treasury = total
- All amounts fit in 64 bits
- Metadata commitment (epoch, counts)

### 9.3 Verification

```rust
pub struct BlockVerifier {
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
}
```

- With verifying key: cryptographic verification (~10ms)
- Without verifying key: fail closed (reject all proofs in production)
- Subgroup checks on deserialization prevent invalid curve attacks

---

## 10. Operational Guide

### 10.1 Genesis Node Setup

```bash
# Only ONE node runs with --genesis
ghost-pool --config /etc/ghost/pool.toml --genesis

# Wait 60 seconds for genesis params to initialize
# Then start remaining nodes WITHOUT --genesis
ghost-pool --config /etc/ghost/pool.toml
```

### 10.2 MPC State Reset

To reset MPC state (e.g., for testnet redeployment):

```bash
sudo systemctl stop ghost-pool
sudo rm /home/ghost/.ghost/ghost.db
sudo rm -rf /home/ghost/.ghost/mpc_params/
sudo systemctl start ghost-pool
```

### 10.3 Monitoring

```bash
# Check elder status
sqlite3 /home/ghost/.ghost/ghost.db \
  "SELECT position, hex(node_id), timestamp FROM mpc_contributions ORDER BY position;"

# Check ceremony state
curl http://localhost:8800/api/v1/mpc/contributors | jq length
```

---

## 11. Source Files

| File | Purpose |
|------|---------|
| `bins/ghost-pool/src/mpc_handler.rs` | MPC message handling, BFT voting, contribution processing |
| `bins/ghost-pool/src/main.rs:645-661` | Elder status check on startup |
| `bins/ghost-pool/src/main.rs:1192-1276` | Auto-contribution task (15s delay) |
| `crates/ghost-consensus/src/mesh.rs` | Noise encryption routing for MPC messages |
| `crates/ghost-consensus/src/message.rs` | MPC message structs (MPC-C1 through MPC-C4) |
| `crates/ghost-zkp/src/ceremony.rs` | CeremonyManager, parameter generation |
| `crates/ghost-zkp/src/block.rs` | BlockCircuit definition |
| `crates/ghost-zkp/src/payout.rs` | PayoutCircuit definition |
| `crates/ghost-zkp/src/verifier.rs` | BlockVerifier, proof verification |
| `crates/ghost-storage/src/queries.rs` | `is_mpc_elder()`, `get_mpc_elder_position()`, `get_mpc_elder_count()` |

---

*End of MPC Ceremony & Elder System Specification*

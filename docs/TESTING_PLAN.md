# Bitcoin Ghost v1.4 - Pre-Mainnet Testing Plan

## Overview

This document outlines all testing required before mainnet deployment. Tests are organized by priority and dependency order.

---

## Test Environment

- **Network**: Bitcoin Signet
- **Nodes**: 4 VMs (London, New York, Singapore, Sydney)
- **Ghost Core**: Running on each VM with signet chain

| VM | IP | Role |
|----|-----|------|
| VM1 | 83.136.251.162 | Primary test node |
| VM2 | 85.9.198.212 | Consensus peer |
| VM3 | 213.163.207.46 | Consensus peer |
| VM4 | 95.111.221.169 | Consensus peer |

---

## Phase 1: Node Connectivity (Priority: CRITICAL)

### 1.1 Mesh Network Connectivity
**Goal**: Verify all 4 nodes can communicate via P2P mesh

**Test Steps**:
1. Check each node's peer count via API
2. Verify bidirectional connectivity (A→B and B→A)
3. Send test message through mesh, verify propagation

**Commands**:
```bash
# Check peer count on each node
for vm in 83.136.251.162 85.9.198.212 213.163.207.46 95.111.221.169; do
  echo "=== $vm ==="
  curl -s http://$vm:8080/api/v1/mesh/status | jq '{peer_count, consensus_status}'
done
```

**Expected**: Each node shows peer_count >= 3, consensus_status = "active"

**Current Issue**: Nodes show peer_count = 0 (isolated). Need to configure peer discovery or static peers.

### 1.2 Peer Discovery Configuration
**Goal**: Configure nodes to discover each other

**Options**:
1. Static peer list in config
2. DNS seed
3. Manual peer addition via API/CLI

**Config Change** (`/etc/ghost/pool.toml`):
```toml
[network]
bootstrap_peers = [
  "83.136.251.162:8555",
  "85.9.198.212:8555",
  "213.163.207.46:8555",
  "95.111.221.169:8555"
]
```

---

## Phase 2: Mining Integration (Priority: CRITICAL)

### 2.1 Stratum Connection Test
**Goal**: Connect a miner and verify basic handshake

**Test Steps**:
1. Use a CPU miner (e.g., cpuminer) to connect to Stratum port
2. Verify connection appears in logs
3. Verify miner shows in API

**Commands**:
```bash
# On test machine with cpuminer (SV1 port 3333)
cpuminer -a sha256d -o stratum+tcp://83.136.251.162:3333 -u testminer -p x

# Check miner connected
curl -s http://83.136.251.162:8080/api/v1/mining/miners | jq .
```

**Expected**: Miner count increases, miner appears in list

### 2.2 Share Submission Test
**Goal**: Verify shares are submitted and counted correctly

**Test Steps**:
1. Connect miner at low difficulty
2. Wait for share submissions
3. Verify shares appear in round accounting
4. Check WebSocket broadcasts ShareSubmitted events

**Commands**:
```bash
# Watch WebSocket for share events
websocat ws://83.136.251.162:8080/ws | grep ShareSubmitted
```

**Expected**: ShareSubmitted events with valid=true

### 2.3 Vardiff Test
**Goal**: Verify variable difficulty adjusts based on miner hashrate

**Test Steps**:
1. Connect miner, note initial difficulty
2. Wait for vardiff adjustment (target: 10s between shares)
3. Verify difficulty increased/decreased appropriately

**Expected**: Difficulty adjusts to maintain ~10s share interval

### 2.4 Round Management Test
**Goal**: Verify rounds start/end correctly on new blocks

**Test Steps**:
1. Note current round_id
2. Wait for new signet block (or use regtest to generate)
3. Verify round_id increments
4. Verify previous round's shares are finalized

**Commands**:
```bash
# Watch for round changes (response is wrapped in {signed, response})
watch -n5 'curl -s http://83.136.251.162:8080/health | jq ".response | {round_id, block_height}"'
```

---

## Phase 3: Consensus Testing (Priority: CRITICAL)

### 3.1 Vote Propagation Test
**Goal**: Verify votes propagate across all nodes

**Test Steps**:
1. Trigger a payout proposal on VM1
2. Check if VM2, VM3, VM4 receive the proposal
3. Verify each node votes
4. Check vote counts on each node

**Expected**: All 4 nodes see proposal, 4/4 votes recorded

### 3.2 BFT Threshold Test (67%)
**Goal**: Verify consensus requires 67% approval

**Test Steps**:
1. With 4 nodes, need 3 approvals (75% > 67%)
2. Simulate 2 approvals, 2 rejections - should NOT reach consensus
3. Simulate 3 approvals, 1 rejection - SHOULD reach consensus

### 3.3 Consensus Timeout Test
**Goal**: Verify proposals timeout correctly if votes not received

**Test Steps**:
1. Stop 2 nodes
2. Trigger proposal on remaining 2 nodes
3. Verify timeout after consensus_timeout_secs
4. Verify proposal marked as TimedOut

### 3.4 Network Partition Test
**Goal**: Verify behavior when network splits

**Test Steps**:
1. Partition: VM1+VM2 vs VM3+VM4
2. Trigger proposals on each partition
3. Neither partition should reach consensus (only 50%)
4. Rejoin network, verify recovery

---

## Phase 4: Ghost Pay L2 (Priority: HIGH)

### 4.1 Ghost Key Generation
**Goal**: Verify Ghost ID generation works

**Test Steps**:
1. Generate new Ghost Key via CLI
2. Verify ghost1... address format
3. Verify key can be imported to wallet

**Commands**:
```bash
ghost-cli key generate
ghost-cli key show
```

### 4.2 Ghost Lock Creation
**Goal**: Create a Ghost Lock state channel

**Test Steps**:
1. Create lock via API with denomination (e.g., 10000 sats)
2. Verify lock appears in database
3. Verify lock state = Created

**Commands**:
```bash
curl -X POST http://83.136.251.162:8080/api/ghost-pay/lock \
  -H "Content-Type: application/json" \
  -d '{"ghost_id": "ghost1...", "denomination": "small", "timelock_tier": 1}'
```

### 4.3 Ghost Lock Funding
**Goal**: Fund a Ghost Lock on L1

**Test Steps**:
1. Get funding address for lock
2. Send signet BTC to funding address
3. Wait for confirmation
4. Verify lock state = Active

### 4.4 Wraith Session Test
**Goal**: Complete a Wraith mixing session

**Test Steps**:
1. Create 2+ Ghost Locks with same denomination
2. Register both for Wraith session
3. Wait for registration phase to complete
4. Verify Phase 1 (split) transaction created
5. Verify Phase 2 (merge) transaction created
6. Verify final outputs are shuffled

**Minimum Participants**: 2 (for testing), production requires more

### 4.5 L2 Payment Test
**Goal**: Send instant payment via L2

**Test Steps**:
1. Two users with funded Ghost Locks
2. User A sends L2 payment to User B
3. Verify instant confirmation
4. Verify balance updates on both sides

### 4.6 L1 Settlement Test
**Goal**: Withdraw from L2 to L1

**Test Steps**:
1. Request withdrawal from Ghost Lock
2. Wait for reconciliation batch
3. Verify L1 transaction created
4. Verify funds received at destination address

---

## Phase 5: Payout Testing (Priority: HIGH)

### 5.1 Payout Calculation Test
**Goal**: Verify payout distribution is correct

**Test Steps**:
1. Simulate round with known shares:
   - Miner A: 60% of work
   - Miner B: 40% of work
2. Simulate block found (6.25 BTC reward on mainnet)
3. Verify payout proposal:
   - Treasury: 1% (0.0625 BTC)
   - Node pool: Based on capability shares
   - Miners: Proportional to work

### 5.2 Multi-Node Payout Consensus
**Goal**: Verify all nodes agree on payout amounts

**Test Steps**:
1. Complete round with shares from multiple miners
2. Trigger payout proposal
3. Verify all nodes calculate identical payout amounts
4. Verify consensus reached
5. Verify coinbase includes correct outputs

### 5.3 Node Pool Distribution Test
**Goal**: Verify 5-4-3-2-1 share system works

**Setup**: 4 nodes with varying capabilities
- Node 1: All capabilities (15 shares)
- Node 2: No elder (14 shares)
- Node 3: No GhostPay (11 shares)
- Node 4: Minimal (5 shares)

**Expected Distribution**: Proportional to shares (15+14+11+5 = 45 total)

---

## Phase 6: BUDS Policy Testing (Priority: MEDIUM)

### 6.1 Policy Enforcement Test
**Goal**: Verify transactions are filtered by policy

**Test Steps**:
1. Create transaction with inscription (T3 tier)
2. Submit to mempool
3. Request block template
4. Verify transaction excluded from template (bitcoin_pure policy)

### 6.2 Policy Profile Switching
**Goal**: Verify policy profiles can be changed

**Test Steps**:
1. Start with bitcoin_pure profile
2. Switch to permissive profile via API
3. Verify previously-filtered transaction now included

---

## Phase 7: Archive Mode Testing (Priority: MEDIUM)

### 7.1 Historical Block Query
**Goal**: Verify can retrieve old blocks

**Test Steps**:
1. Query block at height 1000
2. Verify block data returned
3. Verify merkle proof valid

**Commands**:
```bash
curl http://83.136.251.162:8080/verify/archive?block=<hash_at_height_1000>
```

### 7.2 Historical Transaction Query
**Goal**: Verify can retrieve old transactions

**Test Steps**:
1. Query known historical txid
2. Verify transaction data returned
3. Verify inclusion proof valid

---

## Phase 8: Failure & Recovery Testing (Priority: MEDIUM)

### 8.1 Node Failure Recovery
**Goal**: Verify system continues with N-1 nodes

**Test Steps**:
1. Stop VM1
2. Verify VM2, VM3, VM4 continue operating
3. Verify consensus still works (3/4 = 75% > 67%)
4. Restart VM1, verify rejoins mesh

### 8.2 Ghost Core Disconnect
**Goal**: Verify graceful degradation when RPC fails

**Test Steps**:
1. Stop Ghost Core on VM1
2. Verify ghost-pool continues running
3. Verify API returns appropriate errors
4. Restart Ghost Core, verify reconnection

### 8.3 Database Recovery
**Goal**: Verify database can be restored from backup

**Test Steps**:
1. Create database backup
2. Corrupt/delete database
3. Restore from backup
4. Verify all data intact

---

## Phase 9: Performance Testing (Priority: LOW)

### 9.1 High Miner Load
**Goal**: Verify system handles many concurrent miners

**Test Steps**:
1. Connect 100+ simulated miners
2. Monitor CPU/memory usage
3. Verify share processing latency
4. Verify no dropped connections

### 9.2 High Transaction Volume
**Goal**: Verify mempool handling under load

**Test Steps**:
1. Flood mempool with transactions
2. Verify block templates generated correctly
3. Verify no memory leaks

---

## Test Execution Checklist

### Pre-Test Setup
- [ ] All 4 VMs running latest ghost-pool binary
- [ ] Ghost Core synced on all VMs
- [ ] Database backed up
- [ ] Monitoring/logging enabled

### Phase 1: Connectivity
- [ ] 1.1 Mesh network - all nodes connected
- [ ] 1.2 Peer discovery configured

### Phase 2: Mining
- [ ] 2.1 Stratum connection works
- [ ] 2.2 Share submission works
- [ ] 2.3 Vardiff adjusts correctly
- [ ] 2.4 Round management works

### Phase 3: Consensus
- [ ] 3.1 Votes propagate to all nodes
- [ ] 3.2 67% threshold enforced
- [ ] 3.3 Timeout works correctly
- [ ] 3.4 Partition recovery works

### Phase 4: Ghost Pay
- [ ] 4.1 Ghost Key generation works
- [ ] 4.2 Ghost Lock creation works
- [ ] 4.3 Ghost Lock funding works
- [ ] 4.4 Wraith session completes
- [ ] 4.5 L2 payments work
- [ ] 4.6 L1 settlement works

### Phase 5: Payouts
- [ ] 5.1 Payout calculation correct
- [ ] 5.2 Multi-node consensus on payouts
- [ ] 5.3 Node pool distribution correct

### Phase 6: BUDS
- [ ] 6.1 Policy enforcement works
- [ ] 6.2 Policy switching works

### Phase 7: Archive
- [ ] 7.1 Historical blocks queryable
- [ ] 7.2 Historical transactions queryable

### Phase 8: Failure Recovery
- [ ] 8.1 N-1 node operation works
- [ ] 8.2 Ghost Core disconnect handled
- [ ] 8.3 Database recovery works

### Phase 9: Performance
- [ ] 9.1 High miner load handled
- [ ] 9.2 High tx volume handled

---

## Success Criteria for Mainnet

All of the following must pass:
1. ✅ 4+ nodes maintain mesh connectivity for 24+ hours
2. ✅ Mining works with real miner for 24+ hours
3. ✅ Consensus reaches agreement on 10+ payout proposals
4. ✅ Ghost Pay E2E flow completes successfully
5. ✅ No data loss after simulated failures
6. ✅ All unit and integration tests pass

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Consensus deadlock | Timeout mechanism, manual intervention API |
| Payout miscalculation | Multi-node verification, logging |
| Ghost Core disconnect | Graceful degradation, auto-reconnect |
| Database corruption | Regular backups, WAL mode |
| Network partition | Quorum requirements, partition detection |

---

## Next Steps

1. **Immediate**: Fix mesh connectivity (nodes currently isolated)
2. **This week**: Complete Phase 1-3 testing
3. **Next week**: Complete Phase 4-5 testing
4. **Before mainnet**: Complete all phases, 24h stability test

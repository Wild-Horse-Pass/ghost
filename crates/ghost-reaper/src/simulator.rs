use std::collections::BTreeSet;

use crate::flow::{find_else_endif, parse_ops, ScriptOp};

// ── Safety Limits ────────────────────────────────────────────────────────────

const MAX_STACK_DEPTH: usize = 1000;
const MAX_IF_DEPTH: usize = 100;
const MAX_BRANCH_PATHS: usize = 64;

// ── Core Data Structures ─────────────────────────────────────────────────────

/// Tracks which witness indices contributed to a stack value.
#[derive(Clone, Debug)]
struct Taint(BTreeSet<u16>);

impl Taint {
    /// Taint originating from a witness item at `index`.
    fn witness(index: u16) -> Self {
        let mut set = BTreeSet::new();
        set.insert(index);
        Self(set)
    }

    /// Taint originating from the script itself (no witness contribution).
    fn script() -> Self {
        Self(BTreeSet::new())
    }

    /// Merge two taints (union of witness indices).
    fn merge(&self, other: &Taint) -> Taint {
        Taint(self.0.union(&other.0).copied().collect())
    }

    /// Whether this taint includes any witness-derived data.
    fn has_witness(&self) -> bool {
        !self.0.is_empty()
    }
}

/// A simulated stack item — we only track taint, not actual values.
#[derive(Clone, Debug)]
struct SimItem {
    taint: Taint,
}

/// Simulated stack (main or alt).
#[derive(Clone, Debug)]
struct SimStack {
    items: Vec<SimItem>,
}

impl SimStack {
    fn new() -> Self {
        Self { items: Vec::new() }
    }

    fn push(&mut self, item: SimItem) -> bool {
        if self.items.len() >= MAX_STACK_DEPTH {
            return false;
        }
        self.items.push(item);
        true
    }

    fn pop(&mut self) -> Option<SimItem> {
        self.items.pop()
    }

    fn peek(&self) -> Option<&SimItem> {
        self.items.last()
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// ── Simulator State ──────────────────────────────────────────────────────────

struct SimState {
    stack: SimStack,
    alt_stack: SimStack,
    essential: BTreeSet<u16>,
    branch_count: usize,
}

impl SimState {
    fn new() -> Self {
        Self {
            stack: SimStack::new(),
            alt_stack: SimStack::new(),
            essential: BTreeSet::new(),
            branch_count: 0,
        }
    }

    /// Mark all witness indices in a taint as essential.
    fn mark_essential(&mut self, taint: &Taint) {
        for &idx in &taint.0 {
            self.essential.insert(idx);
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Simulate script execution tracking which witness items are essential.
///
/// Returns `Some(essential_indices)` on success, `None` if the simulator
/// cannot handle this script (caller should fall back to `count_stack_consumption()`).
///
/// `witness_item_count` is the number of stack witness items (excluding
/// the script and control block for tapscript, or the witnessScript for P2WSH).
pub(crate) fn simulate_essential_witnesses(
    witness_item_count: usize,
    script_bytes: &[u8],
    is_tapscript: bool,
) -> Option<BTreeSet<u16>> {
    if script_bytes.is_empty() {
        return Some(BTreeSet::new());
    }

    let ops = parse_ops(script_bytes);
    if ops.is_empty() {
        return Some(BTreeSet::new());
    }

    let mut state = SimState::new();

    // Push witness items onto the stack (bottom = item 0, top = item N-1).
    // In Bitcoin, witness items are pushed in order: item 0 is deepest on the stack.
    for i in 0..witness_item_count {
        if !state.stack.push(SimItem {
            taint: Taint::witness(i as u16),
        }) {
            return None;
        }
    }

    simulate_range(&ops, script_bytes, 0, ops.len(), is_tapscript, &mut state)?;

    Some(state.essential)
}

// ── Core Simulation ──────────────────────────────────────────────────────────

/// Simulate a range of opcodes [start..end) on the given state.
/// Returns `Some(())` on success, `None` to bail.
fn simulate_range(
    ops: &[ScriptOp],
    script: &[u8],
    start: usize,
    end: usize,
    is_tapscript: bool,
    state: &mut SimState,
) -> Option<()> {
    let mut i = start;

    while i < end {
        let op = &ops[i];
        match op.opcode {
            // ── Push opcodes ─────────────────────────────────────────────
            // OP_0
            0x00 => {
                state.stack.push(SimItem {
                    taint: Taint::script(),
                });
                i += 1;
            }
            // OP_PUSHBYTES_1..75, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4
            0x01..=0x4e => {
                state.stack.push(SimItem {
                    taint: Taint::script(),
                });
                i += 1;
            }
            // OP_1NEGATE
            0x4f => {
                state.stack.push(SimItem {
                    taint: Taint::script(),
                });
                i += 1;
            }
            // OP_1..OP_16
            0x51..=0x60 => {
                state.stack.push(SimItem {
                    taint: Taint::script(),
                });
                i += 1;
            }

            // ── Stack manipulation ───────────────────────────────────────

            // OP_DUP
            0x76 => {
                let top = state.stack.peek()?.clone();
                state.stack.push(top);
                i += 1;
            }
            // OP_2DUP
            0x6e => {
                let len = state.stack.len();
                if len < 2 {
                    return None;
                }
                let a = state.stack.items[len - 2].clone();
                let b = state.stack.items[len - 1].clone();
                state.stack.push(a);
                state.stack.push(b);
                i += 1;
            }
            // OP_3DUP
            0x6f => {
                let len = state.stack.len();
                if len < 3 {
                    return None;
                }
                let a = state.stack.items[len - 3].clone();
                let b = state.stack.items[len - 2].clone();
                let c = state.stack.items[len - 1].clone();
                state.stack.push(a);
                state.stack.push(b);
                state.stack.push(c);
                i += 1;
            }
            // OP_DROP
            0x75 => {
                state.stack.pop()?;
                i += 1;
            }
            // OP_2DROP
            0x6d => {
                state.stack.pop()?;
                state.stack.pop()?;
                i += 1;
            }
            // OP_NIP — remove second-to-top
            0x77 => {
                if state.stack.len() < 2 {
                    return None;
                }
                let len = state.stack.len();
                state.stack.items.remove(len - 2);
                i += 1;
            }
            // OP_SWAP
            0x7c => {
                let len = state.stack.len();
                if len < 2 {
                    return None;
                }
                state.stack.items.swap(len - 2, len - 1);
                i += 1;
            }
            // OP_ROT — move 3rd-to-top to top
            0x7b => {
                let len = state.stack.len();
                if len < 3 {
                    return None;
                }
                let item = state.stack.items.remove(len - 3);
                state.stack.items.push(item);
                i += 1;
            }
            // OP_OVER — copy second-to-top to top
            0x78 => {
                let len = state.stack.len();
                if len < 2 {
                    return None;
                }
                let item = state.stack.items[len - 2].clone();
                state.stack.push(item);
                i += 1;
            }
            // OP_TUCK — insert top before second-to-top
            0x7d => {
                let len = state.stack.len();
                if len < 2 {
                    return None;
                }
                let top = state.stack.items[len - 1].clone();
                state.stack.items.insert(len - 2, top);
                i += 1;
            }
            // OP_2OVER
            0x70 => {
                let len = state.stack.len();
                if len < 4 {
                    return None;
                }
                let a = state.stack.items[len - 4].clone();
                let b = state.stack.items[len - 3].clone();
                state.stack.push(a);
                state.stack.push(b);
                i += 1;
            }
            // OP_2ROT
            0x71 => {
                let len = state.stack.len();
                if len < 6 {
                    return None;
                }
                let a = state.stack.items.remove(len - 6);
                let b = state.stack.items.remove(len - 6); // shifted after first remove
                state.stack.items.push(a);
                state.stack.items.push(b);
                i += 1;
            }
            // OP_2SWAP
            0x72 => {
                let len = state.stack.len();
                if len < 4 {
                    return None;
                }
                state.stack.items.swap(len - 4, len - 2);
                state.stack.items.swap(len - 3, len - 1);
                i += 1;
            }
            // OP_PICK — copy item at depth N to top (bail if N is witness-tainted)
            0x79 => {
                let top = state.stack.pop()?;
                if top.taint.has_witness() {
                    return None; // can't determine index statically
                }
                // Without knowing the actual value, bail
                return None;
            }
            // OP_ROLL — move item at depth N to top (bail if N is witness-tainted)
            0x7a => {
                let top = state.stack.pop()?;
                if top.taint.has_witness() {
                    return None;
                }
                return None;
            }
            // OP_TOALTSTACK
            0x6b => {
                let item = state.stack.pop()?;
                state.alt_stack.push(item);
                i += 1;
            }
            // OP_FROMALTSTACK
            0x6c => {
                let item = state.alt_stack.pop()?;
                state.stack.push(item);
                i += 1;
            }
            // OP_SIZE — push size, keep original
            0x82 => {
                if state.stack.is_empty() {
                    return None;
                }
                state.stack.push(SimItem {
                    taint: Taint::script(),
                });
                i += 1;
            }
            // OP_DEPTH
            0x74 => {
                state.stack.push(SimItem {
                    taint: Taint::script(),
                });
                i += 1;
            }
            // OP_IFDUP — bail (runtime truthiness unknown)
            0x73 => return None,

            // ── Arithmetic / logic ───────────────────────────────────────

            // Unary: OP_1ADD(0x8b), OP_1SUB(0x8c), OP_NEGATE(0x8f),
            //        OP_ABS(0x90), OP_NOT(0x91), OP_0NOTEQUAL(0x92)
            0x8b | 0x8c | 0x8f | 0x90 | 0x91 | 0x92 => {
                let a = state.stack.pop()?;
                state.stack.push(SimItem { taint: a.taint });
                i += 1;
            }
            // Binary: OP_ADD(0x93), OP_SUB(0x94), OP_BOOLAND(0x9a),
            //         OP_BOOLOR(0x9b), OP_NUMEQUAL(0x9c), OP_NUMNOTEQUAL(0x9e),
            //         OP_LESSTHAN(0x9f), OP_GREATERTHAN(0xa0),
            //         OP_LESSTHANOREQUAL(0xa1), OP_GREATERTHANOREQUAL(0xa2),
            //         OP_MIN(0xa3), OP_MAX(0xa4)
            0x93 | 0x94 | 0x9a | 0x9b | 0x9c | 0x9e | 0x9f | 0xa0 | 0xa1 | 0xa2 | 0xa3 | 0xa4 => {
                let b = state.stack.pop()?;
                let a = state.stack.pop()?;
                state.stack.push(SimItem {
                    taint: a.taint.merge(&b.taint),
                });
                i += 1;
            }
            // OP_WITHIN (ternary)
            0xa5 => {
                let max = state.stack.pop()?;
                let min = state.stack.pop()?;
                let x = state.stack.pop()?;
                let merged = x.taint.merge(&min.taint).merge(&max.taint);
                state.stack.push(SimItem { taint: merged });
                i += 1;
            }
            // OP_NUMEQUALVERIFY — binary compare + verify
            0x9d => {
                let b = state.stack.pop()?;
                let a = state.stack.pop()?;
                let merged = a.taint.merge(&b.taint);
                if merged.has_witness() {
                    state.mark_essential(&merged);
                }
                i += 1;
            }
            // OP_VERIFY — pop + verify
            0x69 => {
                let item = state.stack.pop()?;
                if item.taint.has_witness() {
                    state.mark_essential(&item.taint);
                }
                i += 1;
            }

            // ── Hash opcodes ─────────────────────────────────────────────
            // SHA256(0xa7), HASH160(0xa8), HASH256(0xa9), RIPEMD160(0xaa)
            // Propagate taint through the hash: the result carries the input's taint.
            0xa7..=0xaa => {
                let item = state.stack.pop()?;
                state.stack.push(SimItem { taint: item.taint });
                i += 1;
            }

            // ── Verification opcodes ─────────────────────────────────────

            // OP_CHECKSIG(0xac), OP_CHECKSIGVERIFY(0xad)
            0xac | 0xad => {
                let pubkey = state.stack.pop()?;
                let sig = state.stack.pop()?;
                // Mark the signature's witness taint as essential
                state.mark_essential(&sig.taint);
                // Pubkey taint is also essential if witness-derived
                state.mark_essential(&pubkey.taint);
                if op.opcode == 0xac {
                    // CHECKSIG pushes a boolean result
                    state.stack.push(SimItem {
                        taint: sig.taint.merge(&pubkey.taint),
                    });
                }
                // CHECKSIGVERIFY pushes nothing (verifies in-place)
                i += 1;
            }

            // OP_CHECKSIGADD (0xba) — tapscript only
            0xba if is_tapscript => {
                let pubkey = state.stack.pop()?;
                let counter = state.stack.pop()?;
                let sig = state.stack.pop()?;
                state.mark_essential(&sig.taint);
                state.mark_essential(&pubkey.taint);
                // Pushes updated counter (merge all taints)
                state.stack.push(SimItem {
                    taint: sig.taint.merge(&counter.taint).merge(&pubkey.taint),
                });
                i += 1;
            }

            // OP_CHECKMULTISIG(0xae), OP_CHECKMULTISIGVERIFY(0xaf)
            0xae | 0xaf => {
                // Pop N (number of pubkeys)
                let n_item = state.stack.pop()?;
                // We need to know N — if it's witness-tainted, bail
                if n_item.taint.has_witness() {
                    return None;
                }
                // Without knowing actual value, we need the script constant.
                // Look back in ops to find the OP_N that was just pushed.
                let n = find_preceding_small_int(ops, i, script)?;

                // Pop N pubkeys
                let mut all_taint = Taint::script();
                for _ in 0..n {
                    let pk = state.stack.pop()?;
                    state.mark_essential(&pk.taint);
                    all_taint = all_taint.merge(&pk.taint);
                }

                // Pop M (number of sigs)
                let m_item = state.stack.pop()?;
                if m_item.taint.has_witness() {
                    return None;
                }
                let m = find_second_preceding_small_int(ops, i, n, script)?;

                // Pop M signatures + 1 dummy
                for _ in 0..m {
                    let sig = state.stack.pop()?;
                    state.mark_essential(&sig.taint);
                    all_taint = all_taint.merge(&sig.taint);
                }
                // Dummy byte (Bitcoin consensus bug)
                let dummy = state.stack.pop()?;
                state.mark_essential(&dummy.taint);

                if op.opcode == 0xae {
                    state.stack.push(SimItem { taint: all_taint });
                }
                i += 1;
            }

            // OP_EQUAL(0x87), OP_EQUALVERIFY(0x88)
            0x87 | 0x88 => {
                let b = state.stack.pop()?;
                let a = state.stack.pop()?;
                let merged = a.taint.merge(&b.taint);
                // If either operand has witness taint, mark as essential
                if merged.has_witness() {
                    state.mark_essential(&merged);
                }
                if op.opcode == 0x87 {
                    state.stack.push(SimItem { taint: merged });
                }
                i += 1;
            }

            // OP_CHECKLOCKTIMEVERIFY(0xb1), OP_CHECKSEQUENCEVERIFY(0xb2)
            // Peek at top (don't pop) — mark essential if witness-derived
            0xb1 | 0xb2 => {
                let taint = state.stack.peek()?.taint.clone();
                if taint.has_witness() {
                    state.mark_essential(&taint);
                }
                i += 1;
            }

            // ── Control flow ─────────────────────────────────────────────

            // OP_IF(0x63), OP_NOTIF(0x64)
            0x63 | 0x64 => {
                state.branch_count += 1;
                if state.branch_count > MAX_BRANCH_PATHS {
                    return None;
                }

                // Pop the condition
                let cond = state.stack.pop()?;
                // Condition is essential — execution path depends on it
                if cond.taint.has_witness() {
                    state.mark_essential(&cond.taint);
                }

                let (else_idx, endif_idx) = find_else_endif(ops, i);
                let endif_idx = endif_idx?;

                // Count IF depth to enforce limit
                let if_depth = count_if_depth(ops, i);
                if if_depth > MAX_IF_DEPTH {
                    return None;
                }

                if let Some(else_idx) = else_idx {
                    // IF <if_body> ELSE <else_body> ENDIF
                    let if_body_start = i + 1;
                    let if_body_end = else_idx;
                    let else_body_start = else_idx + 1;
                    let else_body_end = endif_idx;

                    // Clone state for the ELSE branch
                    let mut else_state = SimState {
                        stack: state.stack.clone(),
                        alt_stack: state.alt_stack.clone(),
                        essential: state.essential.clone(),
                        branch_count: state.branch_count,
                    };

                    // Simulate IF branch
                    simulate_range(ops, script, if_body_start, if_body_end, is_tapscript, state)?;
                    // Simulate ELSE branch
                    simulate_range(
                        ops,
                        script,
                        else_body_start,
                        else_body_end,
                        is_tapscript,
                        &mut else_state,
                    )?;

                    // Different stack depths → bail
                    if state.stack.len() != else_state.stack.len() {
                        return None;
                    }

                    // Union essential sets
                    for idx in else_state.essential {
                        state.essential.insert(idx);
                    }

                    // Merge stack taints (union at each position)
                    for (j, else_item) in else_state.stack.items.into_iter().enumerate() {
                        state.stack.items[j].taint =
                            state.stack.items[j].taint.merge(&else_item.taint);
                    }

                    state.branch_count = state.branch_count.max(else_state.branch_count);
                } else {
                    // IF <if_body> ENDIF (no ELSE)
                    let if_body_start = i + 1;
                    let if_body_end = endif_idx;

                    // Clone state for the "skip" branch (IF not taken)
                    let skip_state_stack = state.stack.clone();
                    let _skip_state_alt = state.alt_stack.clone();
                    let skip_state_essential = state.essential.clone();

                    // Simulate IF branch
                    simulate_range(ops, script, if_body_start, if_body_end, is_tapscript, state)?;

                    // Different stack depths → bail
                    if state.stack.len() != skip_state_stack.len() {
                        return None;
                    }

                    // Union essential sets
                    for idx in skip_state_essential {
                        state.essential.insert(idx);
                    }

                    // Merge stack taints
                    for (j, skip_item) in skip_state_stack.items.into_iter().enumerate() {
                        state.stack.items[j].taint =
                            state.stack.items[j].taint.merge(&skip_item.taint);
                    }
                }

                // Skip past ENDIF
                i = endif_idx + 1;
            }
            // OP_ELSE / OP_ENDIF — should not be encountered directly
            // (handled by IF branch simulation above)
            0x67 | 0x68 => {
                // If we hit these outside of IF simulation, bail
                return None;
            }

            // OP_RETURN — terminate this execution path
            0x6a => {
                return Some(());
            }

            // OP_NOP, OP_NOP1, OP_NOP4..OP_NOP10 — do nothing
            0x61 | 0xb0 | 0xb3..=0xb9 => {
                i += 1;
            }

            // ── Bail-out opcodes ─────────────────────────────────────────
            // OP_CODESEPARATOR
            0xab => return None,
            // OP_CHECKSIGADD in non-tapscript
            0xba => return None,
            // Disabled opcodes and anything unrecognized
            _ => return None,
        }
    }

    Some(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Count the current IF nesting depth at a given IF opcode position.
fn count_if_depth(ops: &[ScriptOp], if_idx: usize) -> usize {
    let mut depth: usize = 0;
    for op in ops.iter().take(if_idx + 1) {
        match op.opcode {
            0x63 | 0x64 => depth += 1,
            0x68 => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

/// Find the small integer (OP_0..OP_16) that was the N value for CHECKMULTISIG.
/// The N is right before the CHECKMULTISIG in standard scripts (after pubkey pushes).
fn find_preceding_small_int(
    ops: &[ScriptOp],
    checkmultisig_idx: usize,
    script: &[u8],
) -> Option<usize> {
    // Walk backward to find the last OP_N or OP_0 before the multisig
    // that was directly before the pubkey pushes
    if checkmultisig_idx == 0 {
        return None;
    }
    let prev = &ops[checkmultisig_idx - 1];
    match prev.opcode {
        0x00 => Some(0),
        0x51..=0x60 => Some((prev.opcode - 0x50) as usize),
        // Could be an OP_PUSHBYTES encoding a small number
        0x01 if prev.data_size == 1 => {
            let val = script[prev.offset + 1];
            if val <= 16 {
                Some(val as usize)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Find M for CHECKMULTISIG by looking back past N pubkey pushes.
fn find_second_preceding_small_int(
    ops: &[ScriptOp],
    checkmultisig_idx: usize,
    n: usize,
    script: &[u8],
) -> Option<usize> {
    // Pattern: OP_M <pk1> <pk2> ... <pkN> OP_N OP_CHECKMULTISIG
    // We need to go back past OP_N (1 op) and N pubkey pushes
    let target_idx = checkmultisig_idx.checked_sub(1 + n + 1)?;
    let op = &ops[target_idx];
    match op.opcode {
        0x00 => Some(0),
        0x51..=0x60 => Some((op.opcode - 0x50) as usize),
        0x01 if op.data_size == 1 => {
            let val = script[op.offset + 1];
            if val <= 16 {
                Some(val as usize)
            } else {
                None
            }
        }
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a 33-byte compressed pubkey push (OP_PUSHBYTES_33 + 33 bytes).
    fn push_pubkey() -> Vec<u8> {
        let mut v = vec![0x21]; // OP_PUSHBYTES_33
        v.extend([0x02; 33]); // compressed pubkey (0x02 prefix + 32 bytes)
        v
    }

    /// Helper: build a 32-byte push (OP_PUSHBYTES_32 + 32 bytes).
    fn push_32() -> Vec<u8> {
        let mut v = vec![0x20]; // OP_PUSHBYTES_32
        v.extend([0xAA; 32]);
        v
    }

    /// Helper: build a 20-byte push (OP_PUSHBYTES_20 + 20 bytes).
    fn push_20() -> Vec<u8> {
        let mut v = vec![0x14]; // OP_PUSHBYTES_20
        v.extend([0xBB; 20]);
        v
    }

    // ── Test 1: Simple CHECKSIG ──────────────────────────────────────────

    #[test]
    fn test_simple_checksig() {
        // Script: <pk> OP_CHECKSIG
        // Witness: [sig]
        let mut script = push_pubkey();
        script.push(0xac); // OP_CHECKSIG
        let result = simulate_essential_witnesses(1, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0])));
    }

    // ── Test 2: CHECKSIG with excess items ───────────────────────────────

    #[test]
    fn test_checksig_excess_items() {
        // Script: <pk> OP_CHECKSIG
        // Witness: [sig, junk1, junk2] — only sig (item 0) needed
        // Wait — witness items are pushed in order: item 0 is bottom.
        // So stack bottom→top: [item0, item1, item2]
        // Script pushes pubkey on top: [item0, item1, item2, pk]
        // CHECKSIG pops pubkey (pk) and sig (item2)
        // So item2 is the actual sig, items 0 and 1 are dead.
        let mut script = push_pubkey();
        script.push(0xac); // OP_CHECKSIG
        let result = simulate_essential_witnesses(3, &script, false);
        // Item 2 is the sig (top of witness stack), items 0, 1 are dead
        assert_eq!(result, Some(BTreeSet::from([2])));
    }

    // ── Test 3: Hash lock ────────────────────────────────────────────────

    #[test]
    fn test_hash_lock() {
        // Script: OP_SHA256 <expected_hash> OP_EQUAL
        // Witness: [preimage]
        let mut script = vec![0xa7]; // OP_SHA256
        script.extend(push_32()); // push expected hash
        script.push(0x87); // OP_EQUAL
        let result = simulate_essential_witnesses(1, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0])));
    }

    // ── Test 4: IF/ELSE branch union ─────────────────────────────────────

    #[test]
    fn test_if_else_branch_union() {
        // Script: OP_IF <pk1> OP_CHECKSIG OP_ELSE <pk2> OP_CHECKSIG OP_ENDIF
        // Witness: [sig, condition]
        // Both branches need a sig, condition determines which path
        let mut script = vec![0x63]; // OP_IF
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG
        script.push(0x67); // OP_ELSE
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG
        script.push(0x68); // OP_ENDIF

        // Witness: [sig=0, condition=1]
        // Stack bottom→top: [sig(0), cond(1)]
        // IF pops cond(1) — marked essential
        // Both branches: pop pubkey(script), pop sig(0) for CHECKSIG
        let result = simulate_essential_witnesses(2, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0, 1])));
    }

    // ── Test 5: Bail on CODESEPARATOR ────────────────────────────────────

    #[test]
    fn test_bail_on_codeseparator() {
        // Script: OP_CODESEPARATOR OP_CHECKSIG
        let script = vec![0xab, 0xac];
        let result = simulate_essential_witnesses(1, &script, false);
        assert_eq!(result, None);
    }

    // ── Test 6: 2-of-3 CHECKMULTISIG ────────────────────────────────────

    #[test]
    fn test_2of3_checkmultisig() {
        // Script: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        // Witness: [dummy, sig1, sig2]
        let mut script = vec![0x52]; // OP_2
        for _ in 0..3 {
            script.extend(push_pubkey());
        }
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG

        // Witness items [0]=dummy (bottom), [1]=sig1, [2]=sig2 (top)
        // Stack: [dummy(0), sig1(1), sig2(2)]
        // Script pushes: OP_2, pk1, pk2, pk3, OP_3
        // CHECKMULTISIG: pops N(=3), pops 3 pubkeys, pops M(=2), pops 2 sigs, pops dummy
        let result = simulate_essential_witnesses(3, &script, false);
        // All 3 witness items are essential (dummy + 2 sigs)
        assert_eq!(result, Some(BTreeSet::from([0, 1, 2])));
    }

    // ── Test 7: OP_DROP discards dead data ───────────────────────────────

    #[test]
    fn test_drop_discards_dead() {
        // Script: OP_DROP <pk> OP_CHECKSIG
        // Witness: [sig, junk]
        // Stack: [sig(0), junk(1)]
        // DROP pops junk(1) — lost
        // Script pushes pk
        // CHECKSIG pops pk, pops sig(0) — essential
        let mut script = vec![0x75]; // OP_DROP
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG

        let result = simulate_essential_witnesses(2, &script, false);
        // Item 0 (sig) is essential, item 1 (junk that gets dropped) is dead
        assert_eq!(result, Some(BTreeSet::from([0])));
    }

    // ── Test 8: DUP propagates taint ─────────────────────────────────────

    #[test]
    fn test_dup_propagates_taint() {
        // Script: OP_DUP <pk> OP_CHECKSIGVERIFY <pk> OP_CHECKSIG
        // Witness: [sig]
        // Stack: [sig(0)]
        // DUP → [sig(0), sig(0)]
        // Push pk → [sig(0), sig(0), pk]
        // CHECKSIGVERIFY pops pk + sig(0) → [sig(0)]
        // Push pk → [sig(0), pk]
        // CHECKSIG pops pk + sig(0) → result
        let mut script = vec![0x76]; // OP_DUP
        script.extend(push_pubkey());
        script.push(0xad); // OP_CHECKSIGVERIFY
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG

        let result = simulate_essential_witnesses(1, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0])));
    }

    // ── Test 9: Empty script ─────────────────────────────────────────────

    #[test]
    fn test_empty_script() {
        let result = simulate_essential_witnesses(0, &[], false);
        assert_eq!(result, Some(BTreeSet::new()));
    }

    // ── Test 10: CHECKSIGADD tapscript multi-sig ─────────────────────────

    #[test]
    fn test_checksigadd_tapscript() {
        // Script: <pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD <pk3> OP_CHECKSIGADD
        //         OP_2 OP_NUMEQUAL
        // Witness: [sig1, sig2, sig3] — all 3 essential
        // Stack: [sig1(0), sig2(1), sig3(2)]
        // <pk1> CHECKSIG: pops pk1(script) + sig3(2) → pushes result(taint={2})
        // <pk2> CHECKSIGADD: pops pk2(script) + result({2}) + sig2(1) → pushes counter(taint={1,2})
        // <pk3> CHECKSIGADD: pops pk3(script) + counter({1,2}) + sig1(0) → pushes counter(taint={0,1,2})
        // OP_2 pushes 2(script)
        // NUMEQUAL: pops 2(script) + counter({0,1,2}) → result
        let mut script = Vec::new();
        script.extend(push_pubkey()); // pk1
        script.push(0xac); // OP_CHECKSIG
        script.extend(push_pubkey()); // pk2
        script.push(0xba); // OP_CHECKSIGADD
        script.extend(push_pubkey()); // pk3
        script.push(0xba); // OP_CHECKSIGADD
        script.push(0x52); // OP_2
        script.push(0x9c); // OP_NUMEQUAL

        let result = simulate_essential_witnesses(3, &script, true);
        assert_eq!(result, Some(BTreeSet::from([0, 1, 2])));
    }

    // ── Test 11: CLTV/CSV ────────────────────────────────────────────────

    #[test]
    fn test_cltv_marks_essential() {
        // Script: OP_CHECKLOCKTIMEVERIFY OP_DROP <pk> OP_CHECKSIG
        // Witness: [sig, locktime]
        // Stack: [sig(0), locktime(1)]
        // CLTV peeks locktime(1) — marked essential
        // DROP pops locktime(1)
        // Push pk, CHECKSIG pops pk + sig(0)
        let mut script = vec![0xb1]; // OP_CHECKLOCKTIMEVERIFY
        script.push(0x75); // OP_DROP
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG

        let result = simulate_essential_witnesses(2, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0, 1])));
    }

    // ── Test: CSV marks essential ────────────────────────────────────────

    #[test]
    fn test_csv_marks_essential() {
        // Script: OP_CHECKSEQUENCEVERIFY OP_DROP <pk> OP_CHECKSIG
        // Witness: [sig, sequence]
        let mut script = vec![0xb2]; // OP_CHECKSEQUENCEVERIFY
        script.push(0x75); // OP_DROP
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG

        let result = simulate_essential_witnesses(2, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0, 1])));
    }

    // ── Test: HASH160 hash lock ──────────────────────────────────────────

    #[test]
    fn test_hash160_lock() {
        // Script: OP_HASH160 <expected_hash_20> OP_EQUALVERIFY <pk> OP_CHECKSIG
        // Witness: [sig, preimage]
        let mut script = vec![0xa8]; // OP_HASH160
        script.extend(push_20()); // push expected hash
        script.push(0x88); // OP_EQUALVERIFY
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG

        // Stack: [sig(0), preimage(1)]
        // HASH160 pops preimage(1), pushes hash(taint={1})
        // Push expected hash(script)
        // EQUALVERIFY pops both, marks {1} essential
        // Push pk, CHECKSIG pops pk + sig(0), marks {0} essential
        let result = simulate_essential_witnesses(2, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0, 1])));
    }

    // ── Test: Simulator is tighter than count_stack_consumption ──────────

    #[test]
    fn test_simulator_tighter_than_counter() {
        // Script: OP_DROP <pk> OP_CHECKSIG
        // count_stack_consumption says 1 (just the CHECKSIG sig)
        // But the DROP also consumes one, so actual witness need is 2 items
        // for the script to not underflow. However, item 1 (dropped) is dead.
        // Simulator: item 0 essential, item 1 dead.
        let mut script = vec![0x75]; // OP_DROP
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG

        let sim_result = simulate_essential_witnesses(2, &script, false).unwrap();
        let counter_result = crate::essential::count_stack_consumption(&script, false);

        // Simulator identifies 1 essential item (sig), counter says 1 too
        // But with 2 witness items, simulator knows item 1 (dropped) is dead
        assert_eq!(sim_result.len(), 1);
        assert!(sim_result.len() <= counter_result);
    }

    // ── Test: TOALTSTACK / FROMALTSTACK ──────────────────────────────────

    #[test]
    fn test_altstack_preserves_taint() {
        // Script: OP_TOALTSTACK <pk> OP_CHECKSIGVERIFY OP_FROMALTSTACK <pk> OP_CHECKSIG
        // Witness: [sig1, sig2]
        // Stack: [sig1(0), sig2(1)]
        // TOALTSTACK: moves sig2(1) to alt stack
        // Push pk, CHECKSIGVERIFY: pops pk + sig1(0) — marks {0} essential
        // FROMALTSTACK: pushes sig2(1) back
        // Push pk, CHECKSIG: pops pk + sig2(1) — marks {1} essential
        let mut script = vec![0x6b]; // OP_TOALTSTACK
        script.extend(push_pubkey());
        script.push(0xad); // OP_CHECKSIGVERIFY
        script.push(0x6c); // OP_FROMALTSTACK
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG

        let result = simulate_essential_witnesses(2, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0, 1])));
    }

    // ── Test: SWAP reorders taint correctly ──────────────────────────────

    #[test]
    fn test_swap_reorders_taint() {
        // Script: OP_SWAP <pk> OP_CHECKSIGVERIFY <pk> OP_CHECKSIG
        // Witness: [sig_for_second, sig_for_first]
        // Stack: [sig_for_second(0), sig_for_first(1)]
        // SWAP → [sig_for_first(1), sig_for_second(0)]
        // Push pk, CHECKSIGVERIFY: pops pk + sig_for_second(0)
        // Push pk, CHECKSIG: pops pk + sig_for_first(1)
        // Both essential
        let mut script = vec![0x7c]; // OP_SWAP
        script.extend(push_pubkey());
        script.push(0xad); // OP_CHECKSIGVERIFY
        script.extend(push_pubkey());
        script.push(0xac); // OP_CHECKSIG

        let result = simulate_essential_witnesses(2, &script, false);
        assert_eq!(result, Some(BTreeSet::from([0, 1])));
    }
}

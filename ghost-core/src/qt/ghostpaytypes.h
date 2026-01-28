// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_GHOSTPAYTYPES_H
#define GHOST_QT_GHOSTPAYTYPES_H

#include <QString>
#include <QDateTime>
#include <QList>
#include <cstdint>

namespace GhostPay {

/**
 * Standard denomination tiers for Ghost Locks
 * These match the Rust enum in ghost-locks/src/denomination.rs
 */
enum class Denomination {
    Micro = 0,   // 10,000 sats (0.0001 BTC)
    Tiny = 1,    // 100,000 sats (0.001 BTC)
    Small = 2,   // 1,000,000 sats (0.01 BTC)
    Medium = 3,  // 10,000,000 sats (0.1 BTC)
    Large = 4,   // 100,000,000 sats (1 BTC)
    XL = 5       // 1,000,000,000 sats (10 BTC)
};

/** Get satoshi value for a denomination */
inline int64_t denominationSats(Denomination d) {
    switch (d) {
        case Denomination::Micro:  return 10000;
        case Denomination::Tiny:   return 100000;
        case Denomination::Small:  return 1000000;
        case Denomination::Medium: return 10000000;
        case Denomination::Large:  return 100000000;
        case Denomination::XL:     return 1000000000;
    }
    return 0;
}

/** Get display name for a denomination */
inline QString denominationName(Denomination d) {
    switch (d) {
        case Denomination::Micro:  return QStringLiteral("Micro (0.0001 BTC)");
        case Denomination::Tiny:   return QStringLiteral("Tiny (0.001 BTC)");
        case Denomination::Small:  return QStringLiteral("Small (0.01 BTC)");
        case Denomination::Medium: return QStringLiteral("Medium (0.1 BTC)");
        case Denomination::Large:  return QStringLiteral("Large (1 BTC)");
        case Denomination::XL:     return QStringLiteral("XL (10 BTC)");
    }
    return QStringLiteral("Unknown");
}

/**
 * Ghost Lock state in lifecycle
 * Matches ghost-locks/src/state.rs
 */
enum class LockState {
    Created = 0,      // Fresh from Wraith, needs first jump
    Active = 1,       // Has L2 activity, will reconcile at next batch
    Idle = 2,         // No L2 activity, waiting for jump deadline
    Queued = 3,       // Deadline passed, in queue for reconciliation
    Reconciling = 4,  // Currently in a reconciliation batch
    Closed = 5        // Reconciled and exited (terminal)
};

/** Get display name for a lock state */
inline QString lockStateName(LockState s) {
    switch (s) {
        case LockState::Created:     return QStringLiteral("Created");
        case LockState::Active:      return QStringLiteral("Active");
        case LockState::Idle:        return QStringLiteral("Idle");
        case LockState::Queued:      return QStringLiteral("Queued");
        case LockState::Reconciling: return QStringLiteral("Reconciling");
        case LockState::Closed:      return QStringLiteral("Closed");
    }
    return QStringLiteral("Unknown");
}

/** Check if state allows L2 activity */
inline bool stateAllowsL2Activity(LockState s) {
    return s == LockState::Active || s == LockState::Idle;
}

/**
 * Timelock tier for recovery
 * Matches ghost-locks/src/timelock.rs
 */
enum class TimelockTier {
    Short = 0,    // ~3 months (26,280 blocks)
    Standard = 1, // ~6 months (52,560 blocks)
    Long = 2      // ~1 year (105,120 blocks)
};

/** Get block count for timelock tier */
inline uint32_t timelockBlocks(TimelockTier t) {
    switch (t) {
        case TimelockTier::Short:    return 26280;
        case TimelockTier::Standard: return 52560;
        case TimelockTier::Long:     return 105120;
    }
    return 52560;
}

/**
 * Information about a Ghost Lock
 */
struct GhostLockInfo {
    QString lockId;              // 32-byte hex ID
    QString lockPubkey;          // X-only pubkey (hex)
    QString recoveryPubkey;      // Recovery pubkey (hex)
    uint32_t creationHeight;     // L1 block height when created
    Denomination denomination;   // Standard denomination
    TimelockTier timelockTier;   // Recovery timelock
    LockState state;             // Current lifecycle state
    int64_t l2Balance;           // Current L2 balance in sats
    uint64_t lastActivityHeight; // Last L2 virtual block with activity
    uint32_t recoveryHeight;     // Height when timelock expires

    /** Check if recovery is available */
    bool isRecoveryAvailable(uint32_t currentHeight) const {
        return currentHeight >= recoveryHeight;
    }

    /** Blocks until recovery available */
    uint32_t blocksUntilRecovery(uint32_t currentHeight) const {
        if (currentHeight >= recoveryHeight) return 0;
        return recoveryHeight - currentHeight;
    }
};

/**
 * L2 balance information
 */
struct L2Balance {
    int64_t available{0};  // Immediately spendable
    int64_t pending{0};    // In pending payments
    int64_t total{0};      // available + pending
    int lockCount{0};      // Number of active locks
};

/**
 * L2 Payment information
 */
struct PaymentInfo {
    QString paymentId;       // Unique payment ID
    QString fromLockId;      // Sender's lock ID
    QString toGhostId;       // Recipient's Ghost ID (silent payment address)
    int64_t amount;          // Amount in sats
    uint64_t virtualBlock;   // L2 virtual block height
    QDateTime timestamp;     // When payment was made
    bool confirmed;          // Whether in confirmed L2 block
    QString status;          // "pending", "confirmed", "failed"
};

/**
 * Ghost Pay node status
 */
struct NodeStatus {
    bool connected;          // Whether connected to ghost-pay-node
    QString nodeId;          // Node's public identity
    QString version;         // Node software version
    uint64_t l2Height;       // Current L2 virtual block height
    uint32_t currentEpoch;   // Current reconciliation epoch
    int peerCount;           // Number of connected L2 peers
    uint32_t l1Height;       // Current L1 block height (if tracking)
    QString stateRoot;       // Current L2 state root (hex)
};

/**
 * Wraith session status
 */
enum class WraithPhase {
    Forming = 0,      // Waiting for participants
    Phase1Ready = 1,  // Ready for split signing
    Phase1Signed = 2, // Split tx signed, broadcasting
    Phase2Ready = 3,  // Ready for merge signing
    Phase2Signed = 4, // Merge tx signed, broadcasting
    Complete = 5,     // Successfully completed
    Failed = 6        // Session failed
};

inline QString wraithPhaseName(WraithPhase p) {
    switch (p) {
        case WraithPhase::Forming:      return QStringLiteral("Forming");
        case WraithPhase::Phase1Ready:  return QStringLiteral("Phase 1 Ready");
        case WraithPhase::Phase1Signed: return QStringLiteral("Phase 1 Signed");
        case WraithPhase::Phase2Ready:  return QStringLiteral("Phase 2 Ready");
        case WraithPhase::Phase2Signed: return QStringLiteral("Phase 2 Signed");
        case WraithPhase::Complete:     return QStringLiteral("Complete");
        case WraithPhase::Failed:       return QStringLiteral("Failed");
    }
    return QStringLiteral("Unknown");
}

/**
 * Wraith session information
 */
struct WraithSessionInfo {
    QString sessionId;           // Session identifier
    Denomination denomination;   // Session denomination
    WraithPhase phase;           // Current phase
    int participantCount;        // Number of participants
    int minParticipants;         // Minimum required
    int maxParticipants;         // Maximum allowed
    QDateTime createdAt;         // When session started
    QDateTime expiresAt;         // When session expires if not complete
    QString coordinatorId;       // Coordinator node ID
    bool isCoordinator;          // Whether we are the coordinator
};

/**
 * Jump queue status for a lock
 */
struct JumpStatus {
    QString lockId;
    bool inQueue;                // Whether in jump queue
    int queuePosition;           // Position in queue (0 = not in queue)
    uint64_t deadline;           // Virtual block deadline
    bool needsRotation;          // Whether key rotation needed
    QString riskTier;            // "low", "medium", "high"
};

/**
 * Reconciliation batch information
 */
struct BatchInfo {
    QString batchId;
    uint32_t epochId;
    int inputCount;
    int outputCount;
    int64_t totalAmount;
    QString status;              // "forming", "signing", "broadcast", "confirmed"
    QDateTime createdAt;
    QString txid;                // L1 txid once broadcast
};

} // namespace GhostPay

#endif // GHOST_QT_GHOSTPAYTYPES_H

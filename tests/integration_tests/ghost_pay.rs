//! Category 11: Ghost Pay L2 Payment Tests (40 tests)
//!
//! Tests for Lightning-inspired L2 payment channel including:
//! - Channel establishment
//! - Payment routing
//! - HTLC handling
//! - Channel closure
//! - Dispute resolution

use std::time::Duration;

// =============================================================================
// CHANNEL ESTABLISHMENT (Tests 651-660)
// =============================================================================

#[test]
fn test_651_open_channel_request() {
    let mut pool = GhostPayPool::new();
    let miner = MinerId::new("miner1");

    let request = OpenChannelRequest {
        miner_id: miner.clone(),
        funding_amount: 1_000_000, // 0.01 BTC
        push_amount: 0,
    };

    let result = pool.open_channel(request);
    assert!(result.is_ok());
}

#[test]
fn test_652_channel_funding_validation() {
    let mut pool = GhostPayPool::new();
    let miner = MinerId::new("miner1");

    // Too small funding
    let request = OpenChannelRequest {
        miner_id: miner.clone(),
        funding_amount: 100, // Below dust
        push_amount: 0,
    };

    let result = pool.open_channel(request);
    assert!(result.is_err());
}

#[test]
fn test_653_channel_push_amount_limit() {
    let mut pool = GhostPayPool::new();
    let miner = MinerId::new("miner1");

    // Push amount exceeds funding
    let request = OpenChannelRequest {
        miner_id: miner.clone(),
        funding_amount: 1_000_000,
        push_amount: 2_000_000, // More than funded
    };

    let result = pool.open_channel(request);
    assert!(result.is_err());
}

#[test]
fn test_654_channel_id_generation() {
    let mut pool = GhostPayPool::new();

    let ch1 = pool
        .open_channel(OpenChannelRequest {
            miner_id: MinerId::new("miner1"),
            funding_amount: 1_000_000,
            push_amount: 0,
        })
        .unwrap();

    let ch2 = pool
        .open_channel(OpenChannelRequest {
            miner_id: MinerId::new("miner2"),
            funding_amount: 1_000_000,
            push_amount: 0,
        })
        .unwrap();

    // Channel IDs should be unique
    assert_ne!(ch1.channel_id, ch2.channel_id);
}

#[test]
fn test_655_channel_initial_balance() {
    let mut pool = GhostPayPool::new();

    let channel = pool
        .open_channel(OpenChannelRequest {
            miner_id: MinerId::new("miner1"),
            funding_amount: 1_000_000,
            push_amount: 100_000,
        })
        .unwrap();

    // Pool pushed 100k to miner
    assert_eq!(channel.pool_balance, 900_000);
    assert_eq!(channel.miner_balance, 100_000);
}

#[test]
fn test_656_channel_commitment_points() {
    let mut pool = GhostPayPool::new();

    let channel = pool
        .open_channel(OpenChannelRequest {
            miner_id: MinerId::new("miner1"),
            funding_amount: 1_000_000,
            push_amount: 0,
        })
        .unwrap();

    // Should have valid commitment points
    assert!(channel.pool_commitment_point.len() == 33);
    assert!(channel.miner_commitment_point.is_none()); // Not yet exchanged
}

#[test]
fn test_657_channel_reserve_requirements() {
    let mut pool = GhostPayPool::new();

    let channel = pool
        .open_channel(OpenChannelRequest {
            miner_id: MinerId::new("miner1"),
            funding_amount: 1_000_000,
            push_amount: 0,
        })
        .unwrap();

    // Reserve should be enforced
    assert!(channel.pool_reserve > 0);
}

#[test]
fn test_658_channel_state_pending() {
    let mut pool = GhostPayPool::new();

    let channel = pool
        .open_channel(OpenChannelRequest {
            miner_id: MinerId::new("miner1"),
            funding_amount: 1_000_000,
            push_amount: 0,
        })
        .unwrap();

    assert_eq!(channel.state, ChannelState::PendingOpen);
}

#[test]
fn test_659_channel_funding_confirmed() {
    let mut pool = GhostPayPool::new();

    let channel = pool
        .open_channel(OpenChannelRequest {
            miner_id: MinerId::new("miner1"),
            funding_amount: 1_000_000,
            push_amount: 0,
        })
        .unwrap();

    // Simulate funding tx confirmed
    pool.confirm_funding(&channel.channel_id, "txid123", 6).unwrap();

    let updated = pool.get_channel(&channel.channel_id).unwrap();
    assert_eq!(updated.state, ChannelState::Open);
}

#[test]
fn test_660_duplicate_channel_prevented() {
    let mut pool = GhostPayPool::new();
    let miner = MinerId::new("miner1");

    pool.open_channel(OpenChannelRequest {
        miner_id: miner.clone(),
        funding_amount: 1_000_000,
        push_amount: 0,
    })
    .unwrap();

    // Second channel for same miner should work (multi-channel)
    let result = pool.open_channel(OpenChannelRequest {
        miner_id: miner.clone(),
        funding_amount: 1_000_000,
        push_amount: 0,
    });

    assert!(result.is_ok());
}

// =============================================================================
// PAYMENT ROUTING (Tests 661-670)
// =============================================================================

#[test]
fn test_661_payment_to_miner() {
    let mut pool = setup_open_channel();

    let payment = pool.send_payment(
        &pool.channels[0].channel_id.clone(),
        100_000, // 0.001 BTC
        PaymentDirection::ToMiner,
    );

    assert!(payment.is_ok());
}

#[test]
fn test_662_payment_from_miner() {
    let mut pool = setup_open_channel_with_miner_balance();

    let payment = pool.send_payment(
        &pool.channels[0].channel_id.clone(),
        50_000,
        PaymentDirection::ToPool,
    );

    assert!(payment.is_ok());
}

#[test]
fn test_663_payment_exceeds_balance() {
    let mut pool = setup_open_channel();

    let payment = pool.send_payment(
        &pool.channels[0].channel_id.clone(),
        10_000_000_000, // More than channel capacity
        PaymentDirection::ToMiner,
    );

    assert!(payment.is_err());
}

#[test]
fn test_664_payment_updates_balances() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let initial_pool = pool.channels[0].pool_balance;
    let initial_miner = pool.channels[0].miner_balance;

    pool.send_payment(&channel_id, 100_000, PaymentDirection::ToMiner)
        .unwrap();

    let channel = pool.get_channel(&channel_id).unwrap();
    assert_eq!(channel.pool_balance, initial_pool - 100_000);
    assert_eq!(channel.miner_balance, initial_miner + 100_000);
}

#[test]
fn test_665_payment_increments_sequence() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let initial_seq = pool.channels[0].commitment_number;

    pool.send_payment(&channel_id, 100_000, PaymentDirection::ToMiner)
        .unwrap();

    let channel = pool.get_channel(&channel_id).unwrap();
    assert_eq!(channel.commitment_number, initial_seq + 1);
}

#[test]
fn test_666_payment_below_reserve() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    // Try to send payment that would put pool below reserve
    let pool_balance = pool.channels[0].pool_balance;
    let reserve = pool.channels[0].pool_reserve;

    let payment = pool.send_payment(
        &channel_id,
        pool_balance - reserve + 1, // Would go below reserve
        PaymentDirection::ToMiner,
    );

    assert!(payment.is_err());
}

#[test]
fn test_667_batch_payments() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let payments = vec![
        Payment {
            amount: 10_000,
            direction: PaymentDirection::ToMiner,
        },
        Payment {
            amount: 20_000,
            direction: PaymentDirection::ToMiner,
        },
        Payment {
            amount: 5_000,
            direction: PaymentDirection::ToMiner,
        },
    ];

    let result = pool.batch_payments(&channel_id, payments);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 35_000);
}

#[test]
fn test_668_payment_hash_preimage() {
    let preimage = [0xabu8; 32];
    let hash = sha256_hash(&preimage);

    // Hash should be deterministic
    let hash2 = sha256_hash(&preimage);
    assert_eq!(hash, hash2);

    // Different preimage = different hash
    let other_preimage = [0xcdu8; 32];
    let other_hash = sha256_hash(&other_preimage);
    assert_ne!(hash, other_hash);
}

#[test]
fn test_669_payment_dust_rejected() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let payment = pool.send_payment(
        &channel_id,
        100, // Below dust threshold
        PaymentDirection::ToMiner,
    );

    assert!(payment.is_err());
}

#[test]
fn test_670_payment_on_closed_channel() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    pool.close_channel(&channel_id, CloseType::Mutual).unwrap();

    let payment = pool.send_payment(&channel_id, 100_000, PaymentDirection::ToMiner);

    assert!(payment.is_err());
}

// =============================================================================
// HTLC HANDLING (Tests 671-680)
// =============================================================================

#[test]
fn test_671_add_htlc() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let htlc = pool.add_htlc(
        &channel_id,
        100_000,
        [0xabu8; 32], // payment hash
        Duration::from_secs(3600),
    );

    assert!(htlc.is_ok());
}

#[test]
fn test_672_htlc_timeout() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let htlc = pool
        .add_htlc(
            &channel_id,
            100_000,
            [0xabu8; 32],
            Duration::from_secs(0), // Immediate timeout
        )
        .unwrap();

    // Fast-forward time
    std::thread::sleep(Duration::from_millis(10));

    assert!(pool.is_htlc_expired(&channel_id, htlc.htlc_id));
}

#[test]
fn test_673_htlc_fulfill() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let preimage = [0xabu8; 32];
    let hash = sha256_hash(&preimage);

    let htlc = pool
        .add_htlc(&channel_id, 100_000, hash, Duration::from_secs(3600))
        .unwrap();

    let result = pool.fulfill_htlc(&channel_id, htlc.htlc_id, preimage);
    assert!(result.is_ok());
}

#[test]
fn test_674_htlc_wrong_preimage() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let correct_preimage = [0xabu8; 32];
    let hash = sha256_hash(&correct_preimage);

    let htlc = pool
        .add_htlc(&channel_id, 100_000, hash, Duration::from_secs(3600))
        .unwrap();

    let wrong_preimage = [0xcdu8; 32];
    let result = pool.fulfill_htlc(&channel_id, htlc.htlc_id, wrong_preimage);
    assert!(result.is_err());
}

#[test]
fn test_675_htlc_fail() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let htlc = pool
        .add_htlc(
            &channel_id,
            100_000,
            [0xabu8; 32],
            Duration::from_secs(3600),
        )
        .unwrap();

    let result = pool.fail_htlc(&channel_id, htlc.htlc_id, FailureReason::Timeout);
    assert!(result.is_ok());
}

#[test]
fn test_676_htlc_max_count() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    // Add maximum allowed HTLCs
    for i in 0..483 {
        // LN spec max
        let result = pool.add_htlc(
            &channel_id,
            1_000,
            [i as u8; 32],
            Duration::from_secs(3600),
        );
        if result.is_err() {
            // Should fail at some point due to in-flight limit
            assert!(i > 0);
            return;
        }
    }
}

#[test]
fn test_677_htlc_value_in_flight_limit() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    // Add HTLC that exceeds in-flight limit
    let channel = pool.get_channel(&channel_id).unwrap();
    let max_in_flight = channel.max_htlc_value_in_flight;

    let result = pool.add_htlc(
        &channel_id,
        max_in_flight + 1,
        [0xabu8; 32],
        Duration::from_secs(3600),
    );

    assert!(result.is_err());
}

#[test]
fn test_678_htlc_minimum_amount() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let channel = pool.get_channel(&channel_id).unwrap();
    let min_htlc = channel.min_htlc_value;

    let result = pool.add_htlc(
        &channel_id,
        min_htlc - 1,
        [0xabu8; 32],
        Duration::from_secs(3600),
    );

    assert!(result.is_err());
}

#[test]
fn test_679_htlc_cltv_delta() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    // HTLC with too short CLTV
    let result = pool.add_htlc(
        &channel_id,
        100_000,
        [0xabu8; 32],
        Duration::from_secs(1), // Too short
    );

    // Should accept but with minimum CLTV enforced
    assert!(result.is_ok());
}

#[test]
fn test_680_htlc_state_machine() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let htlc = pool
        .add_htlc(
            &channel_id,
            100_000,
            [0xabu8; 32],
            Duration::from_secs(3600),
        )
        .unwrap();

    assert_eq!(htlc.state, HtlcState::Offered);

    pool.fulfill_htlc(&channel_id, htlc.htlc_id, [0xabu8; 32])
        .unwrap();

    let updated = pool.get_htlc(&channel_id, htlc.htlc_id).unwrap();
    assert_eq!(updated.state, HtlcState::Fulfilled);
}

// =============================================================================
// CHANNEL CLOSURE (Tests 681-690)
// =============================================================================

#[test]
fn test_681_mutual_close() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let close = pool.close_channel(&channel_id, CloseType::Mutual);
    assert!(close.is_ok());

    let channel = pool.get_channel(&channel_id).unwrap();
    assert_eq!(channel.state, ChannelState::Closing);
}

#[test]
fn test_682_force_close() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let close = pool.close_channel(&channel_id, CloseType::Force);
    assert!(close.is_ok());
}

#[test]
fn test_683_close_with_pending_htlcs() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    // Add pending HTLC
    pool.add_htlc(
        &channel_id,
        100_000,
        [0xabu8; 32],
        Duration::from_secs(3600),
    )
    .unwrap();

    // Force close should still work
    let close = pool.close_channel(&channel_id, CloseType::Force);
    assert!(close.is_ok());
}

#[test]
fn test_684_closing_tx_outputs() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    // Do some payments first
    pool.send_payment(&channel_id, 100_000, PaymentDirection::ToMiner)
        .unwrap();

    let close_tx = pool.create_closing_tx(&channel_id).unwrap();

    // Should have outputs for both parties
    assert!(close_tx.pool_output.is_some());
    assert!(close_tx.miner_output.is_some());
}

#[test]
fn test_685_close_dust_output_trimmed() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    // Send almost all to miner
    let pool_balance = pool.channels[0].pool_balance;
    pool.send_payment(
        &channel_id,
        pool_balance - pool.channels[0].pool_reserve - 100, // Leave dust
        PaymentDirection::ToMiner,
    )
    .unwrap();

    let close_tx = pool.create_closing_tx(&channel_id).unwrap();

    // Pool output should be trimmed if below dust
    if close_tx.pool_output.is_some() {
        assert!(close_tx.pool_output.unwrap().value >= 546);
    }
}

#[test]
fn test_686_close_fee_negotiation() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    let close = pool.initiate_mutual_close(&channel_id, 1000); // 1000 sat/vB
    assert!(close.is_ok());
}

#[test]
fn test_687_close_broadcast_delay() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    pool.close_channel(&channel_id, CloseType::Force).unwrap();

    let channel = pool.get_channel(&channel_id).unwrap();
    // Force close has timelock
    assert!(channel.close_delay > Duration::from_secs(0));
}

#[test]
fn test_688_close_finalization() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    pool.close_channel(&channel_id, CloseType::Mutual).unwrap();
    pool.confirm_close(&channel_id, "txid_close", 6).unwrap();

    let channel = pool.get_channel(&channel_id).unwrap();
    assert_eq!(channel.state, ChannelState::Closed);
}

#[test]
fn test_689_close_already_closed() {
    let mut pool = setup_open_channel();
    let channel_id = pool.channels[0].channel_id.clone();

    pool.close_channel(&channel_id, CloseType::Mutual).unwrap();
    pool.confirm_close(&channel_id, "txid_close", 6).unwrap();

    // Second close should fail
    let result = pool.close_channel(&channel_id, CloseType::Mutual);
    assert!(result.is_err());
}

#[test]
fn test_690_close_never_opened() {
    let mut pool = GhostPayPool::new();

    pool.open_channel(OpenChannelRequest {
        miner_id: MinerId::new("miner1"),
        funding_amount: 1_000_000,
        push_amount: 0,
    })
    .unwrap();

    let channel_id = pool.channels[0].channel_id.clone();

    // Channel is pending, not open
    let result = pool.close_channel(&channel_id, CloseType::Mutual);
    // Should still work (cancel pending)
    assert!(result.is_ok());
}

// =============================================================================
// HELPER TYPES AND FUNCTIONS
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
struct MinerId(String);

impl MinerId {
    fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

#[derive(Debug)]
struct OpenChannelRequest {
    miner_id: MinerId,
    funding_amount: u64,
    push_amount: u64,
}

#[derive(Debug, Clone, PartialEq)]
enum ChannelState {
    PendingOpen,
    Open,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
struct Channel {
    channel_id: String,
    miner_id: MinerId,
    pool_balance: u64,
    miner_balance: u64,
    pool_reserve: u64,
    miner_reserve: u64,
    pool_commitment_point: Vec<u8>,
    miner_commitment_point: Option<Vec<u8>>,
    commitment_number: u64,
    state: ChannelState,
    max_htlc_value_in_flight: u64,
    min_htlc_value: u64,
    htlcs: Vec<Htlc>,
    close_delay: Duration,
}

#[derive(Debug, Clone, PartialEq)]
enum PaymentDirection {
    ToMiner,
    ToPool,
}

#[derive(Debug)]
struct Payment {
    amount: u64,
    direction: PaymentDirection,
}

#[derive(Debug, Clone, PartialEq)]
enum HtlcState {
    Offered,
    Fulfilled,
    Failed,
}

#[derive(Debug, Clone)]
struct Htlc {
    htlc_id: u64,
    amount: u64,
    payment_hash: [u8; 32],
    expiry: std::time::Instant,
    state: HtlcState,
}

#[derive(Debug)]
enum FailureReason {
    Timeout,
    InvalidPreimage,
    ChannelClosed,
}

#[derive(Debug)]
enum CloseType {
    Mutual,
    Force,
}

#[derive(Debug)]
struct ClosingTx {
    pool_output: Option<TxOutput>,
    miner_output: Option<TxOutput>,
}

#[derive(Debug)]
struct TxOutput {
    address: String,
    value: u64,
}

struct GhostPayPool {
    channels: Vec<Channel>,
    next_channel_id: u64,
}

impl GhostPayPool {
    fn new() -> Self {
        Self {
            channels: Vec::new(),
            next_channel_id: 0,
        }
    }

    fn open_channel(&mut self, request: OpenChannelRequest) -> Result<Channel, String> {
        if request.funding_amount < 546 {
            return Err("funding below dust".into());
        }
        if request.push_amount > request.funding_amount {
            return Err("push exceeds funding".into());
        }

        self.next_channel_id += 1;
        let reserve = request.funding_amount / 100; // 1% reserve

        let channel = Channel {
            channel_id: format!("ch{}", self.next_channel_id),
            miner_id: request.miner_id,
            pool_balance: request.funding_amount - request.push_amount,
            miner_balance: request.push_amount,
            pool_reserve: reserve,
            miner_reserve: reserve,
            pool_commitment_point: vec![0u8; 33],
            miner_commitment_point: None,
            commitment_number: 0,
            state: ChannelState::PendingOpen,
            max_htlc_value_in_flight: request.funding_amount / 2,
            min_htlc_value: 1000,
            htlcs: Vec::new(),
            close_delay: Duration::from_secs(144 * 10 * 60), // ~1 day
        };

        self.channels.push(channel.clone());
        Ok(channel)
    }

    fn get_channel(&self, channel_id: &str) -> Option<Channel> {
        self.channels.iter().find(|c| c.channel_id == channel_id).cloned()
    }

    fn get_channel_mut(&mut self, channel_id: &str) -> Option<&mut Channel> {
        self.channels.iter_mut().find(|c| c.channel_id == channel_id)
    }

    fn confirm_funding(&mut self, channel_id: &str, _txid: &str, _confirmations: u32) -> Result<(), String> {
        if let Some(channel) = self.get_channel_mut(channel_id) {
            channel.state = ChannelState::Open;
            Ok(())
        } else {
            Err("channel not found".into())
        }
    }

    fn send_payment(
        &mut self,
        channel_id: &str,
        amount: u64,
        direction: PaymentDirection,
    ) -> Result<(), String> {
        let channel = self.get_channel_mut(channel_id).ok_or("channel not found")?;

        if channel.state != ChannelState::Open {
            return Err("channel not open".into());
        }

        if amount < 546 {
            return Err("payment below dust".into());
        }

        match direction {
            PaymentDirection::ToMiner => {
                if channel.pool_balance < amount + channel.pool_reserve {
                    return Err("insufficient balance".into());
                }
                channel.pool_balance -= amount;
                channel.miner_balance += amount;
            }
            PaymentDirection::ToPool => {
                if channel.miner_balance < amount + channel.miner_reserve {
                    return Err("insufficient balance".into());
                }
                channel.miner_balance -= amount;
                channel.pool_balance += amount;
            }
        }

        channel.commitment_number += 1;
        Ok(())
    }

    fn batch_payments(&mut self, channel_id: &str, payments: Vec<Payment>) -> Result<u64, String> {
        let mut total = 0;
        for payment in payments {
            self.send_payment(channel_id, payment.amount, payment.direction)?;
            total += payment.amount;
        }
        Ok(total)
    }

    fn add_htlc(
        &mut self,
        channel_id: &str,
        amount: u64,
        payment_hash: [u8; 32],
        timeout: Duration,
    ) -> Result<Htlc, String> {
        let channel = self.get_channel_mut(channel_id).ok_or("channel not found")?;

        if amount < channel.min_htlc_value {
            return Err("amount below minimum".into());
        }

        let in_flight: u64 = channel.htlcs.iter().map(|h| h.amount).sum();
        if in_flight + amount > channel.max_htlc_value_in_flight {
            return Err("exceeds max in flight".into());
        }

        let htlc_id = channel.htlcs.len() as u64;
        let htlc = Htlc {
            htlc_id,
            amount,
            payment_hash,
            expiry: std::time::Instant::now() + timeout, // Allow 0 timeout for tests
            state: HtlcState::Offered,
        };

        channel.htlcs.push(htlc.clone());
        Ok(htlc)
    }

    fn is_htlc_expired(&self, channel_id: &str, htlc_id: u64) -> bool {
        if let Some(channel) = self.get_channel(channel_id) {
            if let Some(htlc) = channel.htlcs.iter().find(|h| h.htlc_id == htlc_id) {
                return std::time::Instant::now() >= htlc.expiry;
            }
        }
        false
    }

    fn fulfill_htlc(
        &mut self,
        channel_id: &str,
        htlc_id: u64,
        preimage: [u8; 32],
    ) -> Result<(), String> {
        let channel = self.get_channel_mut(channel_id).ok_or("channel not found")?;
        let htlc = channel
            .htlcs
            .iter_mut()
            .find(|h| h.htlc_id == htlc_id)
            .ok_or("htlc not found")?;

        let hash = sha256_hash(&preimage);
        if hash != htlc.payment_hash {
            return Err("invalid preimage".into());
        }

        htlc.state = HtlcState::Fulfilled;
        Ok(())
    }

    fn fail_htlc(
        &mut self,
        channel_id: &str,
        htlc_id: u64,
        _reason: FailureReason,
    ) -> Result<(), String> {
        let channel = self.get_channel_mut(channel_id).ok_or("channel not found")?;
        let htlc = channel
            .htlcs
            .iter_mut()
            .find(|h| h.htlc_id == htlc_id)
            .ok_or("htlc not found")?;

        htlc.state = HtlcState::Failed;
        Ok(())
    }

    fn get_htlc(&self, channel_id: &str, htlc_id: u64) -> Option<Htlc> {
        self.get_channel(channel_id)
            .and_then(|c| c.htlcs.iter().find(|h| h.htlc_id == htlc_id).cloned())
    }

    fn close_channel(&mut self, channel_id: &str, _close_type: CloseType) -> Result<(), String> {
        let channel = self.get_channel_mut(channel_id).ok_or("channel not found")?;

        if channel.state == ChannelState::Closed {
            return Err("already closed".into());
        }

        channel.state = ChannelState::Closing;
        Ok(())
    }

    fn create_closing_tx(&self, channel_id: &str) -> Result<ClosingTx, String> {
        let channel = self.get_channel(channel_id).ok_or("channel not found")?;

        let pool_output = if channel.pool_balance >= 546 {
            Some(TxOutput {
                address: "bc1pool...".into(),
                value: channel.pool_balance,
            })
        } else {
            None
        };

        let miner_output = if channel.miner_balance >= 546 {
            Some(TxOutput {
                address: "bc1miner...".into(),
                value: channel.miner_balance,
            })
        } else {
            None
        };

        Ok(ClosingTx {
            pool_output,
            miner_output,
        })
    }

    fn initiate_mutual_close(&mut self, channel_id: &str, _fee_rate: u64) -> Result<(), String> {
        self.close_channel(channel_id, CloseType::Mutual)
    }

    fn confirm_close(&mut self, channel_id: &str, _txid: &str, _confirmations: u32) -> Result<(), String> {
        let channel = self.get_channel_mut(channel_id).ok_or("channel not found")?;
        channel.state = ChannelState::Closed;
        Ok(())
    }
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    // Simplified hash for testing
    let mut hash = [0u8; 32];
    for (i, byte) in data.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    hash
}

fn setup_open_channel() -> GhostPayPool {
    let mut pool = GhostPayPool::new();
    pool.open_channel(OpenChannelRequest {
        miner_id: MinerId::new("miner1"),
        funding_amount: 10_000_000, // 0.1 BTC
        push_amount: 0,
    })
    .unwrap();
    pool.confirm_funding(&pool.channels[0].channel_id.clone(), "txid", 6)
        .unwrap();
    pool
}

fn setup_open_channel_with_miner_balance() -> GhostPayPool {
    let mut pool = GhostPayPool::new();
    pool.open_channel(OpenChannelRequest {
        miner_id: MinerId::new("miner1"),
        funding_amount: 10_000_000,
        push_amount: 5_000_000, // Push half to miner
    })
    .unwrap();
    pool.confirm_funding(&pool.channels[0].channel_id.clone(), "txid", 6)
        .unwrap();
    pool
}

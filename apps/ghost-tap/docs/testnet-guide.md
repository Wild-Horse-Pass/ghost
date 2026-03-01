# Signet / Testnet Integration Guide

**Version:** 0.2.0
**Last Updated:** 2026-03-01

---

## 1. Overview

Before deploying to mainnet, all GhostTap features must be tested against Ghost signet nodes. This guide covers how to connect, configure, and test the full wallet lifecycle.

## 2. Current Infrastructure

| Node | Host | RPC Port | Status | Notes |
|------|------|----------|--------|-------|
| VM1 | 83.136.251.162 | 38332 | Active | Genesis node |
| VM2 | 85.9.198.212 | 38332 | Active | |
| VM3 | 213.163.207.46 | 38332 | Active | |
| VM4 | 95.111.221.169 | 38332 | Active | |

## 3. Node Configuration

### 3.1 Enable RPC for GhostTap

Each signet node needs RPC access configured. In `ghost.conf`:

```
# RPC settings
server=1
rpcuser=ghosttap
rpcpassword=<generate_strong_password>
rpcport=38332
rpcallowip=<mobile_device_ip_or_vpn_subnet>

# GSP (built into ghostd, port 8900)
gsp=1
gspport=8900
blockfilterindex=basic
peerblockfilters=1

# ZMQ notifications (optional, for real-time tx detection)
zmqpubhashblock=tcp://0.0.0.0:28332
zmqpubhashtx=tcp://0.0.0.0:28333
```

> **Security:** Do NOT set `rpcallowip=0.0.0.0/0` in production. Use a VPN or restrict to known IPs. TLS is required for non-localhost RPC connections.

### 3.2 Verify RPC Access

From the machine where GhostTap will run:

```bash
curl -s -u ghosttap:<password> \
  --data-binary '{"jsonrpc":"1.0","id":"test","method":"getblockchaininfo","params":[]}' \
  -H "content-type: text/plain;" \
  http://<vm1_ip>:38332/
```

Expected response:
```json
{
  "result": {
    "chain": "signet",
    "blocks": 12345,
    "headers": 12345,
    "bestblockhash": "0000..."
  },
  "error": null,
  "id": "test"
}
```

### 3.3 Firewall Rules

Ensure the RPC and GSP ports are accessible:

```bash
# On the node server
sudo ufw allow from <mobile_ip> to any port 38332  # RPC
sudo ufw allow from <mobile_ip> to any port 8900   # GSP WebSocket

# Or via iptables
sudo iptables -A INPUT -p tcp --dport 38332 -s <mobile_ip> -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8900 -s <mobile_ip> -j ACCEPT
```

## 4. GhostTap Configuration

### 4.1 Setting RPC Endpoints

In the GhostTap app, navigate to Settings → Network and configure:

| Field | Value |
|-------|-------|
| RPC URL | `https://<vm1_ip>:38332` |
| GSP URL | `ws://<vm1_ip>:8900/gsp/ws/v1` |
| Username | `ghosttap` |
| Password | `<password>` |
| Network | Signet |

Add VM2-VM4 as fallback endpoints.

### 4.2 Rust Core Configuration

For development/testing via Rust directly:

```rust
use ghost_tap_core::network::client::{NodeClient, NodeConfig};

let config = NodeConfig {
    host: "<vm1_ip>".to_string(),
    port: 38332,
    username: "ghosttap".to_string(),
    password: "<password>".to_string(),
    use_tls: false,  // true if behind TLS proxy
    timeout_ms: 30000,
    network: Network::Signet,
};

let client = NodeClient::new(config);
```

## 5. Test Scenarios

### 5.1 Wallet Creation & Recovery

| # | Test | Steps | Expected |
|---|------|-------|----------|
| W1 | Create 24-word wallet | Tap "Create" → backup mnemonic → verify 3 words | Wallet created, balance = 0 |
| W2 | Create 12-word wallet | Same as W1 with 12-word option | Wallet created, balance = 0 |
| W3 | Import wallet | Tap "Import" → enter valid mnemonic | Wallet restored, syncs history |
| W4 | Import invalid mnemonic | Enter random words | Error: invalid mnemonic |
| W5 | Recovery determinism | Create on device A → import same mnemonic on device B | Same addresses, same balances |

### 5.2 Receiving Ghost

| # | Test | Steps | Expected |
|---|------|-------|----------|
| R1 | Generate address | Tap "Receive" | Fresh address displayed with QR |
| R2 | Receive payment | Send from node CLI to displayed address | Balance updates after sync |
| R3 | Multiple receives | Send 3 payments to different addresses | All appear in history, balance sums correctly |
| R4 | Pending → confirmed | Send payment, check before/after confirmation | Shows "Pending" then "Confirmed" |

**Send test coins from node CLI:**
```bash
ghost-cli -signet sendtoaddress <ghosttap_address> 10.0
```

### 5.3 Sending Ghost

| # | Test | Steps | Expected |
|---|------|-------|----------|
| S1 | Send payment | Enter address + amount → review → biometric → confirm | Tx broadcast, appears in history |
| S2 | Insufficient funds | Try to send more than balance | Error: insufficient funds |
| S3 | Invalid address | Enter garbage address | Error: invalid address |
| S4 | Fee selection | Send with low/medium/high fee | Different fees shown in review |
| S5 | Change output | Send partial balance | Change returned to wallet, balance correct |

### 5.4 QR Payments

| # | Test | Steps | Expected |
|---|------|-------|----------|
| Q1 | Generate QR | Tap "Receive" → show QR | Valid QR with ghost: URI |
| Q2 | Scan QR | Scan receive QR from another device | Pre-fills address and amount |
| Q3 | Merchant QR | Merchant enters amount → show QR → customer scans → pays | Payment received by merchant |
| Q4 | Invalid QR | Scan non-payment QR code | Error: not a valid payment QR |

### 5.5 NFC Payments (Android Only)

| # | Test | Steps | Expected |
|---|------|-------|----------|
| N1 | HCE activation | Open GhostTap, wallet unlocked | HCE service running |
| N2 | NFC payment | Merchant activates reader → customer taps | Payment processes, both see confirmation |
| N3 | Locked wallet tap | Lock wallet → tap merchant's reader | HCE responds "wallet locked" |
| N4 | iOS reads Android HCE | iOS merchant → Android customer tap | Payment processes via Core NFC |
| N5 | NFC timeout | Customer taps but network is slow | Graceful timeout, retry option |

### 5.6 Merchant Mode

| # | Test | Steps | Expected |
|---|------|-------|----------|
| M1 | Enable merchant mode | Settings → toggle "Merchant Mode" | Terminal and Business tabs appear |
| M2 | Terminal payment | Enter amount → customer pays via QR | Payment received, receipt generated |
| M3 | Receipt generation | Complete payment → "View Receipt" | HTML receipt renders correctly |
| M4 | Receipt sharing | Tap share on receipt | OS share sheet with PDF |
| M5 | Invoice creation | Create invoice with line items | Invoice HTML with QR code |
| M6 | Invoice payment | Customer scans invoice QR → pays | Invoice status → Paid |
| M7 | CSV export | Export → select date range → CSV | Valid CSV with transaction data |
| M8 | PDF export | Export → select date range → PDF | PDF report with summary + table |

### 5.7 Wraith Washing

| # | Test | Steps | Expected |
|---|------|-------|----------|
| WR1 | Manual wash | Receive payment → "Wash via Wraith" | Funds cycle through anon balance |
| WR2 | Auto-wash | Enable auto-wash → receive payment | Payment auto-queued for wash |
| WR3 | Wash queue | Queue 3 washes, max_concurrent=2 | 2 active, 1 queued |
| WR4 | Failed wash | Disconnect network during wash | Wash marked failed, retry available |

### 5.8 Edge Cases

| # | Test | Steps | Expected |
|---|------|-------|----------|
| E1 | Network disconnect | Turn off WiFi/cellular during sync | Graceful error, retry on reconnect |
| E2 | App backgrounding | Background app during send | Transaction completes or fails cleanly |
| E3 | Double-spend attempt | Try to spend same UTXOs twice | Second attempt rejected |
| E4 | Node failover | Kill primary node during operation | Automatic failover to next node |
| E5 | Concurrent access | Receive while sending | Both transactions process correctly |

## 6. Automated Testing

### 6.1 Rust Unit Tests

```bash
cargo test -p ghost-tap-core        # 118 tests
cargo test -p ghost-tap-integration  # 8 tests
```

### 6.2 Integration Test Against Live Node

> **TODO:** Write integration tests that connect to a real signet node:

```rust
#[tokio::test]
#[ignore]  // Requires live signet node
async fn test_live_sync() {
    let client = NodeClient::new(signet_config());
    let info = client.get_blockchain_info().await.unwrap();
    assert_eq!(info.chain, "signet");
}
```

### 6.3 Android UI Tests

```bash
cd android && ./gradlew connectedAndroidTest
```

### 6.4 iOS UI Tests

```bash
cd ios && xcodebuild test -scheme GhostTap -destination 'platform=iOS Simulator,name=iPhone 15'
```

## 7. Debugging

### 7.1 Rust Logging

Set `RUST_LOG` for verbose output:

```bash
RUST_LOG=ghost_tap_core=debug cargo test
```

In the mobile app, Rust tracing output goes to:
- **Android:** Logcat (tag: `ghost_tap`)
- **iOS:** Console.app / Xcode console

### 7.2 RPC Debugging

Test individual RPC calls:

```bash
# Get balance for an address
ghost-cli -signet getaddressbalance '{"addresses":["<address>"]}'

# List UTXOs
ghost-cli -signet listunspent 1 9999999 '["<address>"]'

# Get raw transaction
ghost-cli -signet getrawtransaction <txid> true
```

### 7.3 Network Debugging

```bash
# Check if RPC port is open
nc -zv <vm1_ip> 38332

# Test TLS (if using)
openssl s_client -connect <vm1_ip>:38332

# Monitor RPC calls on node
tail -f ~/.ghost/signet/debug.log | grep "RPC"
```

## 8. Known Issues & Workarounds

| Issue | Workaround |
|-------|-----------|
| First sync is slow | Expected — needs to scan all addresses for UTXOs |
| NFC timing out on first tap | Retry — HCE service may take a moment to initialize |
| Balance not updating | Pull-to-refresh or restart sync |
| Wraith wash stuck "InProgress" | Check node connectivity, may need manual retry |

## 9. Checklist Before Mainnet

- [ ] All test scenarios in Section 5 pass on physical devices
- [ ] No crashes in 24-hour soak test
- [ ] Failover tested: kill each node individually, wallet continues working
- [ ] Wraith washing completes end-to-end
- [ ] Receipt and invoice PDFs render correctly on both platforms
- [ ] CSV export opens correctly in Excel/Google Sheets
- [ ] Biometric authentication works on at least 3 different device models
- [ ] NFC payment tested on at least 2 different Android devices
- [ ] Memory profiling shows no leaks (especially around key material)
- [ ] Network traffic audit confirms no plaintext sensitive data
- [ ] `cargo audit` shows no known vulnerabilities

## 10. Known UI Gaps

The following features exist in the Rust core but are not yet wired into
the iOS/Android UI:

- **QR code scanning (Finding 13):** The `payment::qr` module generates and
  parses `ghost:` URIs, but the camera/scan UI is a native placeholder.
  The native layer must call `PaymentRequest::parse()` with the scanned
  string and pass the result to `build_transaction()`.

- **Simulate payment button (Finding 17):** For testnet testing, the app
  should expose a debug button that calls `wallet.add_utxo()` with a
  synthetic UTXO so that send/receive flows can be exercised without
  needing a faucet or mining setup.

## 11. Integration Test Approach

Integration tests live in `apps/ghost-tap/tests/integration/` and are run
with `cargo test -p ghost-tap-integration`. They exercise the Rust core
against a local signet node (or mock). Key test scenarios:

1. **Wallet roundtrip:** Generate → export mnemonic → re-import → verify
   same addresses.
2. **Transaction lifecycle:** Build unsigned → sign → serialize → verify
   signature → (optionally) broadcast.
3. **Sync flow:** Register addresses → trigger sync → verify UTXOs
   populated.
4. **Encrypted backup:** Export → import with correct password → verify
   same wallet ID. Import with wrong password → verify failure.

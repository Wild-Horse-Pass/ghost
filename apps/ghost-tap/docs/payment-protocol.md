# Payment Protocol Specification

**Version:** 0.2.0
**Last Updated:** 2026-03-01

---

## 1. Overview

GhostTap supports three payment methods:

| Method | Customer → Merchant | Platforms |
|--------|-------------------|-----------|
| QR Code | Scan merchant's QR, confirm payment | All |
| NFC Tap | Tap phone to merchant's reader | Android customer, Android/iOS merchant |
| Lightning Invoice | Scan Bolt11/Bolt12 QR | All (planned) |

## 2. QR Code Payment Protocol

### 2.1 URI Format

#### Ghost

```
ghost:<address>?amount=<sats>&memo=<text>&label=<text>
```

| Field | Required | Description |
|-------|----------|-------------|
| address | Yes | Ghost address (base58 or bech32) |
| amount | No | Amount in satoshis (integer) |
| memo | No | Payment memo (URL-encoded) |
| label | No | Recipient label (URL-encoded) |

| exp | No | Expiry timestamp (Unix seconds). Prevents replay. |
| net | No | Network identifier: `ghost`, `bitcoin`, `lightning` |

Examples:
```
ghost:GXj2k8f9aB3cD4eF5gH6iJ7kL8mN9oP0
ghost:GXj2k8f9aB3cD4eF5gH6iJ7kL8mN9oP0?amount=100000000&memo=Coffee&exp=1709312400
ghost:GXj2k8f9aB3cD4eF5gH6iJ7kL8mN9oP0?amount=50000&label=Bob%27s%20Shop&memo=Invoice%20%23123&net=ghost
```

#### Bitcoin (BIP21)

```
bitcoin:<address>?amount=<btc>&message=<text>&label=<text>
```

| Field | Required | Description |
|-------|----------|-------------|
| address | Yes | Bitcoin address (bech32 `bc1...` preferred) |
| amount | No | Amount in BTC (decimal) |
| message | No | Payment description |
| label | No | Recipient label |

#### Lightning

```
lightning:<bolt11_invoice>
```

Or LNURL:
```
lnurl:<bech32_encoded_url>
```

### 2.2 URI Parsing

The `PaymentRequest` struct in `core/src/payment/qr.rs` handles parsing:

```rust
pub struct PaymentRequest {
    pub address: String,
    pub amount: Option<u64>,
    pub memo: Option<String>,
    pub label: Option<String>,
}
```

Parsing rules:
1. Check scheme prefix (`ghost:`, `bitcoin:`, `lightning:`)
2. Extract address (everything between scheme and `?`)
3. Parse query parameters (standard URL encoding)
4. Check `exp` field — reject if expired
5. Check `net` field — warn if network mismatch (e.g., Ghost URI scanned while in Bitcoin mode)
6. Unknown parameters are ignored (forward compatibility)
7. Empty address → parse error
8. Non-numeric amount → parse error

### 2.3 QR Code Generation

**Merchant flow:**
1. Merchant enters amount on terminal keypad
2. System generates payment URI with merchant's receive address + amount
3. QR code rendered from URI string
4. Customer scans with GhostTap camera

**Receive flow:**
1. User taps "Receive" → system generates fresh address
2. QR code rendered from `ghost:<address>` (no amount)
3. Sender scans, enters amount, confirms

### 2.4 QR Code Scanning

**Android:** CameraX + Google MLKit Barcode Scanning
- `BarcodeScanner` with `FORMAT_QR_CODE` filter
- Returns decoded string → parsed as `PaymentRequest`

**iOS:** AVFoundation `AVCaptureSession`
- `AVCaptureMetadataOutput` with `.qr` metadata object type
- Returns decoded string → parsed as `PaymentRequest`

### 2.5 Multi-Network Detection

When scanning a QR code, GhostTap auto-detects the network from the URI scheme:

| Prefix | Network | Action |
|--------|---------|--------|
| `ghost:` | Ghost | Open Ghost send flow |
| `bitcoin:` | Bitcoin | Open Bitcoin send flow (if enabled) |
| `lightning:` | Lightning | Open Lightning send flow (if enabled) |
| `lnurl:` | Lightning | Resolve LNURL, then Lightning flow |
| No prefix | Unknown | Try to detect address format, ask user |

## 3. NFC Payment Protocol

### 3.1 Overview

NFC payments use Android's Host Card Emulation (HCE). The customer's phone emulates a contactless card, and the merchant's phone reads it.

```
┌──────────────┐          NFC           ┌──────────────┐
│   Customer   │ ◄─────────────────────► │   Merchant   │
│  (HCE card)  │   ISO 7816-4 APDU      │  (NFC reader)│
│              │                         │              │
│ Responds to  │                         │ Sends SELECT │
│ SELECT AID   │                         │ + payment req│
│ + payment    │                         │              │
│   response   │                         │ Reads payment│
│              │                         │   response   │
└──────────────┘                         └──────────────┘
```

### 3.2 Application ID (AID)

```
AID: F0474854415000
     F0 = proprietary
     47485441 = "GHTA" (ASCII)
     50 = payment
     00 = version 0
```

Registered in:
- Android: `res/xml/ghosttap_hce.xml`
- iOS: Core NFC entitlements

### 3.3 APDU Protocol

#### Step 1: SELECT AID

Merchant sends ISO 7816-4 SELECT command:

```
CLA: 00
INS: A4 (SELECT)
P1:  04 (by name)
P2:  00
Lc:  07 (AID length)
Data: F0 47 48 54 41 50 00
```

Customer HCE responds with payment capability:

```
SW1-SW2: 90 00 (success)
Data: 01 (version) + wallet status byte
```

Status byte:
- `0x00` = wallet locked (cannot pay)
- `0x01` = wallet ready

#### Step 2: Payment Request (Merchant → Customer)

Merchant sends payment request via APDU:

```
Binary format:
Offset  Size     Field
0       1        Version (0x01)
1       1        Message type (0x01 = PaymentRequest)
2       8        Amount (u64 big-endian, satoshis)
10      2        Address length (u16 big-endian)
12      N        Address (UTF-8)
12+N    2        Memo length (u16 big-endian, 0 if none)
14+N    M        Memo (UTF-8, optional)
```

Maximum payload: 256 bytes (ISO 7816 short APDU limit)

#### Step 3: Payment Response (Customer → Merchant)

Customer's wallet signs and broadcasts, then responds:

```
Binary format:
Offset  Size     Field
0       1        Version (0x01)
1       1        Message type (0x02 = PaymentResponse)
2       1        Status (0x00 = success, 0x01 = error)
3       2        TxID length (u16 big-endian)
5       N        TxID (hex string, typically 64 chars)
```

### 3.4 NFC Timing & Limits

NFC has strict timing constraints:
- **Initial response:** < 500ms (after SELECT)
- **Payment response:** < 5 seconds (allows time for signing + broadcast)
- If wallet is locked or processing, return status `0x00` (locked) immediately

**Maximum NFC payment:** Equivalent of 250 GBP fiat value (converted at current exchange rate). Payments exceeding this limit are rejected with status `0x01` and must use QR code flow instead.

**Authentication:** Biometric or 6-digit PIN required for ALL NFC payments, regardless of amount. No auto-sign threshold.

### 3.5 Error Handling

| Scenario | HCE Response |
|----------|-------------|
| Wallet locked | Status byte `0x00` in SELECT response |
| Insufficient funds | PaymentResponse with status `0x01` |
| Network error (can't broadcast) | PaymentResponse with status `0x01` |
| Invalid payment request | No response (disconnect) |
| Timeout during signing | PaymentResponse with status `0x01` |

### 3.6 iOS Core NFC (Merchant Reader)

iOS cannot emulate HCE but can READ NFC tags using Core NFC:

```swift
// NFCTagReaderSession with ISO-DEP (ISO 7816)
let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
session.alertMessage = "Hold customer's phone near reader"
session.begin()

// On tag detection:
// 1. Send SELECT AID
// 2. Send PaymentRequest APDU
// 3. Read PaymentResponse APDU
```

Required entitlement: `com.apple.developer.nfc.readersession.iso7816.select-identifiers` with AID `F0474854415000`.

### 3.7 Platform Support Matrix

| Customer OS | Merchant OS | Method | Notes |
|------------|------------|--------|-------|
| Android | Android | NFC | HCE ↔ NfcAdapter.ReaderCallback |
| Android | iOS | NFC | HCE ↔ Core NFC ISO-DEP |
| iOS | Android | QR | iOS cannot emulate HCE |
| iOS | iOS | QR | Neither can emulate |
| Any | Any | QR | Always available as fallback |

## 4. Payment Flow Sequences

### 4.1 QR Payment (Consumer → Merchant)

```
Merchant                          Customer
   │                                 │
   ├─ Enter amount on keypad         │
   ├─ Generate payment URI           │
   ├─ Display QR code                │
   │                                 │
   │         ◄── Scan QR ───         │
   │                                 ├─ Parse payment URI
   │                                 ├─ Show review (amount, address, fee)
   │                                 ├─ Biometric confirm
   │                                 ├─ Sign transaction
   │                                 ├─ Broadcast to network
   │                                 │
   ├─ Detect incoming tx (sync)      │
   ├─ Show confirmation              ├─ Show confirmation
   ├─ Generate receipt               │
   │                                 │
```

### 4.2 NFC Payment (Android Customer → Merchant)

```
Merchant                          Customer (Android)
   │                                 │
   ├─ Enter amount on keypad         │
   ├─ Activate NFC reader            │
   ├─ Display "Tap to pay"           │
   │                                 │
   │     ◄── Customer taps ──►       │
   │                                 │
   ├─ SELECT AID F0474854415000      │
   │                                 ├─ Respond: version + status
   ├─ Send PaymentRequest APDU       │
   │  (amount, address, memo)        │
   │                                 ├─ Display amount to user
   │                                 ├─ Auto-sign (or biometric)
   │                                 ├─ Broadcast to network
   │                                 ├─ Send PaymentResponse APDU
   │                                 │  (txid)
   ├─ Receive PaymentResponse        │
   ├─ Verify txid on network         │
   ├─ Show confirmation              ├─ Show confirmation
   ├─ Generate receipt               │
   │                                 │
```

### 4.3 Lightning Payment (Planned)

```
Merchant                          Customer
   │                                 │
   ├─ Enter amount                   │
   ├─ Create Bolt11 invoice          │
   ├─ Display invoice QR             │
   │                                 │
   │         ◄── Scan QR ───         │
   │                                 ├─ Decode Bolt11 invoice
   │                                 ├─ Show review (amount, description)
   │                                 ├─ Confirm payment
   │                                 ├─ LDK routes payment through LN
   │                                 │
   ├─ LDK receives payment           │
   ├─ Invoice marked paid            │
   ├─ Show confirmation              ├─ Show confirmation
   │                                 │
```

## 5. Resolved Design Decisions

- **NFC authentication:** Biometric or 6-digit PIN required for ALL NFC payments. No auto-sign threshold.
- **QR expiry:** Yes — `exp` field (Unix timestamp) included in payment URIs. Expired URIs are rejected.
- **NFC payment limit:** Maximum equivalent of 250 GBP fiat value. Exceeding requires QR flow.
- **Network identifier:** Yes — `net` field in payment URIs prevents cross-network address confusion.
- **Lightning LSP:** TBD — to be decided when Lightning integration begins.

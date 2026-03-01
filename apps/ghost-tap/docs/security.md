# Security Specification

**Version:** 0.2.0
**Last Updated:** 2026-03-01

---

## 1. Threat Model

### 1.1 Assets to Protect

| Asset | Sensitivity | Storage |
|-------|------------|---------|
| BIP39 mnemonic seed | CRITICAL | Platform keychain only (never in SQLite) |
| Private keys | CRITICAL | Derived on-demand, never persisted, zeroized after use |
| Wallet encryption key | HIGH | Platform keychain |
| Transaction history | MEDIUM | SQLite (plaintext — addresses visible on-chain anyway) |
| UTXO set | MEDIUM | SQLite (plaintext) |
| Merchant profile | LOW-MEDIUM | SQLite (tax ID encrypted) |
| RPC credentials | HIGH | SQLite (encrypted via KV store) |

### 1.2 Threat Actors

| Actor | Capability | Mitigation |
|-------|-----------|------------|
| Phone thief (locked device) | Physical access, device locked | Keychain requires device unlock, biometric gate |
| Phone thief (unlocked device) | Physical access, device unlocked | App-level biometric gate before signing |
| Malware on device | App sandbox escape, file access | Keychain hardware backing, no keys in SQLite |
| Network attacker (MITM) | Intercept/modify RPC traffic | TLS for all network connections |
| Malicious RPC node | Return false data | Verify transaction proofs (future), use own node |
| NFC eavesdropper | Read NFC communication | NFC range ~4cm, payment requires wallet unlock |
| QR code swapper | Replace merchant QR with attacker's | Verify address matches merchant profile |

### 1.3 Out of Scope (v1)

- Side-channel attacks (timing, power analysis)
- Rooted/jailbroken device protection
- Hardware wallet integration
- Multi-signature schemes
- Supply chain attacks on dependencies

## 2. Key Management

### 2.1 Key Derivation

```
BIP39 Mnemonic (12 or 24 words)
        │
        ▼ PBKDF2-HMAC-SHA512 (2048 rounds)
    512-bit Seed
        │
        ▼ BIP32 master key derivation
    Master Key (xprv)
        │
        ├─► m/44'/0'/0'  ── Ghost account key
        │       ├─► m/44'/0'/0'/0/n  ── Receive addresses
        │       └─► m/44'/0'/0'/1/n  ── Change addresses
        │
        ├─► m/44'/0'/0'    ── Bitcoin account key (planned)
        │       ├─► m/84'/0'/0'/0/n   ── Native SegWit receive
        │       └─► m/84'/0'/0'/1/n   ── Native SegWit change
        │
        └─► Lightning (LDK manages from same seed) (planned)
```

### 2.2 Key Lifecycle

1. **Generation:** `bip39::Mnemonic::generate()` using platform CSPRNG (`getrandom` crate → `/dev/urandom` on Linux, `SecRandomCopyBytes` on iOS, `java.security.SecureRandom` on Android)

2. **Backup:** Mnemonic displayed once during wallet creation. User must verify 3 random words. Mnemonic stored encrypted in platform keychain.

3. **Derivation:** Private keys derived on-demand from seed when signing. Never persisted to storage. `Zeroizing<[u8; 32]>` wrapper ensures memory cleanup.

4. **Usage:** Keys used only for transaction signing or message signing. Signing requires biometric confirmation.

5. **Destruction:** `zeroize` crate's `Drop` implementation overwrites key material with zeros. Seed material is wrapped in `secrecy::Secret`.

### 2.3 What Goes Where

| Data | Storage Location | Encryption |
|------|-----------------|------------|
| Mnemonic (encrypted) | Platform keychain | AES-256-GCM (keychain key) |
| Master encryption key | Platform keychain | Hardware-backed (where available) |
| Derived private keys | Memory only | Zeroizing wrapper |
| Public keys / addresses | SQLite | Plaintext (not sensitive) |
| RPC credentials | SQLite KV store | AES-256-GCM |
| Merchant tax ID | SQLite KV store | AES-256-GCM |

## 3. Platform Keychain

### 3.1 iOS: Keychain Services

```swift
let query: [String: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrService: "com.ghost.tap",
    kSecAttrAccount: key,
    kSecValueData: value,
    kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAttrAccessControl: SecAccessControlCreateWithFlags(
        nil,
        .biometryCurrentSet,  // Require biometric
        .privateKeyUsage,
        nil
    )
]
SecItemAdd(query as CFDictionary, nil)
```

Key attributes:
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — Not available when locked, not in backups
- `.biometryCurrentSet` — Invalidated if biometrics change (re-enrollment required)
- Backed by Secure Enclave on devices with it

### 3.2 Android: Keystore

```kotlin
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES,
    "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder("ghost_tap_master", PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(30, AUTH_BIOMETRIC_STRONG)
        .setIsStrongBoxBacked(true)  // If available
        .build()
)
```

Key attributes:
- Hardware-backed (StrongBox if available, TEE otherwise)
- Requires user authentication (biometric) within 30 seconds
- Not extractable from device
- Invalidated on biometric enrollment change

### 3.3 Desktop Fallback

For development and desktop (Tauri) builds:
- **macOS:** macOS Keychain via Security framework
- **Windows:** Windows Credential Manager (planned)
- **Linux:** Secret Service API via `libsecret` (planned)
- **Testing:** In-memory `DesktopFallbackKeychain` (HashMap, NOT for production)

## 4. Local Storage Encryption

### 4.1 SQLite Database

The database file is stored in the app's private directory:
- **Android:** `/data/data/com.ghost.tap/databases/ghosttap.db`
- **iOS:** `<app_container>/Library/Application Support/ghosttap.db`

The database itself is not encrypted (no SQLCipher). Instead, sensitive values are encrypted at the application layer before writing to the `kv_store` table.

### 4.2 AES-256-GCM Encryption

```rust
// core/src/crypto/mod.rs
pub fn encrypt_aes_gcm(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = generate_random_bytes(12);  // 96-bit nonce
    let cipher = Aes256Gcm::new(key.into());
    let ciphertext = cipher.encrypt(&nonce.into(), plaintext)?;
    // Prepend nonce to ciphertext: [nonce (12 bytes)][ciphertext][tag (16 bytes)]
    Ok([nonce.as_slice(), ciphertext.as_slice()].concat())
}
```

- **Key:** 256-bit, stored in platform keychain
- **Nonce:** 96-bit, randomly generated per encryption, prepended to ciphertext
- **Tag:** 128-bit authentication tag appended by AES-GCM
- **Storage format:** `[nonce:12][ciphertext:N][tag:16]` in SQLite BLOB

### 4.3 What's Encrypted vs Plaintext

| Table | Encrypted | Reason |
|-------|-----------|--------|
| `kv_store` | Values with `_encrypted` suffix | Contains seed, RPC creds, tax ID |
| `utxos` | No | Addresses are public on-chain |
| `history` | No | Transactions are public on-chain |
| `wallet_meta` | No | Contains indices and timestamps only |
| `merchant_profile` | Tax ID field only | Business info is semi-public |

## 5. Biometric Authentication

### 5.1 Authentication Methods

GhostTap supports three authentication methods, in order of preference:

1. **Biometric (Face ID / Touch ID / Fingerprint)** — Primary method
2. **6-digit PIN** — Fallback when biometrics unavailable or failed
3. **Device passcode** — Final fallback via OS (LAContext / BiometricPrompt)

The 6-digit PIN is set during wallet creation and stored hashed (SHA-256) in the platform keychain. It is NOT the same as the device lock PIN.

### 5.2 When Authentication Is Required

| Action | Auth Required |
|--------|---------------|
| View mnemonic | Yes |
| Sign transaction (send) | Yes |
| Sign NFC payment | Yes (ALL amounts, no auto-sign) |
| Unlock wallet after auto-lock | Yes |
| View balance | No |
| View history | No |
| Generate receive address | No |
| Create invoice | No |
| Export transactions | No |
| Change settings | No |

### 5.3 Authentication Fallback Chain

```
Biometric → 6-digit PIN → Device passcode
```

If biometric fails, prompt for 6-digit PIN. If PIN fails 5 times consecutively, require mnemonic re-import (wallet wipe + reimport).

### 5.4 Auto-Lock

The wallet automatically locks after a configurable period of inactivity:

| Setting | Default | Range |
|---------|---------|-------|
| Auto-lock timeout | 5 minutes | 1 min, 5 min, 15 min, 30 min, 1 hour |

When locked:
- Balance and history remain visible (read-only)
- All signing operations require re-authentication
- NFC HCE responds with "wallet locked" status
- Background sync continues (no auth needed for read-only operations)

### 5.5 Root / Jailbreak Detection

GhostTap detects rooted Android devices and jailbroken iOS devices:

**Android detection signals:**
- `su` binary present in PATH
- Magisk, SuperSU, or Xposed installed
- Test key build fingerprint
- `/system` mounted read-write

**iOS detection signals:**
- Cydia or Sileo installed
- Ability to write outside sandbox
- `fork()` succeeds (sandboxed apps can't fork)
- Known jailbreak paths exist

**Behavior on detection:**
- Show warning dialog: "Your device appears to be rooted/jailbroken. Key material may be accessible to other apps. Proceed at your own risk."
- Allow user to dismiss and continue (not a hard block)
- Log the detection event (without sensitive data)
- Do NOT refuse to operate — user has final say

### 5.6 Biometric Enrollment Changes

If the user adds or removes a fingerprint/face:
- Keychain items with `.biometryCurrentSet` (iOS) or biometric-bound keys (Android) are invalidated
- User must re-import wallet from mnemonic
- This prevents a thief from enrolling their biometrics to access the wallet

## 6. Network Security

### 6.1 Transport Security

| Connection | Protocol | Security |
|-----------|----------|----------|
| Ghost RPC | HTTPS | TLS 1.2+ (via rustls) |
| GSP WebSocket | WSS | TLS 1.2+ (via tokio-tungstenite + native-tls) |
| Bitcoin RPC | HTTPS | TLS 1.2+ |
| Electrum | SSL/TLS | TLS 1.2+ |
| Lightning (LDK) | Noise_XK | Lightning BOLT #8 encrypted transport |

### 6.2 RPC Authentication

- HTTP Basic Auth for Ghost and Bitcoin RPC
- JWT token for GSP (signed with BIP-340 Schnorr proof)
- Credentials stored encrypted in local SQLite KV store

### 6.3 Certificate Pinning

Certificate pinning is supported via `NodeConfig::with_pinned_cert(der_bytes)`. When a
pinned certificate is set, the `reqwest` TLS client disables built-in root certificates
and trusts only the pinned DER-encoded cert. GSP authentication functions (`register`,
`create_session`) accept a pre-configured `reqwest::Client` via `_with_client` variants
so the same pinning policy can be applied to GSP HTTP calls.

## 7. NFC Security

### 7.1 Physical Security

- NFC communication range: ~4cm (requires physical proximity)
- HCE only responds when wallet is unlocked
- Payment requires active user interaction (customer must have app open)

### 7.2 Replay Protection

- Each payment generates a unique transaction (new UTXO inputs, unique txid)
- NFC payment response includes the txid, which is verified on-chain
- No session tokens or bearer credentials are transmitted over NFC

### 7.3 Eavesdropping

- An attacker within NFC range could observe the payment amount and addresses
- This is equivalent to observing a public blockchain transaction (same information)
- Wraith washing mitigates address linkability after the fact

## 8. Memory Safety

### 8.1 Zeroization

All sensitive data uses `zeroize` crate wrappers:

```rust
use zeroize::{Zeroize, Zeroizing};

// Private key material
let private_key: Zeroizing<[u8; 32]> = derive_key(...);
// Automatically zeroized when dropped

// Seed material
let seed: Zeroizing<[u8; 64]> = derive_seed(mnemonic, passphrase);
// Automatically zeroized when dropped
```

### 8.2 Secret Wrapper

The `secrecy` crate provides `Secret<T>` for types that should not be logged or displayed:

```rust
use secrecy::{Secret, ExposeSecret};

let mnemonic: Secret<String> = Secret::new(mnemonic_string);
// Debug/Display prints "[REDACTED]"
// Must explicitly call .expose_secret() to access
```

### 8.3 Logging

- `tracing` crate is used for structured logging
- **Never log:** mnemonics, private keys, seeds, encryption keys, RPC passwords
- **OK to log:** public addresses, txids, block heights, error messages, sync status
- Debug builds may log more (amounts, address indices) — strip in release

## 9. Dependency Security

### 9.1 Supply Chain

- All dependencies pinned via `Cargo.lock`
- `rusqlite` uses `bundled` feature (compiles SQLite from source, no system dependency)
- `getrandom` uses platform CSPRNG (no custom entropy sources)
- TLS via `rustls` (pure Rust, no OpenSSL dependency for most targets)

### 9.2 Audit Status

| Crate | Audited | Notes |
|-------|---------|-------|
| bip39 | Community reviewed | Widely used in crypto wallets |
| secp256k1 | Heavily audited | Bitcoin Core's libsecp256k1 bindings |
| aes-gcm | RustCrypto project | Well-maintained, constant-time |
| rusqlite | Community reviewed | SQLite itself is extensively tested |
| uniffi | Mozilla | Used in Firefox |
| zeroize | RustCrypto project | Audited for correctness |

Run `cargo audit` regularly. Consider `cargo-vet` for supply chain verification.

## 10. Resolved Design Decisions

- **Panic wipe button:** No. Too high a risk of accidental data loss. Users can uninstall the app to clear data.
- **Auto-lock:** Yes. Configurable timeout (default 5 minutes). Wallet locks, requiring biometric/PIN to sign.
- **Root/jailbreak detection:** Yes. Warning dialog shown, but user can dismiss and continue.
- **Rate limiting on auth failures:** Yes. 5 consecutive PIN failures → require mnemonic re-import.
- **6-digit PIN:** Yes. Added as fallback to biometrics. Set during wallet creation.

## 11. Open Questions

- [ ] SQLCipher (full-database encryption) vs current per-value AES — TBD based on performance testing

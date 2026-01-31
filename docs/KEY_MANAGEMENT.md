# Key Management Guide

This document covers key management best practices for Bitcoin Ghost nodes, including key generation, storage, HSM integration, multi-sig treasury setup, and backup procedures.

## Overview

Bitcoin Ghost uses three types of cryptographic keys:

1. **Node Identity Key** - Ed25519 keypair for P2P authentication and consensus voting
2. **Treasury Address** - Bitcoin address (single or multi-sig) for pool fee collection
3. **Signing Key** (optional) - For registry authentication

## Node Identity Keys

### Key Generation

Node identity keys are Ed25519 keypairs with an optional proof-of-work to prevent Sybil attacks.

#### Generate New Identity

```bash
ghost-pool --generate-identity
```

This creates `~/.ghost/node.key` containing:
- 32 bytes: Ed25519 private key
- 12 bytes: PoW proof (nonce + difficulty)

#### View Identity

```bash
ghost-pool --show-identity
```

Output:
```
Node ID: a1b2c3d4...
Short ID: a1b2c3d4
Signer: local
```

### Key Storage

#### File-Based (Default)

Location: `~/.ghost/node.key`

**Required permissions:**
```bash
chmod 600 ~/.ghost/node.key
chmod 700 ~/.ghost
```

**Never:**
- Store keys in version control
- Share keys between nodes
- Copy keys over unencrypted channels

#### Configuration

```toml
[identity]
key_path = "~/.ghost/node.key"
display_name = "my-pool-node"

# Optional explicit signer config
[identity.signer]
type = "local"
key_path = "~/.ghost/node.key"
```

### HSM Integration

Hardware Security Modules provide the highest security for production nodes.

#### Supported HSM Types

- PKCS#11 compatible HSMs (Thales, Utimaco, etc.)
- YubiHSM 2
- AWS CloudHSM

#### HSM Configuration

```toml
[identity.signer]
type = "hsm"
library_path = "/usr/lib/pkcs11/libsofthsm2.so"  # PKCS#11 library
slot = 0                                          # HSM slot number
pin_env = "HSM_PIN"                               # Env var containing PIN
key_label = "ghost-node-key"                      # Key label in HSM
```

#### HSM Setup Steps

1. **Install PKCS#11 library**
   ```bash
   # For SoftHSM (testing)
   apt install softhsm2

   # For YubiHSM
   # Download from yubico.com
   ```

2. **Initialize HSM slot**
   ```bash
   # SoftHSM example
   softhsm2-util --init-token --slot 0 --label "ghost" --pin 1234 --so-pin 0000
   ```

3. **Generate key in HSM**
   ```bash
   # Use pkcs11-tool or HSM-specific tools
   pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
     --login --pin 1234 \
     --keypairgen --key-type EC:ed25519 \
     --label "ghost-node-key"
   ```

4. **Configure ghost-pool**
   ```bash
   export HSM_PIN=1234
   ghost-pool --config ghost.toml
   ```

#### HSM Security Recommendations

- Use a dedicated HSM for each production node
- Implement HSM backup procedures per vendor guidelines
- Use environment variables or secret managers for PINs
- Enable HSM audit logging
- Implement physical security for HSM devices

### KMS Integration

Cloud Key Management Services provide managed key security.

#### AWS KMS Configuration

```toml
[identity.signer]
type = "kms"
provider = "aws"
key_id = "arn:aws:kms:us-east-1:123456789:key/12345678-1234-1234-1234-123456789012"
region = "us-east-1"
```

#### AWS KMS Setup

1. **Create KMS key**
   ```bash
   aws kms create-key \
     --description "Ghost Node Identity Key" \
     --key-usage SIGN_VERIFY \
     --key-spec ECC_NIST_P256
   ```

2. **Configure IAM policy**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": [
         "kms:Sign",
         "kms:Verify",
         "kms:GetPublicKey"
       ],
       "Resource": "arn:aws:kms:us-east-1:123456789:key/*"
     }]
   }
   ```

3. **Set up credentials**
   ```bash
   # Use IAM role (recommended) or environment variables
   export AWS_ACCESS_KEY_ID=...
   export AWS_SECRET_ACCESS_KEY=...
   ```

## Treasury Address

### Single-Signature Treasury

For smaller pools or testnets:

```toml
[pool]
treasury_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
```

### Multi-Signature Treasury

For production pools, use M-of-N multi-sig (P2WSH):

```toml
[pool.treasury]
type = "multisig"
address = "bc1qft5p2uhsdcdc3l2ua4ap5qqfg4pjaqlp250x7us7a8qqhrxrxfsqseac85"
required = 2  # M signatures required
total = 3     # N total signers
witness_script = "522102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7d91d924106522d912102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f92102e4a72030de28e190fa4b3d0a47aece02195f2d5f2e1b1a8b7ff1234567890abc53ae"
pubkeys = [
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7d91d924106522d91",
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  "02e4a72030de28e190fa4b3d0a47aece02195f2d5f2e1b1a8b7ff1234567890abc"
]
```

### Creating a Multi-Sig Treasury

#### Step 1: Collect Public Keys

Each signer generates their key:
```bash
# Each signer runs:
bitcoin-cli getnewaddress "" bech32
bitcoin-cli getaddressinfo <address>
# Extract the pubkey field
```

#### Step 2: Create Multi-Sig Script

```bash
# 2-of-3 multi-sig
bitcoin-cli createmultisig 2 '["pubkey1","pubkey2","pubkey3"]' bech32
```

Output:
```json
{
  "address": "bc1q...",
  "redeemScript": "5221...53ae",
  "descriptor": "wsh(multi(2,...))"
}
```

#### Step 3: Configure Ghost

Use the output in your configuration:

```toml
[pool.treasury]
type = "multisig"
address = "<address from output>"
witness_script = "<redeemScript from output>"
required = 2
total = 3
pubkeys = ["pubkey1", "pubkey2", "pubkey3"]
```

### Multi-Sig Best Practices

- **Key distribution**: Store keys with different trusted parties
- **Geographic separation**: Keys in different physical locations
- **Threshold selection**:
  - 2-of-3 for small teams
  - 3-of-5 for larger organizations
  - Never use 1-of-N (defeats purpose)
- **Hardware wallets**: Use hardware wallets for multi-sig keys
- **Test spending**: Verify you can spend from the address on testnet first

## Backup and Recovery

### Encrypted Backups

#### Create Encrypted Backup

```bash
# Using GPG
gpg --symmetric --cipher-algo AES256 \
    --output ~/.ghost/node.key.gpg \
    ~/.ghost/node.key

# Store passphrase securely (separate from backup)
```

#### Restore from Backup

```bash
gpg --decrypt ~/.ghost/node.key.gpg > ~/.ghost/node.key
chmod 600 ~/.ghost/node.key
```

### Backup Storage

**Recommended locations:**
- Encrypted USB drive in physical safe
- Hardware security module backup partition
- Air-gapped system
- Secret management service (HashiCorp Vault, AWS Secrets Manager)

**Never store backups:**
- On the same system as the primary key
- In unencrypted cloud storage
- In email or messaging apps
- In version control

### Disaster Recovery

1. **Document recovery procedures**
   - Key locations
   - Required credentials/passphrases
   - Contact information for key holders

2. **Test recovery regularly**
   - Verify backup integrity monthly
   - Full recovery drill annually

3. **Multi-sig recovery**
   - Ensure M signers can be reached
   - Document signer succession plan

## Security Recommendations

### Local Key Security

- [ ] Key file permissions: `600`
- [ ] Parent directory permissions: `700`
- [ ] No world-readable paths to key
- [ ] Encrypted filesystem recommended
- [ ] Regular permission audits

### Network Security

- [ ] Firewall restricts P2P ports
- [ ] TLS for all external connections
- [ ] VPN for inter-node communication
- [ ] DDoS protection for public nodes

### Operational Security

- [ ] Limit key access to necessary personnel
- [ ] Audit trail for key access
- [ ] Separation of duties (different keys for different functions)
- [ ] Regular security reviews

### Monitoring

- [ ] Alert on key file access
- [ ] Monitor for unexpected signatures
- [ ] Track node identity changes
- [ ] Log all consensus votes

## Troubleshooting

### "Key file not found"

```
Error: Key file not found at ~/.ghost/node.key
```

**Solution:**
```bash
ghost-pool --generate-identity
```

### "Invalid key length"

```
Error: Invalid key length: expected 32 or 44, got X
```

**Solution:** Key file is corrupted. Restore from backup or generate new identity.

### "HSM slot not available"

```
Error: HSM slot 0 not available
```

**Solutions:**
- Verify HSM is connected and powered
- Check PKCS#11 library path
- Verify slot number in HSM configuration
- Ensure proper permissions for HSM device

### "KMS key not found"

```
Error: KMS key not found: arn:aws:kms:...
```

**Solutions:**
- Verify key ARN is correct
- Check IAM permissions
- Ensure AWS credentials are configured
- Verify region matches key location

## References

- [Ed25519 Specification](https://ed25519.cr.yp.to/)
- [BIP-141: Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [BIP-173: Bech32 Addresses](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
- [PKCS#11 Standard](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)

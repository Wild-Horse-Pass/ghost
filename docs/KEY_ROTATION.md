```
//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: KEY_ROTATION.md                                                                                                |
//|======================================================================================================================|
```

# Key Rotation Procedures

This document provides operational procedures for rotating node identity keys in Bitcoin Ghost.

## When to Rotate Keys

### Scheduled Rotation
- **Recommended interval**: Every 12-24 months for mainnet nodes
- **Best practice**: Rotate during planned maintenance windows
- **Coordination**: For pool operators, notify peers before rotation

### Triggered Rotation

Rotate immediately if:
- Private key file may have been exposed (backup theft, unauthorized access)
- Personnel with key access leave the organization
- Security audit recommends rotation
- Moving to a new HSM or KMS provider
- Upgrading from local keys to HSM/KMS

### Signs of Compromise
- Unexpected voting behavior attributed to your node
- Messages signed by your node that you didn't authorize
- Peers reporting conflicting signatures from your node_id

## Pre-Rotation Checklist

Before rotating your node identity:

1. **Backup current key**
   ```bash
   cp ~/.ghost/node.key ~/.ghost/node.key.backup-$(date +%Y%m%d)
   chmod 600 ~/.ghost/node.key.backup-*
   ```

2. **Record current node ID**
   ```bash
   ghost-pool --show-identity
   # Save the Node ID output for reference
   ```

3. **Notify peers** (for pool operators)
   - Inform other pool operators of your planned rotation
   - Provide new node_id after generation
   - Coordinate timing to minimize consensus disruption

4. **Check elder status**
   - **Important**: Rotating keys changes your node_id, which affects elder status
   - Elder status is tied to node_id - a new node_id must re-earn elder status
   - Consider using the elder transfer procedure (below) to preserve status

5. **Verify backup procedures**
   - Ensure you have secure backup storage ready for new key

## Rotation Procedure

### Step 1: Stop the Node

```bash
# Graceful shutdown
pkill -SIGTERM ghost-pool
# Wait for clean shutdown
sleep 5
```

### Step 2: Backup and Archive Old Key

```bash
# Create secure backup directory if needed
mkdir -p ~/.ghost/key-archive
chmod 700 ~/.ghost/key-archive

# Archive the old key with timestamp
mv ~/.ghost/node.key ~/.ghost/key-archive/node.key.$(date +%Y%m%d-%H%M%S)
```

### Step 3: Generate New Identity

```bash
# Generate new identity
ghost-pool --generate-identity

# Verify the new identity
ghost-pool --show-identity
```

### Step 4: Restart the Node

```bash
# Start with new identity
ghost-pool --config ghost.toml
```

### Step 5: Verify New Identity

```bash
# Check logs for successful startup
tail -f ~/.ghost/logs/ghost-pool.log

# Verify the node is participating in consensus
curl http://localhost:8080/health
```

## Post-Rotation Verification

1. **Confirm new node_id**
   ```bash
   ghost-pool --show-identity
   ```

2. **Check peer connectivity**
   ```bash
   curl http://localhost:8080/api/peers
   ```

3. **Verify consensus participation**
   - Monitor for vote messages in logs
   - Check for successful payout proposal handling

4. **Update external references**
   - Update seed node lists if you're a seed
   - Notify pool participants of new node_id
   - Update monitoring systems

## Emergency Rotation (Suspected Compromise)

If you suspect your key has been compromised:

### Immediate Actions

1. **Stop the node immediately**
   ```bash
   pkill -9 ghost-pool
   ```

2. **Preserve evidence** (don't delete the old key yet)
   ```bash
   cp ~/.ghost/node.key ~/.ghost/COMPROMISED-node.key-$(date +%Y%m%d)
   ```

3. **Generate new identity on a clean system**
   ```bash
   # On a separate, verified clean machine if possible
   ghost-pool --generate-identity --data-dir /secure/path
   ```

4. **Alert other operators**
   - Notify other pool operators immediately
   - Provide old node_id to blacklist
   - Provide new node_id for whitelisting

### Investigation

- Check access logs for the key file
- Review system access patterns
- Audit any backup systems that had the key
- Check for unauthorized SSH sessions or logins

### Recovery

1. Transfer new key to production system (over secure channel)
2. Verify key file permissions: `chmod 600 ~/.ghost/node.key`
3. Restart node with new identity
4. Monitor for any suspicious activity

## HSM Key Rotation

For nodes using Hardware Security Modules:

### Pre-Rotation

1. Ensure new HSM slot is available
2. Verify HSM backup procedures
3. Test key generation on HSM

### Rotation Steps

1. Generate new key in HSM
   ```toml
   # Update ghost.toml with new slot
   [identity.signer]
   type = "hsm"
   slot = 2  # New slot
   pin_env = "HSM_PIN"
   key_label = "ghost-node-2024"
   ```

2. Update node configuration
3. Restart node
4. Verify new identity
5. Secure old HSM slot (delete or archive per policy)

## KMS Key Rotation

For nodes using cloud Key Management Services:

### AWS KMS

1. Create new key in AWS KMS
2. Update IAM policies for new key ARN
3. Update ghost.toml with new key_id
4. Restart node
5. Schedule deletion of old key (30-day minimum)

### Configuration Update

```toml
[identity.signer]
type = "kms"
provider = "aws"
key_id = "arn:aws:kms:us-east-1:123456789:key/new-key-id"
region = "us-east-1"
```

## Rollback Procedure

If rotation fails and you need to restore the old identity:

1. Stop the node
2. Restore backup key
   ```bash
   cp ~/.ghost/key-archive/node.key.YYYYMMDD-HHMMSS ~/.ghost/node.key
   chmod 600 ~/.ghost/node.key
   ```
3. Restart the node
4. Verify old identity is active

**Warning**: Only roll back if the old key hasn't been compromised and peers haven't updated their records.

## Elder Status and Key Rotation

Key rotation affects elder status because elder status is tied to your node_id (derived from your public key). When you rotate keys:

1. Your new identity has a different node_id
2. The new node_id has no elder history
3. You may lose elder privileges until re-earned

### Preserving Elder Status (Future Feature)

A future update will support elder status transfer using cryptographic proofs:

```bash
# Generate rotation proof (signs new pubkey with old key)
ghost-pool --rotate-identity --transfer-elder

# This creates a KeyRotationProof that:
# 1. Links old node_id to new node_id
# 2. Proves ownership of both keys
# 3. Allows database to transfer elder status
```

Until this feature is implemented, carefully consider timing of key rotations:
- Avoid rotating during critical consensus periods
- Coordinate with other pool operators
- Accept temporary elder status loss

### Impact on Rewards

Mining rewards are typically tied to:
- Payout addresses (not node_id) - **Not affected by rotation**
- Share accounting (by miner_id) - **Not affected by rotation**

Node rewards (for running infrastructure) may be affected if they rely on elder status.

## Best Practices

- **Never share private keys** between nodes
- **Use HSM/KMS** for mainnet production nodes
- **Automate backups** but encrypt them at rest
- **Document rotations** with dates and reasons
- **Test rotation procedures** on testnet first
- **Keep old keys archived** (encrypted) for forensic purposes
- **Monitor for orphaned votes** after rotation

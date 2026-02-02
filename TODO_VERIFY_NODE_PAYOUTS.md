# TODO: Verify Node Payouts (Feb 1, 2026)

## Context
Node capability registration fix was deployed to all 4 VMs. VM1 (UK-LON1) went down due to UpCloud storage backend issue during testing. Miner needs restart to connect to VM2.

## What was deployed
1. **SRI Pool fix** - Decodes TDP coinbase outputs correctly (individual TxOut decode, not Vec)
2. **Node capabilities callback** - Health pings now register node capabilities with RoundManager
3. **Node reward fallback** - If no eligible nodes, node reward pool goes to treasury

## Commits
- sv2-apps: `69bd8d0b` - Fix TxOut decoding to handle SV2 raw output format
- ghost: `e6a19b4` - Update sv2-apps submodule + Wire up node capability registration

## IMPORTANT: Deployment path
- SRI Pool binary is `/opt/ghost/bin/pool_sv2` (NOT /opt/ghost/bin/pool!)

## To verify once miner connects to VM2

1. Watch logs for a block:
```bash
ssh ghost-vm2 "sudo journalctl -u ghost-pool -f" | grep -E "BLOCK FOUND|Built coinbase|nodes="
```

2. Check that coinbase shows `nodes=X` (should be 3-4, not 0):
```
Built coinbase with approved payout outputs height=XXXXX miners=1 nodes=3 treasury=XXXXX
```

3. If nodes=0 still, check if health pings are registering capabilities:
```bash
ssh ghost-vm2 "sudo journalctl -u ghost-pool --since '5 minutes ago' | grep -i 'node capabilities'"
```

## Expected payout distribution
- 99% to miners (49.5 BTC per block on signet)
- 0.5% to node reward pool (split by capability shares: 5-4-3-2-1)
- 0.5% to treasury (0.25 BTC)
- If no eligible nodes: node pool redirects to treasury (total 0.5 BTC to treasury)

## VMs
- VM1: 83.136.251.162 (UK-LON1) - was stuck, may need restart check
- VM2: 85.9.198.212
- VM3: 213.163.207.46
- VM4: 95.111.221.169

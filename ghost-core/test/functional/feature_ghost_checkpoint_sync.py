#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ghost Haze checkpoint P2P sync test.

Verifies end-to-end checkpoint generation, P2P download, and snapshot loading.

Setup:
- node0: --hazemode=full_archive (miner, generates checkpoint)
- node1: --hazemode=hazed (downloads checkpoint from node0 via P2P)

Test steps:
1. Mine deterministic chain on node0 to checkpoint height (160)
2. Generate checkpoint via generatecheckpoint RPC on node0
3. Restart node0 so it advertises NODE_HAZE_CHECKPOINT
4. Start node1 (hazed), sync headers from node0
5. Trigger checkpoint download via downloadcheckpoint RPC on node1
6. Wait for snapshot activation on node1
7. Verify UTXO set matches between nodes
8. Mine new blocks, sync forward, verify equivalence
9. Restart node1, verify persistence
"""

import os
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


# Must match a regtest assumeutxo entry in chainparams.cpp
SNAPSHOT_HEIGHT = 160


class GhostCheckpointSyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-hazemode=full_archive", "-disablewallet", "-debug=haze"],
            ["-hazemode=hazed", "-disablewallet", "-debug=haze", "-debug=net"],
        ]

    def skip_test_if_missing_module(self):
        pass  # No wallet needed

    def setup_network(self):
        # Start only node0 initially
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(0)

    def run_test(self):
        node0 = self.nodes[0]

        # Use mocktime for deterministic chain
        node0.setmocktime(node0.getblockheader(node0.getbestblockhash())['time'])

        self.log.info(f"Step 1: Mine {SNAPSHOT_HEIGHT} blocks on full_archive node")
        addr = node0.get_deterministic_priv_key().address
        self.generatetoaddress(node0, SNAPSHOT_HEIGHT, addr, sync_fun=self.no_op)
        assert_equal(node0.getblockcount(), SNAPSHOT_HEIGHT)

        self.log.info("Step 2: Record UTXO set info at snapshot height")
        utxo_info_0 = node0.gettxoutsetinfo()
        self.log.info(f"  height={utxo_info_0['height']} txouts={utxo_info_0['txouts']} "
                      f"hash={utxo_info_0['hash_serialized_3']}")

        self.log.info("Step 3: Generate checkpoint via RPC")
        checkpoint_dir = os.path.join(node0.datadir_path, "regtest", "checkpoint")
        result = node0.generatecheckpoint(SNAPSHOT_HEIGHT, checkpoint_dir)
        self.log.info(f"  Checkpoint: height={result['height']} chunks={result['total_chunks']} "
                      f"utxo_count={result['utxo_count']}")
        assert_equal(result['height'], SNAPSHOT_HEIGHT)
        assert result['total_chunks'] > 0, "Expected at least 1 chunk"
        assert result['utxo_count'] > 0, "Expected non-zero UTXO count"

        # Verify checkpoint files exist
        assert Path(checkpoint_dir, "manifest.bin").exists()
        assert Path(checkpoint_dir, "headers.bin").exists()
        assert Path(checkpoint_dir, "bloom.bin").exists()
        assert Path(checkpoint_dir, "utxo_0.bin").exists()

        self.log.info("Step 4: Restart node0 to advertise NODE_HAZE_CHECKPOINT")
        self.restart_node(0, extra_args=self.extra_args[0])
        node0 = self.nodes[0]

        self.log.info("Step 5: Start hazed node and sync headers")
        self.start_node(1)
        node1 = self.nodes[1]

        # Feed headers from node0 to node1
        for i in range(1, SNAPSHOT_HEIGHT + 1):
            block_hex = node0.getblock(node0.getblockhash(i), 0)
            node1.submitheader(block_hex)

        assert_equal(node1.getblockchaininfo()["headers"], SNAPSHOT_HEIGHT)
        self.log.info(f"  node1 headers synced to {SNAPSHOT_HEIGHT}")

        self.log.info("Step 6: Connect nodes and trigger checkpoint download")
        self.connect_nodes(1, 0)

        # Get the peer id for node0 from node1's perspective
        peers = node1.getpeerinfo()
        node0_peer_id = None
        for p in peers:
            node0_peer_id = p['id']
            break
        assert node0_peer_id is not None, "node1 should be connected to node0"

        dl_result = node1.downloadcheckpoint(node0_peer_id)
        self.log.info(f"  downloadcheckpoint result: {dl_result}")
        assert dl_result['requested'], "downloadcheckpoint should succeed"

        self.log.info("Step 7: Wait for snapshot activation on node1")
        # Wait for the checkpoint download and snapshot activation
        def check_snapshot_loaded():
            try:
                chainstates = node1.getchainstates()['chainstates']
                snapshot_cs = [cs for cs in chainstates if 'snapshot_blockhash' in cs]
                return len(snapshot_cs) == 1
            except Exception:
                return False

        self.wait_until(check_snapshot_loaded, timeout=120)
        self.log.info("  Snapshot activated on node1!")

        self.log.info("Step 8: Verify UTXO set matches at checkpoint height")
        utxo_info_1 = node1.gettxoutsetinfo(use_index=False)
        assert_equal(utxo_info_0['hash_serialized_3'], utxo_info_1['hash_serialized_3'])
        assert_equal(utxo_info_0['txouts'], utxo_info_1['txouts'])
        self.log.info("  UTXO hashes match!")

        self.log.info("Step 9: Mine 10 new blocks on node0, sync to node1")
        self.generatetoaddress(node0, 10, addr)
        self.sync_blocks()

        final_height = SNAPSHOT_HEIGHT + 10
        assert_equal(node0.getblockcount(), final_height)
        assert_equal(node1.getblockcount(), final_height)
        self.log.info(f"  Both nodes at height {final_height}")

        self.log.info("Step 10: Verify final UTXO equivalence")
        utxo_final_0 = node0.gettxoutsetinfo()
        utxo_final_1 = node1.gettxoutsetinfo(use_index=False)
        assert_equal(utxo_final_0['hash_serialized_3'], utxo_final_1['hash_serialized_3'])
        assert_equal(utxo_final_0['txouts'], utxo_final_1['txouts'])
        self.log.info("  Final UTXO hashes match!")

        self.log.info("Step 11: Verify node1 has GSB files")
        blocks_dir_1 = Path(node1.chain_path) / "blocks"
        gsb_files = list(blocks_dir_1.glob("gsb*.dat"))
        assert len(gsb_files) > 0, f"Expected gsb files in {blocks_dir_1}"
        self.log.info(f"  node1 has {len(gsb_files)} gsb file(s)")

        self.log.info("Step 12: Restart node1, verify persistence")
        self.restart_node(1, extra_args=self.extra_args[1])
        node1 = self.nodes[1]

        self.wait_until(lambda: len(node1.getchainstates()['chainstates']) == 1)
        assert_equal(node1.getblockcount(), final_height)

        utxo_restart = node1.gettxoutsetinfo(use_index=False)
        assert_equal(utxo_final_0['hash_serialized_3'], utxo_restart['hash_serialized_3'])
        self.log.info("  Post-restart UTXO hash matches!")

        self.log.info("PASSED: Checkpoint P2P sync completed successfully")


if __name__ == "__main__":
    GhostCheckpointSyncTest(__file__).main()

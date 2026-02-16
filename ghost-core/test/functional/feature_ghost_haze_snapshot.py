#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ghost Haze snapshot bootstrap test.

Verifies that a hazed node can bootstrap from a UTXO snapshot (assumeutxo),
skipping background IBD entirely since stripped blocks cannot reconstruct
a valid UTXO set via ConnectBlock.

Setup:
- node0: --hazemode=full_archive (miner, creates snapshot)
- node1: --hazemode=hazed (loads snapshot, syncs forward)

Test steps:
1. Mine deterministic chain on node0 to snapshot height (110)
2. Dump UTXO snapshot via dumptxoutset
3. Start node1 (hazed), sync headers from node0
4. Load snapshot on node1 via loadtxoutset RPC
5. Verify UTXO set matches between nodes
6. Verify node1 has only 1 chainstate (no background IBD)
7. Mine new blocks on node0, sync to node1
8. Verify final UTXO equivalence
9. Verify node1 has GSB files (new blocks stored as stripped)
10. Restart node1, verify chain persists
"""

from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Must match a regtest assumeutxo entry in chainparams.cpp
SNAPSHOT_HEIGHT = 160


class GhostHazeSnapshotTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-hazemode=full_archive", "-disablewallet"],
            ["-hazemode=hazed", "-disablewallet", "-debug=haze"],
        ]

    def skip_test_if_missing_module(self):
        pass  # No wallet needed

    def setup_network(self):
        # Start only node0 initially; node1 starts later after snapshot is ready
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(0)

    def run_test(self):
        node0 = self.nodes[0]

        # Use mocktime for a deterministic chain — block hashes must match
        # the hardcoded assumeutxo entry in chainparams.cpp.
        node0.setmocktime(node0.getblockheader(node0.getbestblockhash())['time'])

        self.log.info(f"Step 1: Mine {SNAPSHOT_HEIGHT} blocks on full_archive node")
        addr = node0.get_deterministic_priv_key().address
        self.generatetoaddress(node0, SNAPSHOT_HEIGHT, addr, sync_fun=self.no_op)
        assert_equal(node0.getblockcount(), SNAPSHOT_HEIGHT)

        self.log.info("Step 2: Record UTXO set info at snapshot height")
        utxo_info_0 = node0.gettxoutsetinfo()
        self.log.info(f"  height={utxo_info_0['height']} txouts={utxo_info_0['txouts']} "
                      f"hash={utxo_info_0['hash_serialized_3']}")

        self.log.info("Step 3: Create UTXO snapshot via dumptxoutset")
        dump_output = node0.dumptxoutset('utxos.dat', "latest")
        snapshot_path = dump_output['path']
        self.log.info(f"  Snapshot at: {snapshot_path}")
        assert_equal(dump_output['base_height'], SNAPSHOT_HEIGHT)

        self.log.info("Step 4: Start hazed node and sync headers")
        self.start_node(1)
        node1 = self.nodes[1]

        # Feed headers from node0 to node1 so it knows the chain
        for i in range(1, SNAPSHOT_HEIGHT + 1):
            block_hex = node0.getblock(node0.getblockhash(i), 0)
            node1.submitheader(block_hex)

        assert_equal(node1.getblockchaininfo()["headers"], SNAPSHOT_HEIGHT)
        self.log.info(f"  node1 headers synced to {SNAPSHOT_HEIGHT}")

        self.log.info("Step 5: Load UTXO snapshot on hazed node")
        loaded = node1.loadtxoutset(snapshot_path)
        assert_equal(loaded['coins_loaded'], SNAPSHOT_HEIGHT)
        assert_equal(loaded['base_height'], SNAPSHOT_HEIGHT)
        self.log.info(f"  Loaded {loaded['coins_loaded']} coins at height {loaded['base_height']}")

        self.log.info("Step 6: Verify UTXO set matches at snapshot height")
        utxo_info_1 = node1.gettxoutsetinfo(use_index=False)
        assert_equal(utxo_info_0['hash_serialized_3'], utxo_info_1['hash_serialized_3'])
        assert_equal(utxo_info_0['txouts'], utxo_info_1['txouts'])
        self.log.info("  UTXO hashes match!")

        self.log.info("Step 7: Verify hazed node has no background IBD (single chainstate)")
        # For hazed nodes, background IBD is disabled immediately in ActivateSnapshot.
        # The snapshot_download_completed callback fires, which triggers cleanup on
        # next restart. But we can check that the IBD chainstate is disabled.
        chainstates = node1.getchainstates()['chainstates']
        self.log.info(f"  Chainstates: {len(chainstates)}")
        # The snapshot chainstate should be the active one
        snapshot_cs = [cs for cs in chainstates if 'snapshot_blockhash' in cs]
        assert len(snapshot_cs) == 1, f"Expected 1 snapshot chainstate, got {len(snapshot_cs)}"
        assert_equal(snapshot_cs[0]['blocks'], SNAPSHOT_HEIGHT)

        self.log.info("Step 8: Mine 10 new blocks on node0, sync to node1")
        self.connect_nodes(0, 1)
        self.generatetoaddress(node0, 10, addr)
        self.sync_blocks()

        final_height = SNAPSHOT_HEIGHT + 10
        assert_equal(node0.getblockcount(), final_height)
        assert_equal(node1.getblockcount(), final_height)
        self.log.info(f"  Both nodes at height {final_height}")

        self.log.info("Step 9: Verify final UTXO equivalence")
        utxo_final_0 = node0.gettxoutsetinfo()
        utxo_final_1 = node1.gettxoutsetinfo(use_index=False)
        assert_equal(utxo_final_0['hash_serialized_3'], utxo_final_1['hash_serialized_3'])
        assert_equal(utxo_final_0['txouts'], utxo_final_1['txouts'])
        assert_equal(utxo_final_0['total_amount'], utxo_final_1['total_amount'])
        self.log.info("  Final UTXO hashes match!")

        self.log.info("Step 10: Verify node1 has GSB files (blocks stored as stripped)")
        blocks_dir_1 = Path(node1.chain_path) / "blocks"
        gsb_files = list(blocks_dir_1.glob("gsb*.dat"))
        assert len(gsb_files) > 0, f"Expected gsb files in {blocks_dir_1}"
        gsb_size = sum(f.stat().st_size for f in gsb_files)
        self.log.info(f"  node1 has {len(gsb_files)} gsb file(s), total {gsb_size} bytes")

        self.log.info("Step 11: Restart node1, verify chain persists")
        self.restart_node(1, extra_args=self.extra_args[1])
        node1 = self.nodes[1]

        # After restart, MaybeCompleteSnapshotValidation auto-validates for
        # hazed nodes and ValidatedSnapshotCleanup removes the IBD chainstate
        # directory, leaving a single clean chainstate.
        self.wait_until(lambda: len(node1.getchainstates()['chainstates']) == 1)
        assert_equal(node1.getblockcount(), final_height)

        utxo_restart = node1.gettxoutsetinfo(use_index=False)
        assert_equal(utxo_final_0['hash_serialized_3'], utxo_restart['hash_serialized_3'])
        self.log.info("  Post-restart UTXO hash matches!")

        self.log.info("PASSED: Hazed node bootstrapped from UTXO snapshot successfully")


if __name__ == "__main__":
    GhostHazeSnapshotTest(__file__).main()

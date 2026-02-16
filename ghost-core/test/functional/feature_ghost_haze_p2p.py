#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test Ghost Haze cross-mode P2P interoperability.

Verifies:
- Mode A <-> Mode A block propagation
- Mode A <-> Mode B block propagation (both directions)
- NODE_GHOST_HAZE service flag advertisement
- Chain sync consistency across all modes
- UTXO set equivalence across all 3 nodes
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


# NODE_GHOST_HAZE = (1 << 14) = 16384
NODE_GHOST_HAZE = 1 << 14


class GhostHazeP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ["-hazemode=hazed"],        # node0: hazed
            ["-hazemode=hazed"],        # node1: hazed
            ["-hazemode=full_archive"], # node2: full_archive
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        # During IBD, only connect hazed nodes to full_archive.
        # Avoid connecting hazed nodes to each other during bulk mining
        # because hazed nodes store stripped blocks (GSB) which can't be
        # served via ReadRawBlock during concurrent block relay.
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)
        self.sync_all()

    def run_test(self):
        node0 = self.nodes[0]  # hazed
        node1 = self.nodes[1]  # hazed
        node2 = self.nodes[2]  # full_archive

        self.log.info("Mine initial blocks on full_archive for maturity")
        self.generate(node2, 110)

        self.log.info("Transfer funds to hazed nodes for testing")
        for _ in range(5):
            node2.sendtoaddress(node0.getnewaddress(), 10.0)
        self.generate(node2, 1)

        # Now connect hazed nodes to each other for P2P tests
        self.log.info("Connect hazed nodes to each other")
        self.connect_nodes(0, 1)

        # === Test 1: Mode A <-> Mode A block propagation ===
        self.log.info("Test 1: Hazed -> Hazed block propagation")
        # Mine one at a time so each block is in cache for peer serving
        blocks_from_0 = []
        for _ in range(5):
            blocks_from_0.extend(self.generate(node0, 1))

        # Verify node1 (also hazed) received the blocks
        assert_equal(node1.getblockcount(), node0.getblockcount())
        for bh in blocks_from_0:
            block = node1.getblock(bh, 1)
            assert_equal(block["hash"], bh)

        self.log.info("  Hazed -> Hazed: OK")

        # === Test 2: Mode A <-> Mode B block propagation ===
        self.log.info("Test 2: Full Archive -> Hazed block propagation")

        # Mine on node2 (full_archive), verify node0 (hazed) receives
        blocks_from_2 = self.generate(node2, 5)
        assert_equal(node0.getblockcount(), node2.getblockcount())
        for bh in blocks_from_2:
            block = node0.getblock(bh, 1)
            assert_equal(block["hash"], bh)

        self.log.info("  Full Archive -> Hazed: OK")

        self.log.info("Test 2b: Hazed -> Full Archive block propagation")

        # Mine on node0 (hazed), verify node2 (full_archive) receives
        # One at a time so each block is cache-served
        blocks_from_0b = []
        for _ in range(5):
            blocks_from_0b.extend(self.generate(node0, 1))
        assert_equal(node2.getblockcount(), node0.getblockcount())
        for bh in blocks_from_0b:
            block = node2.getblock(bh, 1)
            assert_equal(block["hash"], bh)

        self.log.info("  Hazed -> Full Archive: OK")

        # === Test 3: Service flag verification ===
        self.log.info("Test 3: NODE_GHOST_HAZE service flag verification")

        # Check service flags via getnetworkinfo
        net_info0 = node0.getnetworkinfo()
        net_info1 = node1.getnetworkinfo()
        net_info2 = node2.getnetworkinfo()

        # Hazed nodes should advertise NODE_GHOST_HAZE
        local_services0 = int(net_info0["localservices"], 16)
        local_services1 = int(net_info1["localservices"], 16)
        local_services2 = int(net_info2["localservices"], 16)

        assert_equal(local_services0 & NODE_GHOST_HAZE, NODE_GHOST_HAZE)
        assert_equal(local_services1 & NODE_GHOST_HAZE, NODE_GHOST_HAZE)

        # Full archive node should NOT advertise NODE_GHOST_HAZE
        assert_equal(local_services2 & NODE_GHOST_HAZE, 0)

        self.log.info("  Service flags: OK")

        # === Test 4: Chain sync across modes ===
        self.log.info("Test 4: Chain sync consistency across all modes")

        # Mine some more blocks with transactions (one at a time on hazed node)
        for _ in range(3):
            addr = node0.getnewaddress()
            node0.sendtoaddress(addr, 1.0)
            self.generate(node0, 1)

        # Ensure all nodes are at the same tip
        self.sync_all()

        assert_equal(node0.getblockcount(), node1.getblockcount())
        assert_equal(node0.getblockcount(), node2.getblockcount())
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        assert_equal(node0.getbestblockhash(), node2.getbestblockhash())

        self.log.info("  All 3 nodes at same chain tip: OK")

        # Verify UTXO set consistency across all nodes
        self.log.info("  Checking UTXO set consistency...")
        utxo0 = node0.gettxoutsetinfo()
        utxo1 = node1.gettxoutsetinfo()
        utxo2 = node2.gettxoutsetinfo()

        assert_equal(utxo0["hash_serialized_3"], utxo1["hash_serialized_3"])
        assert_equal(utxo0["hash_serialized_3"], utxo2["hash_serialized_3"])
        assert_equal(utxo0["txouts"], utxo1["txouts"])
        assert_equal(utxo0["txouts"], utxo2["txouts"])

        self.log.info("  UTXO sets identical across all 3 nodes: OK")

        self.log.info("All Ghost Haze P2P tests passed")


if __name__ == "__main__":
    GhostHazeP2PTest(__file__).main()

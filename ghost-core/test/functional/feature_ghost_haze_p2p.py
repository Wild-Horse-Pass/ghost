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
        # Connect all nodes in a mesh
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)
        self.sync_all()

    def run_test(self):
        node0 = self.nodes[0]  # hazed
        node1 = self.nodes[1]  # hazed
        node2 = self.nodes[2]  # full_archive

        self.log.info("Mine initial blocks for maturity")
        self.generate(node0, 110)

        # === Test 1: Mode A <-> Mode A block propagation ===
        self.log.info("Test 1: Hazed -> Hazed block propagation")
        blocks_from_0 = self.generate(node0, 5)

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
        blocks_from_0b = self.generate(node0, 5)
        assert_equal(node2.getblockcount(), node0.getblockcount())
        for bh in blocks_from_0b:
            block = node2.getblock(bh, 1)
            assert_equal(block["hash"], bh)

        self.log.info("  Hazed -> Full Archive: OK")

        # === Test 3: Service flag verification ===
        self.log.info("Test 3: NODE_GHOST_HAZE service flag verification")

        # Check node0's peers to find node1 and node2
        peers_0 = node0.getpeerinfo()
        for peer in peers_0:
            services = peer["services"]
            services_int = int(services, 16)
            # We can't easily tell which peer is which by IP in regtest,
            # but we can verify the local node's own service flags via getnetworkinfo
            pass

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

        # Mine some more blocks with transactions
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

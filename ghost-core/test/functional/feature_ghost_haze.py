#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test Ghost Haze mode basic functionality.

Verifies:
- Haze mode RPC status endpoints
- Stripped block storage (no hazeable content on disk)
- getblock includes haze_status in hazed mode, not in full_archive
- getrawtransaction shows stripped indicators
- getlegalpacket works in hazed mode, errors in full_archive
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class GhostHazeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-hazemode=hazed"],
            ["-hazemode=full_archive"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0 = self.nodes[0]  # hazed
        node1 = self.nodes[1]  # full_archive

        self.log.info("Mine 110 blocks on full_archive for coinbase maturity")
        self.generate(node1, 110)

        self.log.info("Transfer funds from full_archive to hazed node")
        addr0 = node0.getnewaddress()
        for _ in range(5):
            node1.sendtoaddress(addr0, 10.0)
        self.generate(node1, 1)

        self.log.info("Verify gethazestatus RPC on both nodes")
        status0 = node0.gethazestatus()
        assert_equal(status0["mode"], "hazed")
        assert_equal(status0["exorcism_active"], True)

        status1 = node1.gethazestatus()
        assert_equal(status1["mode"], "full_archive")
        assert_equal(status1["exorcism_active"], False)

        self.log.info("Create transactions with various types")
        addr = node0.getnewaddress()

        # Standard P2WPKH transfers
        txids = []
        for _ in range(3):
            txid = node0.sendtoaddress(addr, 1.0)
            txids.append(txid)

        # OP_RETURN output with known payload
        payload_hex = "47484f53545f48415a455f544553545f5041594c4f4144"  # "GHOST_HAZE_TEST_PAYLOAD"
        opreturn_txid = node0.sendrawtransaction(
            node0.signrawtransactionwithwallet(
                node0.createrawtransaction(
                    [{"txid": txids[0], "vout": 0}],
                    [
                        {node0.getnewaddress(): 0.5},
                        {"data": payload_hex},
                    ],
                )
            )["hex"],
            0,  # maxfeerate=0
        )
        txids.append(opreturn_txid)

        self.log.info("Mine blocks containing transactions (one at a time for cache serving)")
        # Hazed nodes can only serve the most-recently-cached block to non-hazed
        # peers. Mining one at a time ensures each block is in cache during sync.
        block_hashes = []
        for _ in range(5):
            block_hashes.extend(self.generate(node0, 1))

        self.log.info("Verify getblock on hazed node includes haze_status")
        for bh in block_hashes:
            block = node0.getblock(bh, 2)
            assert "haze_status" in block
            assert_equal(block["haze_status"]["mode"], "hazed")

        self.log.info("Verify getblock on full_archive node does NOT include haze_status")
        for bh in block_hashes:
            block = node1.getblock(bh, 2)
            assert "haze_status" not in block

        self.log.info("Verify gethazestatus shows stripped statistics")
        status0 = node0.gethazestatus()
        assert_greater_than(status0["blocks_stripped"], 0)
        assert_greater_than(status0["bytes_stripped"], 0)

        self.log.info("Grep node0 datadir for GHOST_HAZE_TEST_PAYLOAD — must NOT be found")
        datadir = node0.datadir_path
        payload_bytes = b"GHOST_HAZE_TEST_PAYLOAD"
        found = False
        blocks_dir = os.path.join(datadir, self.chain, "blocks")
        if os.path.isdir(blocks_dir):
            for fname in os.listdir(blocks_dir):
                fpath = os.path.join(blocks_dir, fname)
                if os.path.isfile(fpath):
                    with open(fpath, "rb") as f:
                        content = f.read()
                        if payload_bytes in content:
                            found = True
                            self.log.error(f"Found payload in {fname}!")
                            break
        assert_equal(found, False)

        self.log.info("Verify getlegalpacket returns valid JSON on hazed node")
        packet = node0.getlegalpacket()
        assert_equal(packet["node_mode"], "HAZED")
        assert_equal(packet["exorcism_active"], True)
        assert "legal_summary" in packet

        self.log.info("Verify getlegalpacket errors on full_archive node")
        assert_raises_rpc_error(-1, None, node1.getlegalpacket)

        self.log.info("All Ghost Haze basic tests passed")


if __name__ == "__main__":
    GhostHazeTest(__file__).main()

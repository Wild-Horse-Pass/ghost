#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test Ghost Exorcism: archive-to-hazed conversion.

Verifies:
- Full archive node stores blk*.dat files normally
- --exorcist flag converts blk*.dat to gsb*.dat
- After conversion, node restarts in hazed mode
- Converted node can still serve blocks via getblock
- Known OP_RETURN payloads are NOT present on disk after conversion
- Node continues to function normally after conversion (mines new blocks)
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class GhostExorcismTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-hazemode=full_archive"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mine 50 blocks with OP_RETURN payloads")
        self.generate(node, 110)  # Maturity

        # Create transactions with identifiable payloads
        payload_hex = "4558_4f52_4349_534d_5f54_4553_54".replace("_", "")  # "EXORCISM_TEST"
        block_hashes = []
        for i in range(5):
            addr = node.getnewaddress()
            txid = node.sendtoaddress(addr, 1.0)
            # Create OP_RETURN
            raw = node.createrawtransaction(
                node.listunspent(1, 9999, [], True, {"minimumAmount": 0.1})[:1],
                [
                    {node.getnewaddress(): 0.05},
                    {"data": payload_hex},
                ],
            )
            signed = node.signrawtransactionwithwallet(raw)
            node.sendrawtransaction(signed["hex"])
            bh = self.generate(node, 1)
            block_hashes.extend(bh)

        total_blocks = node.getblockcount()
        self.log.info(f"Chain height: {total_blocks}")

        self.log.info("Stop node and verify blk*.dat files exist")
        self.stop_node(0)
        blocks_dir = os.path.join(node.datadir_path, self.chain, "blocks")
        blk_files = [f for f in os.listdir(blocks_dir) if f.startswith("blk") and f.endswith(".dat")]
        assert_greater_than(len(blk_files), 0)

        self.log.info("Restart with --exorcist flag to convert")
        # The --exorcist flag converts and exits; we need to handle the expected shutdown
        self.start_node(0, extra_args=["-hazemode=full_archive", "-exorcist"])
        # Wait for conversion to complete — node will shut down after conversion
        self.wait_for_node_exit(0, timeout=120)

        self.log.info("Verify gsb*.dat files exist after conversion")
        gsb_files = [f for f in os.listdir(blocks_dir) if f.startswith("gsb") and f.endswith(".dat")]
        assert_greater_than(len(gsb_files), 0)

        self.log.info("Verify blk*.dat files are removed after conversion")
        blk_files_after = [f for f in os.listdir(blocks_dir) if f.startswith("blk") and f.endswith(".dat")]
        assert_equal(len(blk_files_after), 0)

        self.log.info("Restart in hazed mode")
        self.start_node(0, extra_args=["-hazemode=hazed"])

        self.log.info("Verify getblock still works for all previously mined blocks")
        for bh in block_hashes:
            block = node.getblock(bh, 1)
            assert "hash" in block
            assert_equal(block["hash"], bh)

        self.log.info("Grep datadir for known payloads — must NOT be found")
        payload_bytes = bytes.fromhex(payload_hex)
        found = False
        for fname in os.listdir(blocks_dir):
            fpath = os.path.join(blocks_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as f:
                    if payload_bytes in f.read():
                        found = True
                        self.log.error(f"Found payload in {fname}!")
                        break
        assert_equal(found, False)

        self.log.info("Mine 10 more blocks in hazed mode — verify they process correctly")
        new_blocks = self.generate(node, 10)
        assert_equal(len(new_blocks), 10)
        new_height = node.getblockcount()
        assert_equal(new_height, total_blocks + 10)

        # Verify new blocks have haze_status
        for bh in new_blocks:
            block = node.getblock(bh, 2)
            assert "haze_status" in block
            assert_equal(block["haze_status"]["mode"], "hazed")

        self.log.info("Verify gethazestatus reflects converted state")
        status = node.gethazestatus()
        assert_equal(status["mode"], "hazed")
        assert_equal(status["exorcism_active"], True)
        assert_greater_than(status["blocks_stripped"], 0)

        self.log.info("All Ghost Exorcism tests passed")


if __name__ == "__main__":
    GhostExorcismTest(__file__).main()

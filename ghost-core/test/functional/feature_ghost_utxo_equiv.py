#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""UTXO Equivalence Test — the most critical test in the Ghost Haze system.

Verifies that Hazed and Full Archive nodes processing the same chain produce
byte-identical UTXO sets. If hash_serialized_3 differs between modes, this
test MUST fail loudly.

Setup:
- node0: --hazemode=hazed
- node1: --hazemode=full_archive
- Both connected and syncing the same chain

Test creates diverse transaction types:
- P2WPKH standard transfers
- P2TR (Taproot) outputs
- OP_RETURN outputs
- Multi-input transactions
- Coinbase spends at exactly 100 confirmations
"""

import random

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class GhostUtxoEquivTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-hazemode=hazed"],
            ["-hazemode=full_archive"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def run_test(self):
        node0 = self.nodes[0]  # hazed
        node1 = self.nodes[1]  # full_archive

        self.log.info("Step 1: Mine 110 blocks for coinbase maturity")
        self.generate(node0, 110)

        self.log.info("Step 2: Create diverse transaction types")

        # P2WPKH standard transfers
        self.log.info("  Creating P2WPKH transfers...")
        for i in range(10):
            addr = node0.getnewaddress("", "bech32")
            node0.sendtoaddress(addr, 0.5 + i * 0.01)

        self.generate(node0, 1)

        # P2TR (Taproot) outputs
        self.log.info("  Creating P2TR (Taproot) outputs...")
        for i in range(5):
            addr = node0.getnewaddress("", "bech32m")
            node0.sendtoaddress(addr, 0.3 + i * 0.01)

        self.generate(node0, 1)

        # OP_RETURN outputs
        self.log.info("  Creating OP_RETURN outputs...")
        for i in range(5):
            utxos = node0.listunspent(1, 9999, [], True, {"minimumAmount": 0.1})
            if not utxos:
                break
            utxo = utxos[0]
            change_addr = node0.getnewaddress()
            change_amount = float(utxo["amount"]) - 0.001
            data_hex = f"deadbeef{i:04x}"
            raw = node0.createrawtransaction(
                [{"txid": utxo["txid"], "vout": utxo["vout"]}],
                [
                    {change_addr: round(change_amount, 8)},
                    {"data": data_hex},
                ],
            )
            signed = node0.signrawtransactionwithwallet(raw)
            node0.sendrawtransaction(signed["hex"])

        self.generate(node0, 1)

        # Multi-input transactions
        self.log.info("  Creating multi-input transactions...")
        for _ in range(3):
            utxos = node0.listunspent(1, 9999, [], True, {"minimumAmount": 0.01})
            if len(utxos) < 3:
                break
            inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos[:3]]
            total_in = sum(float(u["amount"]) for u in utxos[:3])
            dest_addr = node0.getnewaddress()
            raw = node0.createrawtransaction(
                inputs,
                [{dest_addr: round(total_in - 0.001, 8)}],
            )
            signed = node0.signrawtransactionwithwallet(raw)
            node0.sendrawtransaction(signed["hex"])

        self.generate(node0, 1)

        # More blocks to ensure chain is substantial
        self.log.info("  Mining additional blocks to reach 200+ total...")
        remaining = 200 - node0.getblockcount()
        if remaining > 0:
            self.generate(node0, remaining)

        # Coinbase spends at exactly 100 confirmations
        self.log.info("  Spending coinbase at exactly 100 confirmations...")
        height = node0.getblockcount()
        # Block at height (height - 100) should have a mature coinbase
        target_height = height - 100
        block_hash = node0.getblockhash(target_height)
        block = node0.getblock(block_hash, 2)
        coinbase_txid = block["tx"][0]["txid"]

        # Try to spend the coinbase output
        coinbase_info = node0.gettxout(coinbase_txid, 0)
        if coinbase_info:
            dest = node0.getnewaddress()
            raw = node0.createrawtransaction(
                [{"txid": coinbase_txid, "vout": 0}],
                [{dest: round(float(coinbase_info["value"]) - 0.001, 8)}],
            )
            signed = node0.signrawtransactionwithwallet(raw)
            node0.sendrawtransaction(signed["hex"])
            self.generate(node0, 1)

        self.log.info("Step 3: Mine a few more blocks to finalize")
        self.generate(node0, 5)

        total_height = node0.getblockcount()
        self.log.info(f"  Final chain height: {total_height}")

        self.log.info("Step 4: Ensure both nodes are synced")
        self.sync_blocks()
        assert_equal(node0.getblockcount(), node1.getblockcount())
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        self.log.info("Step 5: Compare UTXO set hashes — THIS IS THE CRITICAL CHECK")
        utxo_info0 = node0.gettxoutsetinfo()
        utxo_info1 = node1.gettxoutsetinfo()

        self.log.info(f"  Hazed node:        hash={utxo_info0['hash_serialized_3']}, txouts={utxo_info0['txouts']}, total={utxo_info0['total_amount']}")
        self.log.info(f"  Full archive node:  hash={utxo_info1['hash_serialized_3']}, txouts={utxo_info1['txouts']}, total={utxo_info1['total_amount']}")

        # THE CRITICAL ASSERTION: UTXO set hashes MUST be identical
        assert_equal(
            utxo_info0["hash_serialized_3"],
            utxo_info1["hash_serialized_3"],
        )

        # Secondary checks
        assert_equal(utxo_info0["txouts"], utxo_info1["txouts"])
        assert_equal(utxo_info0["total_amount"], utxo_info1["total_amount"])

        self.log.info("Step 6: Spot-check 20 random UTXOs via gettxout")
        # Get all UTXOs from node1 to spot-check
        best_hash = node1.getbestblockhash()
        block = node1.getblock(best_hash, 2)

        # Collect some outpoints to check
        checked = 0
        height = node0.getblockcount()
        for h in random.sample(range(1, height), min(20, height - 1)):
            bh = node0.getblockhash(h)
            blk = node0.getblock(bh, 1)
            if not blk["tx"]:
                continue
            txid = blk["tx"][0]  # Check coinbase of random blocks
            utxo0 = node0.gettxout(txid, 0)
            utxo1 = node1.gettxout(txid, 0)

            if utxo0 is None and utxo1 is None:
                # Both spent — consistent
                checked += 1
                continue
            if utxo0 is not None and utxo1 is not None:
                assert_equal(utxo0["value"], utxo1["value"])
                assert_equal(utxo0["scriptPubKey"]["hex"], utxo1["scriptPubKey"]["hex"])
                checked += 1
                continue
            # One is None and the other isn't — UTXO mismatch!
            assert_equal(utxo0 is None, utxo1 is None)

        self.log.info(f"  Spot-checked {checked} UTXOs — all match")

        self.log.info("UTXO equivalence test PASSED — Hazed and Full Archive nodes produce identical UTXO sets")


if __name__ == "__main__":
    GhostUtxoEquivTest(__file__).main()

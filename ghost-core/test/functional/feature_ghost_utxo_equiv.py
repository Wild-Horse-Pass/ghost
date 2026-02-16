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

This test is WALLET-FREE — uses generatetoaddress and signrawtransactionwithkey
to avoid SQLite wallet version dependencies.
"""

import random
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import ECKey
from test_framework.address import key_to_p2wpkh
from test_framework.wallet_util import bytes_to_wif


class GhostUtxoEquivTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # node0 = full_archive (miner) — can serve full blocks to all peers
        # node1 = hazed (receiver) — strips blocks on write, UTXO must still match
        self.extra_args = [
            ["-hazemode=full_archive", "-disablewallet"],
            ["-hazemode=hazed", "-disablewallet"],
        ]

    def skip_test_if_missing_module(self):
        pass  # No wallet needed

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def run_test(self):
        node0 = self.nodes[0]  # full_archive (miner — can serve full blocks)
        node1 = self.nodes[1]  # hazed (strips on write — UTXO must match)

        # Create a deterministic mining key
        mining_key = ECKey()
        mining_key.set(b'\x01' * 32, compressed=True)
        mining_addr = key_to_p2wpkh(mining_key.get_pubkey().get_bytes())
        mining_wif = bytes_to_wif(mining_key.get_bytes(), compressed=True)

        self.log.info("Step 1: Mine 110 blocks for coinbase maturity")
        self.generatetoaddress(node0, 110, mining_addr)
        self.sync_blocks()

        self.log.info("Step 2: Verify initial sync")
        assert_equal(node0.getblockcount(), node1.getblockcount())
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        self.log.info("Step 3: Create transactions with OP_RETURN outputs")
        for i in range(5):
            # Get a mature coinbase UTXO to spend
            block_hash = node0.getblockhash(1 + i)
            block = node0.getblock(block_hash, 2)
            coinbase_tx = block["tx"][0]
            coinbase_txid = coinbase_tx["txid"]
            coinbase_value = coinbase_tx["vout"][0]["value"]

            utxo = node0.gettxout(coinbase_txid, 0)
            if utxo is None:
                continue

            # Build raw transaction: coinbase → change + OP_RETURN
            change_amount = round(coinbase_value - Decimal("0.001"), 8)
            op_return_hex = f"deadbeef{i:04x}"

            raw = node0.createrawtransaction(
                [{"txid": coinbase_txid, "vout": 0}],
                [
                    {mining_addr: change_amount},
                    {"data": op_return_hex},
                ],
            )

            signed = node0.signrawtransactionwithkey(
                raw,
                [mining_wif],
                [{"txid": coinbase_txid, "vout": 0,
                  "scriptPubKey": utxo["scriptPubKey"]["hex"],
                  "amount": coinbase_value}],
            )
            assert signed["complete"], f"Signing failed: {signed.get('errors')}"
            node0.sendrawtransaction(signed["hex"])
            self.log.info(f"  Sent OP_RETURN tx {i}")

        self.generatetoaddress(node0, 1, mining_addr)
        self.sync_blocks()

        self.log.info("Step 3b: Create transactions with bare multisig outputs")
        # Bare multisig is the primary data embedding vector that non-standard
        # stripping targets. The scriptPubKey gets replaced with a placeholder
        # in hazed mode, but the UTXO set must still match because stripping
        # only affects on-disk block storage, not the UTXO database.
        from test_framework.messages import CTxOut, tx_from_hex
        for i in range(3):
            block_hash = node0.getblockhash(6 + i)
            block = node0.getblock(block_hash, 2)
            coinbase_tx = block["tx"][0]
            coinbase_txid = coinbase_tx["txid"]
            coinbase_value = coinbase_tx["vout"][0]["value"]

            utxo = node0.gettxout(coinbase_txid, 0)
            if utxo is None:
                continue

            # Build a bare 1-of-2 multisig scriptPubKey:
            # OP_1 <33-byte pubkey1> <33-byte pubkey2> OP_2 OP_CHECKMULTISIG
            fake_pubkey1 = "02" + "deadbeef" * 8  # 33 bytes
            fake_pubkey2 = "02" + "cafebabe" * 8  # 33 bytes
            multisig_hex = "51" + "21" + fake_pubkey1 + "21" + fake_pubkey2 + "52" + "ae"
            multisig_script = bytes.fromhex(multisig_hex)

            # Create a base tx with change output, then add multisig output
            change_amount = round(coinbase_value - Decimal("0.001"), 8)
            raw_hex = node0.createrawtransaction(
                [{"txid": coinbase_txid, "vout": 0}],
                [{mining_addr: round(change_amount - Decimal("0.0001"), 8)}],
            )

            # Deserialize, append multisig output, re-serialize
            tx = tx_from_hex(raw_hex)
            tx.vout.append(CTxOut(10000, multisig_script))  # 0.0001 BTC
            modified_hex = tx.serialize_without_witness().hex()

            signed = node0.signrawtransactionwithkey(
                modified_hex,
                [mining_wif],
                [{"txid": coinbase_txid, "vout": 0,
                  "scriptPubKey": utxo["scriptPubKey"]["hex"],
                  "amount": coinbase_value}],
            )
            assert signed["complete"], f"Signing failed: {signed.get('errors')}"
            node0.sendrawtransaction(signed["hex"])
            self.log.info(f"  Sent bare multisig tx {i}")

        self.generatetoaddress(node0, 1, mining_addr)
        self.sync_blocks()

        self.log.info("Step 4: Create multi-output transactions")
        # Generate extra keys for distinct output addresses
        extra_keys = []
        for j in range(3):
            k = ECKey()
            k.set((b'\x02' + bytes([j]) + b'\x00' * 30), compressed=True)
            extra_keys.append(key_to_p2wpkh(k.get_pubkey().get_bytes()))

        # Spend a few more coinbases with multiple outputs to different addresses
        for i in range(3):
            block_hash = node0.getblockhash(9 + i)
            block = node0.getblock(block_hash, 2)
            coinbase_tx = block["tx"][0]
            coinbase_txid = coinbase_tx["txid"]
            coinbase_value = coinbase_tx["vout"][0]["value"]

            utxo = node0.gettxout(coinbase_txid, 0)
            if utxo is None:
                continue

            # Split into multiple outputs to different addresses
            split_value = round((coinbase_value - Decimal("0.001")) / 3, 8)
            raw = node0.createrawtransaction(
                [{"txid": coinbase_txid, "vout": 0}],
                [
                    {extra_keys[0]: split_value},
                    {extra_keys[1]: split_value},
                    {extra_keys[2]: split_value},
                ],
            )
            signed = node0.signrawtransactionwithkey(
                raw,
                [mining_wif],
                [{"txid": coinbase_txid, "vout": 0,
                  "scriptPubKey": utxo["scriptPubKey"]["hex"],
                  "amount": coinbase_value}],
            )
            assert signed["complete"]
            node0.sendrawtransaction(signed["hex"])

        self.generatetoaddress(node0, 1, mining_addr)
        self.sync_blocks()

        self.log.info("Step 5: Mine to 200+ blocks")
        remaining = 200 - node0.getblockcount()
        if remaining > 0:
            self.generatetoaddress(node0, remaining, mining_addr)
        self.sync_blocks()

        total_height = node0.getblockcount()
        self.log.info(f"  Final chain height: {total_height}")

        self.log.info("Step 6: Ensure both nodes are synced")
        assert_equal(node0.getblockcount(), node1.getblockcount())
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        self.log.info("Step 7: Compare UTXO set hashes — THIS IS THE CRITICAL CHECK")
        utxo_info0 = node0.gettxoutsetinfo()
        utxo_info1 = node1.gettxoutsetinfo()

        self.log.info(f"  Full archive node:  hash={utxo_info0['hash_serialized_3']}, txouts={utxo_info0['txouts']}, total={utxo_info0['total_amount']}")
        self.log.info(f"  Hazed node:         hash={utxo_info1['hash_serialized_3']}, txouts={utxo_info1['txouts']}, total={utxo_info1['total_amount']}")

        # THE CRITICAL ASSERTION: UTXO set hashes MUST be identical
        assert_equal(
            utxo_info0["hash_serialized_3"],
            utxo_info1["hash_serialized_3"],
        )

        # Secondary checks
        assert_equal(utxo_info0["txouts"], utxo_info1["txouts"])
        assert_equal(utxo_info0["total_amount"], utxo_info1["total_amount"])

        self.log.info("Step 8: Spot-check 20 random UTXOs via gettxout")
        checked = 0
        height = node0.getblockcount()
        for h in random.sample(range(1, height), min(20, height - 1)):
            bh = node0.getblockhash(h)
            blk = node0.getblock(bh, 1)
            if not blk["tx"]:
                continue
            txid = blk["tx"][0]
            utxo0 = node0.gettxout(txid, 0)
            utxo1 = node1.gettxout(txid, 0)

            if utxo0 is None and utxo1 is None:
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

        self.log.info("UTXO equivalence test PASSED — Hazed and Full Archive produce identical UTXO sets")


if __name__ == "__main__":
    GhostUtxoEquivTest(__file__).main()

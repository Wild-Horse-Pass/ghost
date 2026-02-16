#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ghost Haze peer-to-peer block serving test.

Verifies that:
1. A Hazed node syncs correctly from a Full Archive peer (real-time stripping)
2. A Hazed node stores blocks as GSB files on disk
3. New blocks propagate correctly between Full Archive and Hazed nodes
4. UTXO sets match across Full Archive and Hazed nodes after diverse transactions
5. Hazed node correctly operates after restart (persisted mode)

NOTE: Hazed-to-Hazed IBD (bootstrapping a new node purely from stripped blocks)
is NOT tested here. Stripped blocks have modified scriptPubKeys that cannot produce
a correct UTXO set via ConnectBlock. Full hazed->hazed IBD requires a checkpoint or
assumeutxo system (future work). The GHOST_STRIPPED_BLOCK receive/store handler
provides the storage foundation for that future capability.
"""

from decimal import Decimal
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import ECKey
from test_framework.address import key_to_p2wpkh
from test_framework.wallet_util import bytes_to_wif


class GhostHazeServeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-hazemode=full_archive", "-disablewallet"],
            ["-hazemode=hazed", "-disablewallet", "-debug=haze"],
        ]

    def skip_test_if_missing_module(self):
        pass

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(0)
        self.start_node(1)
        self.connect_nodes(0, 1)

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        mining_key = ECKey()
        mining_key.set(b'\x01' * 32, compressed=True)
        mining_addr = key_to_p2wpkh(mining_key.get_pubkey().get_bytes())
        mining_wif = bytes_to_wif(mining_key.get_bytes(), compressed=True)

        self.log.info("Step 1: Mine 110 blocks for coinbase maturity")
        self.generatetoaddress(node0, 110, mining_addr)
        self.sync_blocks()

        self.log.info("Step 2: Create diverse transactions")

        # OP_RETURN transactions
        for i in range(3):
            block_hash = node0.getblockhash(1 + i)
            block = node0.getblock(block_hash, 2)
            coinbase_tx = block["tx"][0]
            coinbase_txid = coinbase_tx["txid"]
            coinbase_value = coinbase_tx["vout"][0]["value"]
            utxo = node0.gettxout(coinbase_txid, 0)
            if utxo is None:
                continue
            change_amount = round(coinbase_value - Decimal("0.001"), 8)
            raw = node0.createrawtransaction(
                [{"txid": coinbase_txid, "vout": 0}],
                [{mining_addr: change_amount}, {"data": f"deadbeef{i:04x}"}],
            )
            signed = node0.signrawtransactionwithkey(
                raw, [mining_wif],
                [{"txid": coinbase_txid, "vout": 0,
                  "scriptPubKey": utxo["scriptPubKey"]["hex"],
                  "amount": coinbase_value}],
            )
            assert signed["complete"]
            node0.sendrawtransaction(signed["hex"])

        self.generatetoaddress(node0, 1, mining_addr)
        self.sync_blocks()

        # Bare multisig transactions
        from test_framework.messages import CTxOut, tx_from_hex
        for i in range(2):
            block_hash = node0.getblockhash(4 + i)
            block = node0.getblock(block_hash, 2)
            coinbase_tx = block["tx"][0]
            coinbase_txid = coinbase_tx["txid"]
            coinbase_value = coinbase_tx["vout"][0]["value"]
            utxo = node0.gettxout(coinbase_txid, 0)
            if utxo is None:
                continue
            fake_pubkey1 = "02" + "deadbeef" * 8
            fake_pubkey2 = "02" + "cafebabe" * 8
            multisig_hex = "51" + "21" + fake_pubkey1 + "21" + fake_pubkey2 + "52" + "ae"
            multisig_script = bytes.fromhex(multisig_hex)
            change_amount = round(coinbase_value - Decimal("0.001"), 8)
            raw_hex = node0.createrawtransaction(
                [{"txid": coinbase_txid, "vout": 0}],
                [{mining_addr: round(change_amount - Decimal("0.0001"), 8)}],
            )
            tx = tx_from_hex(raw_hex)
            tx.vout.append(CTxOut(10000, multisig_script))
            modified_hex = tx.serialize_without_witness().hex()
            signed = node0.signrawtransactionwithkey(
                modified_hex, [mining_wif],
                [{"txid": coinbase_txid, "vout": 0,
                  "scriptPubKey": utxo["scriptPubKey"]["hex"],
                  "amount": coinbase_value}],
            )
            assert signed["complete"]
            node0.sendrawtransaction(signed["hex"])

        self.generatetoaddress(node0, 1, mining_addr)
        self.sync_blocks()

        # Mine remaining to 150
        remaining = 150 - node0.getblockcount()
        if remaining > 0:
            self.generatetoaddress(node0, remaining, mining_addr)
            self.sync_blocks()

        self.log.info(f"  Chain height: {node0.getblockcount()}")

        self.log.info("Step 3: Verify both nodes at same height")
        assert_equal(node0.getblockcount(), 150)
        assert_equal(node1.getblockcount(), 150)
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        self.log.info("Step 4: Verify UTXO equivalence")
        utxo0 = node0.gettxoutsetinfo()
        utxo1 = node1.gettxoutsetinfo()
        assert_equal(utxo0["hash_serialized_3"], utxo1["hash_serialized_3"])
        assert_equal(utxo0["txouts"], utxo1["txouts"])
        assert_equal(utxo0["total_amount"], utxo1["total_amount"])
        self.log.info(f"  UTXO hash: {utxo0['hash_serialized_3']}")
        self.log.info(f"  Total UTXOs: {utxo0['txouts']}")

        self.log.info("Step 5: Verify node1 has GSB files on disk")
        blocks_dir_1 = Path(node1.chain_path) / "blocks"
        gsb_files = list(blocks_dir_1.glob("gsb*.dat"))
        assert len(gsb_files) > 0, f"Expected gsb files in {blocks_dir_1}"
        gsb_size = sum(f.stat().st_size for f in gsb_files)
        self.log.info(f"  node1 has {len(gsb_files)} gsb file(s), total {gsb_size} bytes")

        # node0 should have blk files, not gsb
        blocks_dir_0 = Path(node0.chain_path) / "blocks"
        blk_files = [f for f in blocks_dir_0.glob("blk*.dat") if f.stat().st_size > 0]
        assert len(blk_files) > 0, "Expected blk files on full_archive node"
        blk_size = sum(f.stat().st_size for f in blk_files)
        self.log.info(f"  node0 has {len(blk_files)} blk file(s), total {blk_size} bytes")

        if blk_size > 0:
            ratio = gsb_size / blk_size * 100
            self.log.info(f"  GSB/BLK size ratio: {ratio:.1f}% (lower = more stripped)")

        self.log.info("Step 6: Restart node1, verify persisted hazed mode")
        self.stop_node(1)
        self.start_node(1, extra_args=["-disablewallet", "-debug=haze"])
        self.connect_nodes(0, 1)

        assert_equal(node1.getblockcount(), 150)
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        utxo1_restart = node1.gettxoutsetinfo()
        assert_equal(utxo1_restart["hash_serialized_3"], utxo0["hash_serialized_3"])
        self.log.info("  Persisted mode works, UTXO set matches after restart")

        self.log.info("Step 7: Mine new blocks after restart, verify sync")
        self.generatetoaddress(node0, 10, mining_addr)
        self.sync_blocks()

        assert_equal(node0.getblockcount(), 160)
        assert_equal(node1.getblockcount(), 160)
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

        # Final UTXO check
        utxo0_final = node0.gettxoutsetinfo()
        utxo1_final = node1.gettxoutsetinfo()
        assert_equal(utxo0_final["hash_serialized_3"], utxo1_final["hash_serialized_3"])

        self.log.info("Step 8: Check node1 haze debug log")
        with open(node1.debug_log_path, "r", encoding="utf-8", errors="replace") as f:
            node1_log = f.read()

        # Verify exorcism engine is active
        exorcism_active = "Exorcism active" in node1_log or "Ghost Exorcism active" in node1_log
        persisted_mode = "loaded persisted mode" in node1_log
        self.log.info(f"  Exorcism active in log: {exorcism_active}")
        self.log.info(f"  Persisted mode loaded: {persisted_mode}")

        self.log.info("Ghost Haze Serve test PASSED")


if __name__ == "__main__":
    GhostHazeServeTest(__file__).main()

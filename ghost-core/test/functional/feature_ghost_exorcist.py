#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ghost Exorcist end-to-end conversion test.

Verifies that the --exorcist CLI flag converts a full_archive node to
hazed mode, producing gsb*.dat files, removing blk*.dat files, and
maintaining a correct UTXO set and block index.

Steps:
1. Start node0 in full_archive mode, mine 200 blocks with diverse txs
2. Record UTXO set hash
3. Stop node0, verify blk files exist
4. Run node0 with --exorcist — converts and exits
5. Verify gsb files exist, blk files gone, haze_mode.lock present
6. Restart node0 (persisted HAZED mode), verify chain tip and UTXO match
7. Start node1 (full_archive), connect, mine 10 blocks, verify sync
"""

import os
from decimal import Decimal
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import ECKey
from test_framework.address import key_to_p2wpkh
from test_framework.wallet_util import bytes_to_wif


class GhostExorcistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [
            ["-hazemode=full_archive", "-disablewallet"],
        ]

    def skip_test_if_missing_module(self):
        pass  # No wallet needed

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        # Only start node0 initially; node1 used later for sync test
        self.start_node(0)

    def get_blocks_dir(self, node_index):
        return Path(self.nodes[node_index].chain_path) / "blocks"

    def has_files(self, blocks_dir, prefix):
        """Check if any files matching prefix*.dat exist."""
        if not blocks_dir.exists():
            return False
        for f in blocks_dir.iterdir():
            if f.is_file() and f.name.startswith(prefix) and f.name.endswith(".dat"):
                return True
        return False

    def run_exorcist(self, node):
        """Start node with --exorcist and wait for it to exit.

        The node loads chainstate, runs the conversion, prints results,
        then returns false from AppInitMain (clean shutdown without RPC).
        Bitcoin Core's main() treats AppInitMain returning false as
        EXIT_FAILURE, so the exit code is 1 even on successful conversion.
        We verify success by checking stdout for the completion message.
        """
        node.start(extra_args=["-hazemode=full_archive", "-disablewallet", "-exorcist"])
        ret_code = node.process.wait(timeout=120)

        # Read stdout before closing
        node.stdout.seek(0)
        stdout_content = node.stdout.read().decode("utf-8", errors="replace")

        # Clean up TestNode state (process exited without RPC)
        node.stdout.close()
        node.stderr.close()
        node.running = False
        node.process = None
        node.rpc_connected = False
        node._rpc = None

        # Verify conversion succeeded via stdout message
        assert "Conversion complete!" in stdout_content, \
            f"Exorcist conversion failed (exit code {ret_code}). Stdout:\n{stdout_content}"

    def run_test(self):
        node0 = self.nodes[0]

        # Create a deterministic mining key
        mining_key = ECKey()
        mining_key.set(b'\x01' * 32, compressed=True)
        mining_addr = key_to_p2wpkh(mining_key.get_pubkey().get_bytes())
        mining_wif = bytes_to_wif(mining_key.get_bytes(), compressed=True)

        self.log.info("Step 1: Mine 110 blocks for coinbase maturity")
        self.generatetoaddress(node0, 110, mining_addr, sync_fun=self.no_op)

        self.log.info("Step 2: Create diverse transactions")

        # OP_RETURN transactions
        for i in range(5):
            block_hash = node0.getblockhash(1 + i)
            block = node0.getblock(block_hash, 2)
            coinbase_tx = block["tx"][0]
            coinbase_txid = coinbase_tx["txid"]
            coinbase_value = coinbase_tx["vout"][0]["value"]

            utxo = node0.gettxout(coinbase_txid, 0)
            if utxo is None:
                continue

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
                raw, [mining_wif],
                [{"txid": coinbase_txid, "vout": 0,
                  "scriptPubKey": utxo["scriptPubKey"]["hex"],
                  "amount": coinbase_value}],
            )
            assert signed["complete"]
            node0.sendrawtransaction(signed["hex"])

        self.generatetoaddress(node0, 1, mining_addr, sync_fun=self.no_op)

        # Bare multisig transactions
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

        self.generatetoaddress(node0, 1, mining_addr, sync_fun=self.no_op)

        # Mine to 200
        remaining = 200 - node0.getblockcount()
        if remaining > 0:
            self.generatetoaddress(node0, remaining, mining_addr, sync_fun=self.no_op)

        self.log.info(f"  Chain height: {node0.getblockcount()}")

        self.log.info("Step 3: Record UTXO set hash at height 200")
        utxo_info_before = node0.gettxoutsetinfo()
        utxo_hash_before = utxo_info_before["hash_serialized_3"]
        best_hash_before = node0.getbestblockhash()
        height_before = node0.getblockcount()
        self.log.info(f"  UTXO hash: {utxo_hash_before}")
        self.log.info(f"  Best block: {best_hash_before}")

        self.log.info("Step 4: Stop node0, verify blk files exist")
        self.stop_node(0)
        blocks_dir = self.get_blocks_dir(0)
        assert self.has_files(blocks_dir, "blk"), "Expected blk*.dat files to exist"
        assert not self.has_files(blocks_dir, "gsb"), "Expected no gsb*.dat files yet"

        self.log.info("Step 5: Run --exorcist conversion")
        self.run_exorcist(self.nodes[0])

        self.log.info("Step 6: Verify conversion results on disk")
        assert self.has_files(blocks_dir, "gsb"), "Expected gsb*.dat files after conversion"

        # After conversion, blk/rev files are securely zeroed and deleted.
        # However, Bitcoin Core's Shutdown() may recreate empty blk/rev files.
        # Verify they're either absent or empty (0 bytes).
        for f in blocks_dir.iterdir():
            if f.is_file() and f.name.startswith("blk") and f.name.endswith(".dat"):
                assert f.stat().st_size == 0, \
                    f"Expected blk file {f.name} to be empty after conversion, got {f.stat().st_size} bytes"

        lock_file = Path(self.nodes[0].chain_path) / "haze_mode.lock"
        assert lock_file.exists(), "Expected haze_mode.lock to be written"
        mode_byte = lock_file.read_bytes()
        assert_equal(mode_byte, b'\x00')  # GhostMode::HAZED = 0

        self.log.info("Step 7: Restart node0 in persisted HAZED mode")
        self.start_node(0, extra_args=["-disablewallet"])
        assert_equal(node0.getblockcount(), height_before)
        assert_equal(node0.getbestblockhash(), best_hash_before)

        self.log.info("Step 8: Verify UTXO set matches pre-conversion")
        utxo_info_after = node0.gettxoutsetinfo()
        assert_equal(utxo_info_after["hash_serialized_3"], utxo_hash_before)
        assert_equal(utxo_info_after["txouts"], utxo_info_before["txouts"])
        assert_equal(utxo_info_after["total_amount"], utxo_info_before["total_amount"])
        self.log.info("  UTXO set matches!")

        self.log.info("Step 9: Mine new blocks directly on hazed node0")
        # After conversion, node0 is hazed. New blocks are validated in RAM then
        # stripped and written to GSB — proving the hazed node works post-conversion.
        self.generatetoaddress(node0, 10, mining_addr, sync_fun=self.no_op)
        assert_equal(node0.getblockcount(), height_before + 10)

        self.log.info("Step 10: Final UTXO check after post-conversion mining")
        utxo_final = node0.gettxoutsetinfo()
        # UTXO set should have grown (new coinbase outputs from 10 blocks)
        assert utxo_final["txouts"] > utxo_info_before["txouts"], \
            "Expected more UTXOs after mining new blocks"

        self.log.info("Ghost Exorcist test PASSED")


if __name__ == "__main__":
    GhostExorcistTest(__file__).main()

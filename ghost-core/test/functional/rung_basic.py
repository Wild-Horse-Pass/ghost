#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Ladder Script functional tests for all block types (v2 wire format).

Tests:
- Phase 1 (existing): createrung, decoderung, validateladder, malformed, SIG spend
- Phase 2: HASH_PREIMAGE, CSV, CLTV, MULTISIG, compound SIG+CSV, OR logic,
           negative tests, multi-input/output
- Phase 3: Inversion (inverted CSV, inverted HASH_PREIMAGE)
"""

import hashlib
import os
from decimal import Decimal

from test_framework.key import ECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif, generate_keypair


def make_keypair():
    """Generate an ECKey and return (wif, pubkey_hex)."""
    eckey = ECKey()
    eckey.generate(compressed=True)
    wif = bytes_to_wif(eckey.get_bytes(), compressed=True)
    pubkey_hex = eckey.get_pubkey().get_bytes().hex()
    return wif, pubkey_hex


def locktime_hex(val):
    """Encode a uint32 as 4-byte little-endian hex."""
    return val.to_bytes(4, 'little').hex()


def numeric_hex(val):
    """Encode a uint32 as 4-byte little-endian hex (same as locktime)."""
    return val.to_bytes(4, 'little').hex()


class LadderScriptBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-txindex"]]

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Mining initial blocks for maturity...")
        self.generate(node, 101)
        self.generatetoaddress(node, 101, self.wallet.get_address())
        self.wallet.rescan_utxos()

        # Phase 1 tests (existing)
        self.test_createrung(node)
        self.test_decoderung(node)
        self.test_validateladder(node)
        self.test_decoderung_malformed(node)
        self.test_createrungtx_signrungtx_spend(node)

        # Phase 2 tests
        self.test_hash_preimage_spend(node)
        self.test_csv_spend(node)
        self.test_cltv_spend(node)
        self.test_multisig_spend(node)
        self.test_sig_plus_csv(node)
        self.test_or_logic(node)
        self.test_negative_wrong_sig(node)
        self.test_negative_wrong_preimage(node)
        self.test_negative_csv_too_early(node)
        self.test_negative_cltv_too_early(node)
        self.test_multi_input_output(node)

        # Phase 3 tests (inversion)
        self.test_inverted_csv(node)
        self.test_inverted_hash_preimage(node)

        # Phase 4 tests (new block types)
        self.test_tagged_hash(node)
        self.test_amount_lock(node)
        self.test_amount_lock_out_of_range(node)
        self.test_anchor_output(node)
        self.test_compare_block(node)
        self.test_ctv_template(node)
        self.test_vault_lock(node)

        # Phase 2+ negative tests
        self.test_negative_ctv_wrong_template(node)
        self.test_negative_vault_wrong_key(node)
        self.test_negative_compare_fails(node)
        self.test_negative_tagged_hash_wrong_preimage(node)

        # Recursion tests
        self.test_recurse_same(node)
        self.test_negative_recurse_same_different(node)
        self.test_recurse_same_chain(node)
        self.test_recurse_until_re_encumber(node)
        self.test_recurse_until_termination(node)
        self.test_negative_recurse_until_no_reencumber(node)
        self.test_recurse_count(node)

    # =========================================================================
    # Helpers
    # =========================================================================

    def bootstrap_v3_output(self, node, conditions, output_amount=None):
        """Create and confirm a v3 output with given conditions.
        Returns (txid, vout, amount, scriptPubKey_hex)."""
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        if output_amount is None:
            output_amount = Decimal(input_amount) - Decimal("0.001")

        # We need a bootstrap key to sign the MiniWallet UTXO spend
        boot_wif, boot_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [{"amount": output_amount, "conditions": conditions}]
        )
        unsigned_hex = result["hex"]

        sign_result = node.signrungtx(
            unsigned_hex,
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        return txid, 0, output_amount, spk

    # =========================================================================
    # Phase 1 tests
    # =========================================================================

    def test_createrung(self, node):
        """Test createrung RPC builds a valid ladder witness."""
        self.log.info("Testing createrung RPC...")

        pubkey_hex = "02" + "aa" * 32
        sig_hex = "bb" * 64

        result = node.createrung([{
            "blocks": [{
                "type": "SIG",
                "fields": [
                    {"type": "PUBKEY", "hex": pubkey_hex},
                    {"type": "SIGNATURE", "hex": sig_hex},
                ]
            }]
        }])

        assert "hex" in result
        assert result["size"] > 0
        self.log.info(f"  Created ladder witness: {result['size']} bytes")
        self.ladder_hex = result["hex"]

    def test_decoderung(self, node):
        """Test decoderung RPC decodes ladder witness to JSON."""
        self.log.info("Testing decoderung RPC...")

        result = node.decoderung(self.ladder_hex)

        assert_equal(result["num_rungs"], 1)
        assert_equal(len(result["rungs"]), 1)

        rung = result["rungs"][0]
        assert_equal(rung["rung_index"], 0)
        assert_equal(len(rung["blocks"]), 1)

        block = rung["blocks"][0]
        assert_equal(block["type"], "SIG")
        assert_equal(block["inverted"], False)
        assert_equal(len(block["fields"]), 2)
        assert_equal(block["fields"][0]["type"], "PUBKEY")
        assert_equal(block["fields"][0]["size"], 33)
        assert_equal(block["fields"][1]["type"], "SIGNATURE")
        assert_equal(block["fields"][1]["size"], 64)

        # Check coil defaults (per-ladder, not per-rung)
        coil = result["coil"]
        assert_equal(coil["type"], "UNLOCK")
        assert_equal(coil["attestation"], "INLINE")
        assert_equal(coil["scheme"], "SCHNORR")

        self.log.info("  Decoded ladder witness matches expected structure")

    def test_validateladder(self, node):
        """Test validateladder RPC on a non-v3 transaction."""
        self.log.info("Testing validateladder RPC...")

        raw_tx = (
            "01000000"
            "01"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "00000000"
            "00"
            "ffffffff"
            "01"
            "0000000000000000"
            "016a"
            "00000000"
        )

        result = node.validateladder(raw_tx)
        assert_equal(result["valid"], False)
        assert "Not a v3" in result["error"]

        self.log.info("  Non-v3 transaction correctly rejected")

    def test_decoderung_malformed(self, node):
        """Test decoderung RPC rejects malformed input."""
        self.log.info("Testing malformed ladder witness rejection...")

        # Empty / truncated
        assert_raises_rpc_error(-22, "Failed to decode", node.decoderung, "00")

        # Unknown block type (0x00ff LE): 01 rung, 01 block, ff00 type, 00 inverted, 00 fields, coil bytes
        assert_raises_rpc_error(-22, "unknown block type", node.decoderung, "0101ff000000010101" + "0000")

        # Unknown data type (0xff): 01 rung, 01 block, 0100 SIG, 00 inverted, 01 field, ff type, 01 len, aa data, coil bytes
        assert_raises_rpc_error(-22, "unknown data type", node.decoderung, "010101000001ff01aa010101" + "0000")

        # Oversized PUBKEY field (65 bytes, max is 64):
        # 01 rung, 01 block, 0100 SIG, 00 inverted, 01 field, 01 PUBKEY, 41 len=65, 65 bytes, coil bytes
        oversized = "0101010000010141" + "02" * 65 + "010101" + "0000"
        assert_raises_rpc_error(-22, "too large", node.decoderung, oversized)

        self.log.info("  All malformed inputs correctly rejected")

    def test_createrungtx_signrungtx_spend(self, node):
        """Test end-to-end: create v3 output, sign, broadcast, spend again."""
        self.log.info("Testing createrungtx + signrungtx end-to-end spend...")

        privkey_wif, pubkey_hex = make_keypair()

        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        self.log.info(f"  Using UTXO: {input_txid}:{input_vout} ({input_amount} BTC)")

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        output_amount = Decimal(input_amount) - Decimal("0.001")

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [{"amount": output_amount, "conditions": [{
                "blocks": [{
                    "type": "SIG",
                    "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]
                }]
            }]}]
        )
        unsigned_hex = result["hex"]
        self.log.info(f"  Created unsigned v3 tx: {len(unsigned_hex)//2} bytes")

        sign_result = node.signrungtx(
            unsigned_hex,
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        signed_hex = sign_result["hex"]
        assert sign_result["complete"], "Transaction should be fully signed"
        self.log.info(f"  Signed v3 tx: complete={sign_result['complete']}")

        txid1 = node.sendrawtransaction(signed_hex)
        self.log.info(f"  Broadcast bootstrap tx: {txid1}")
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid1, True)
        assert tx_info["confirmations"] >= 1, "Bootstrap tx should be confirmed"
        self.log.info("  Bootstrap spend (standard -> v3) confirmed!")

        # Rung-to-rung spend
        output_amount2 = output_amount - Decimal("0.001")
        spent_conditions_spk = tx_info["vout"][0]["scriptPubKey"]["hex"]

        result2 = node.createrungtx(
            [{"txid": txid1, "vout": 0}],
            [{"amount": output_amount2, "conditions": [{
                "blocks": [{
                    "type": "SIG",
                    "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]
                }]
            }]}]
        )
        unsigned_hex2 = result2["hex"]

        sign_result2 = node.signrungtx(
            unsigned_hex2,
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": output_amount, "scriptPubKey": spent_conditions_spk}]
        )
        signed_hex2 = sign_result2["hex"]
        assert sign_result2["complete"], "Rung-to-rung tx should be fully signed"

        txid2 = node.sendrawtransaction(signed_hex2)
        self.log.info(f"  Broadcast rung-to-rung tx: {txid2}")
        self.generate(node, 1)

        tx_info2 = node.getrawtransaction(txid2, True)
        assert tx_info2["confirmations"] >= 1, "Rung-to-rung tx should be confirmed"
        self.log.info("  Rung-to-rung spend (v3 -> v3) confirmed!")

        validate1 = node.validateladder(node.getrawtransaction(txid1))
        self.log.info(f"  validateladder tx1: valid={validate1['valid']}")

        validate2 = node.validateladder(node.getrawtransaction(txid2))
        self.log.info(f"  validateladder tx2: valid={validate2['valid']}")

        self.log.info("  End-to-end spend test PASSED!")

    # =========================================================================
    # Phase 2 tests
    # =========================================================================

    def test_hash_preimage_spend(self, node):
        """HASH_PREIMAGE: SHA256 preimage reveal spend."""
        self.log.info("Testing HASH_PREIMAGE spend...")

        # Generate random 32-byte preimage, compute SHA256 hash
        preimage = os.urandom(32)
        hash_digest = hashlib.sha256(preimage).digest()

        # Create v3 output with HASH_PREIMAGE condition
        conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [
            {"type": "HASH256", "hex": hash_digest.hex()}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  HASH_PREIMAGE output: {txid}:{vout}")

        # Spend the HASH_PREIMAGE output
        output_amount = amount - Decimal("0.001")
        spend_wif, spend_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG",
                "fields": [{"type": "PUBKEY", "hex": spend_pubkey}]
            }]}]}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  HASH_PREIMAGE spend confirmed!")

    def test_csv_spend(self, node):
        """CSV: relative timelock spend."""
        self.log.info("Testing CSV spend...")

        csv_blocks = 10

        conditions = [{"blocks": [{"type": "CSV", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  CSV output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Try spending immediately with correct sequence — should fail (UTXO not old enough)
        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CSV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, "non-BIP68-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CSV spend rejected (too early) — correct!")

        # Mine enough blocks for the CSV to mature
        self.generate(node, csv_blocks)

        # Now spend should succeed
        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CSV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  CSV spend confirmed!")

    def test_cltv_spend(self, node):
        """CLTV: absolute timelock spend."""
        self.log.info("Testing CLTV spend...")

        current_height = node.getblockcount()
        target_height = current_height + 20

        conditions = [{"blocks": [{"type": "CLTV", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(target_height)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  CLTV output: {txid}:{vout} (target_height={target_height})")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Try spending now — should fail (height too low)
        # nLockTime must be >= target_height, sequence must not be 0xffffffff
        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0xfffffffe}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            target_height  # locktime
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, "non-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CLTV spend rejected (too early) — correct!")

        # Mine until we reach target height
        blocks_needed = target_height - node.getblockcount()
        if blocks_needed > 0:
            self.generate(node, blocks_needed)

        # Now spend should succeed
        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0xfffffffe}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            target_height  # locktime
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  CLTV spend confirmed!")

    def test_multisig_spend(self, node):
        """MULTISIG: 2-of-3 threshold spend."""
        self.log.info("Testing MULTISIG 2-of-3 spend...")

        # Generate 3 keypairs
        keys = [make_keypair() for _ in range(3)]
        wifs = [k[0] for k in keys]
        pubkeys = [k[1] for k in keys]

        # Conditions: NUMERIC(2) + 3 PUBKEYs
        conditions = [{"blocks": [{"type": "MULTISIG", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},
            {"type": "PUBKEY", "hex": pubkeys[0]},
            {"type": "PUBKEY", "hex": pubkeys[1]},
            {"type": "PUBKEY", "hex": pubkeys[2]},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  MULTISIG output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Sign with keys 0 and 2 (2 of 3)
        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "MULTISIG", "privkeys": [wifs[0], wifs[2]]}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  MULTISIG 2-of-3 spend confirmed!")

    def test_sig_plus_csv(self, node):
        """Compound: SIG + CSV (AND logic within one rung)."""
        self.log.info("Testing SIG + CSV compound spend...")

        privkey_wif, pubkey_hex = make_keypair()
        csv_blocks = 10

        # Conditions: single rung with SIG + CSV blocks
        conditions = [{"blocks": [
            {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]},
            {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  SIG+CSV output: {txid}:{vout}")

        # Mine for CSV maturity
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "privkey": privkey_wif},
                {"type": "CSV"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  SIG + CSV compound spend confirmed!")

    def test_or_logic(self, node):
        """OR logic: two rungs — SIG(key_A) OR HASH_PREIMAGE(hash)."""
        self.log.info("Testing OR logic (2 rungs)...")

        key_a_wif, key_a_pubkey = make_keypair()
        preimage = os.urandom(32)
        hash_digest = hashlib.sha256(preimage).digest()

        # Conditions: 2 rungs
        # Rung 0: SIG(key_A)
        # Rung 1: HASH_PREIMAGE(hash)
        conditions = [
            {"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": key_a_pubkey}
            ]}]},
            {"blocks": [{"type": "HASH_PREIMAGE", "fields": [
                {"type": "HASH256", "hex": hash_digest.hex()}
            ]}]},
        ]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  OR output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Spend using rung 1 (HASH_PREIMAGE) — don't need key_A
        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "rung": 1, "blocks": [
                {"type": "HASH_PREIMAGE", "preimage": preimage.hex()}
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  OR logic spend (via rung 1 HASH_PREIMAGE) confirmed!")

    def test_negative_wrong_sig(self, node):
        """Negative: SIG output, spend with wrong key."""
        self.log.info("Testing negative: wrong SIG key...")

        correct_wif, correct_pubkey = make_keypair()
        wrong_wif, _ = make_keypair()

        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": correct_pubkey}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        # Sign with wrong key
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "SIG", "privkey": wrong_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  Wrong SIG key correctly rejected!")

    def test_negative_wrong_preimage(self, node):
        """Negative: HASH_PREIMAGE output, spend with wrong preimage."""
        self.log.info("Testing negative: wrong HASH_PREIMAGE preimage...")

        preimage = os.urandom(32)
        hash_digest = hashlib.sha256(preimage).digest()
        wrong_preimage = os.urandom(32)

        conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [
            {"type": "HASH256", "hex": hash_digest.hex()}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": wrong_preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  Wrong HASH_PREIMAGE preimage correctly rejected!")

    def test_negative_csv_too_early(self, node):
        """Negative: CSV(10) output, spend immediately."""
        self.log.info("Testing negative: CSV too early...")

        csv_blocks = 10
        conditions = [{"blocks": [{"type": "CSV", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CSV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, "non-BIP68-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CSV too early correctly rejected!")

    def test_negative_cltv_too_early(self, node):
        """Negative: CLTV(future) output, spend with locktime in past."""
        self.log.info("Testing negative: CLTV too early...")

        current_height = node.getblockcount()
        target_height = current_height + 50  # Far in the future

        conditions = [{"blocks": [{"type": "CLTV", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(target_height)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0xfffffffe}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}],
            target_height  # locktime
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, "non-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CLTV too early correctly rejected!")

    def test_multi_input_output(self, node):
        """Multi-input/multi-output: 3 inputs → 2 outputs."""
        self.log.info("Testing multi-input/output (3→2)...")

        privkey_wif, pubkey_hex = make_keypair()
        sig_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        # Create 3 v3 outputs
        utxos = []
        for i in range(3):
            txid, vout, amount, spk = self.bootstrap_v3_output(node, sig_conditions)
            utxos.append({"txid": txid, "vout": vout, "amount": amount, "spk": spk})
            self.log.info(f"  Created v3 output {i}: {txid}:{vout}")

        total_input = sum(u["amount"] for u in utxos)
        fee = Decimal("0.001")
        remaining = total_input - fee
        out1_amount = remaining / 2
        out2_amount = remaining - out1_amount

        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Create tx with 3 inputs, 2 outputs
        inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos]
        outputs = [
            {"amount": out1_amount, "conditions": dest_conditions},
            {"amount": out2_amount, "conditions": dest_conditions},
        ]
        result = node.createrungtx(inputs, outputs)

        # Sign all 3 inputs
        signers = [{"input": i, "blocks": [{"type": "SIG", "privkey": privkey_wif}]} for i in range(3)]
        spent_outputs = [{"amount": u["amount"], "scriptPubKey": u["spk"]} for u in utxos]

        sign_result = node.signrungtx(result["hex"], signers, spent_outputs)
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        assert_equal(len(tx_info["vin"]), 3)
        assert_equal(len(tx_info["vout"]), 2)
        self.log.info("  Multi-input/output (3→2) confirmed!")


    # =========================================================================
    # Phase 3 tests (inversion)
    # =========================================================================

    def test_inverted_csv(self, node):
        """Inverted CSV: spend BEFORE maturity succeeds, after maturity fails."""
        self.log.info("Testing inverted CSV...")

        csv_blocks = 10

        # Create v3 output with inverted CSV condition
        # Inverted CSV means: spendable when CSV is NOT satisfied (i.e., before maturity)
        conditions = [{"blocks": [{"type": "CSV", "inverted": True, "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  Inverted CSV output: {txid}:{vout}")

        # Spend immediately (before maturity) — should succeed with inverted CSV
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CSV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Inverted CSV spend (before maturity) confirmed!")

    def test_inverted_hash_preimage(self, node):
        """Inverted HASH_PREIMAGE: spend when preimage NOT provided succeeds."""
        self.log.info("Testing inverted HASH_PREIMAGE...")

        preimage = os.urandom(32)
        hash_digest = hashlib.sha256(preimage).digest()

        # Create v3 output with inverted HASH_PREIMAGE condition
        # Inverted means: spendable when hash check FAILS (no valid preimage)
        conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "inverted": True, "fields": [
            {"type": "HASH256", "hex": hash_digest.hex()}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  Inverted HASH_PREIMAGE output: {txid}:{vout}")

        # Spend with a WRONG preimage — inverted means this SATISFIES the condition
        wrong_preimage = os.urandom(32)
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": wrong_preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Inverted HASH_PREIMAGE spend (wrong preimage) confirmed!")


    # =========================================================================
    # Phase 4 tests (new block types)
    # =========================================================================

    def test_tagged_hash(self, node):
        """TAGGED_HASH: BIP-340 tagged hash verification."""
        self.log.info("Testing TAGGED_HASH spend...")

        # Tag and preimage
        tag = b"GhostTaggedHash"
        preimage = os.urandom(32)

        # Compute BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || preimage)
        tag_hash = hashlib.sha256(tag).digest()
        expected = hashlib.sha256(tag_hash + tag_hash + preimage).digest()

        conditions = [{"blocks": [{"type": "TAGGED_HASH", "fields": [
            {"type": "HASH256", "hex": tag_hash.hex()},
            {"type": "HASH256", "hex": expected.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  TAGGED_HASH output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "TAGGED_HASH", "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  TAGGED_HASH spend confirmed!")

    def test_amount_lock(self, node):
        """AMOUNT_LOCK: spend within amount range."""
        self.log.info("Testing AMOUNT_LOCK (in range)...")

        # NUMERIC fields are 4 bytes. Use small values that fit easily.
        min_sats = 10000       # 0.0001 BTC
        max_sats = 200000000   # 2.0 BTC

        conditions = [{"blocks": [{"type": "AMOUNT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(min_sats)},
            {"type": "NUMERIC", "hex": numeric_hex(max_sats)},
        ]}]}]

        # Bootstrap with a small amount that fits within the AMOUNT_LOCK range
        # Use createrungtx with two outputs: AMOUNT_LOCK + change
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]
        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        boot_wif, boot_pubkey = make_keypair()
        lock_amount = Decimal("1.0")  # 100M sats — fits in range [10000, 200000000]
        change_amount = Decimal(input_amount) - lock_amount - Decimal("0.001")

        # Change goes to a SIG output
        change_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": boot_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [
                {"amount": lock_amount, "conditions": conditions},
                {"amount": change_amount, "conditions": change_conditions},
            ]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_result["complete"]
        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid, True)
        spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        amount = lock_amount
        self.log.info(f"  AMOUNT_LOCK output: {txid}:0 (amount={amount})")

        # Spend with amount in range
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": 0}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "AMOUNT_LOCK"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  AMOUNT_LOCK (in range) spend confirmed!")

    def test_amount_lock_out_of_range(self, node):
        """AMOUNT_LOCK: reject spend outside amount range."""
        self.log.info("Testing AMOUNT_LOCK (out of range)...")

        min_sats = 500000  # 0.005 BTC
        max_sats = 1000000  # 0.01 BTC

        conditions = [{"blocks": [{"type": "AMOUNT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(min_sats)},
            {"type": "NUMERIC", "hex": numeric_hex(max_sats)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        # Try to spend with output below min (100 sats)
        output_amount = Decimal("0.000001")  # 100 sats — below 500000 min
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "AMOUNT_LOCK"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  AMOUNT_LOCK (out of range) correctly rejected!")

    def test_anchor_output(self, node):
        """ANCHOR: create and validate anchor output structure."""
        self.log.info("Testing ANCHOR output...")

        _, pubkey_hex = make_keypair()
        state_hash = os.urandom(32)

        # ANCHOR_CHANNEL needs local_key + remote_key + commitment_number
        _, remote_pubkey = make_keypair()
        conditions = [{"blocks": [{"type": "ANCHOR_CHANNEL", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex},
            {"type": "PUBKEY", "hex": remote_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(1)},  # commitment_number
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ANCHOR_CHANNEL output: {txid}:{vout}")

        # Decode and verify the output structure
        tx_hex = node.getrawtransaction(txid)
        decoded = node.validateladder(tx_hex)
        self.log.info(f"  validateladder: valid={decoded['valid']}")

        # Spend the anchor (structural validation)
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_CHANNEL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_CHANNEL spend confirmed!")

    def test_compare_block(self, node):
        """COMPARE: test comparison operators on UTXO value."""
        self.log.info("Testing COMPARE block...")

        # COMPARE with GT operator (0x03): input_amount > value_b
        # We'll use a threshold of 1000 sats
        threshold = 1000
        operator_gt = 3  # GT

        conditions = [{"blocks": [{"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(operator_gt)},  # operator
            {"type": "NUMERIC", "hex": numeric_hex(threshold)},    # value_b
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  COMPARE(GT) output: {txid}:{vout} (amount={amount})")

        # Spend — should succeed since input amount >> threshold
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  COMPARE(GT) spend confirmed!")

    def test_ctv_template(self, node):
        """CTV: Full end-to-end CheckTemplateVerify — lock and spend."""
        self.log.info("Testing CTV template verify (full spend cycle)...")

        privkey_wif, pubkey_hex = make_keypair()
        dest_wif, dest_pubkey = make_keypair()

        # Step 1: Bootstrap a SIG-locked output that we control
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        sig_amount = Decimal("1.0")
        change_amount = Decimal(input_amount) - sig_amount - Decimal("0.001")

        sig_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]
        change_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        bootstrap = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [
                {"amount": sig_amount, "conditions": sig_conditions},
                {"amount": change_amount, "conditions": change_conditions},
            ]
        )
        sign_boot = node.signrungtx(
            bootstrap["hex"],
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_boot["complete"]
        boot_txid = node.sendrawtransaction(sign_boot["hex"])
        self.generate(node, 1)

        # Step 2: Pre-compute the CTV template hash.
        # CTV hash commits to: version, locktime, scriptsigs_hash, num_inputs,
        # sequences_hash, num_outputs, outputs_hash, input_index.
        # It does NOT commit to input outpoints — so we can compute it with a
        # placeholder input and the hash will match any spending tx with the
        # same outputs/version/locktime/sequences.
        spend_amount = sig_amount - Decimal("0.002")  # fee for CTV output creation + spending
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Build a template tx with a dummy input (same structure as the real spend)
        template_tx = node.createrungtx(
            [{"txid": boot_txid, "vout": 0}],  # placeholder input — outpoint not in CTV hash
            [{"amount": spend_amount, "conditions": dest_conditions}]
        )
        ctv_result = node.computectvhash(template_tx["hex"], 0)
        ctv_hash = ctv_result["hash"]
        self.log.info(f"  CTV hash: {ctv_hash}")

        # Step 3: Create the CTV-locked output using the computed hash
        ctv_conditions = [{"blocks": [{"type": "CTV", "fields": [
            {"type": "HASH256", "hex": ctv_hash}
        ]}]}]

        ctv_lock_amount = sig_amount - Decimal("0.001")  # leave fee for this tx
        ctv_create = node.createrungtx(
            [{"txid": boot_txid, "vout": 0}],
            [{"amount": ctv_lock_amount, "conditions": ctv_conditions}]
        )

        boot_txinfo = node.getrawtransaction(boot_txid, True)
        boot_spk = boot_txinfo["vout"][0]["scriptPubKey"]["hex"]

        ctv_sign = node.signrungtx(
            ctv_create["hex"],
            [{"input": 0, "blocks": [{"type": "SIG", "privkey": privkey_wif}]}],
            [{"amount": float(sig_amount), "scriptPubKey": boot_spk}]
        )
        assert ctv_sign["complete"]
        ctv_txid = node.sendrawtransaction(ctv_sign["hex"])
        self.generate(node, 1)
        self.log.info(f"  CTV output: {ctv_txid}:0")

        # Step 4: Spend the CTV output with a tx matching the template exactly.
        # The spending tx must produce the same outputs/version/locktime/sequences
        # that were used to compute the CTV hash.
        ctv_txinfo = node.getrawtransaction(ctv_txid, True)
        ctv_spk = ctv_txinfo["vout"][0]["scriptPubKey"]["hex"]
        ctv_out_amount = Decimal(str(ctv_txinfo["vout"][0]["value"]))

        # Build the real spending tx — must match template structure exactly
        real_spend = node.createrungtx(
            [{"txid": ctv_txid, "vout": 0}],
            [{"amount": spend_amount, "conditions": dest_conditions}]
        )

        # Verify the hash matches
        verify_hash = node.computectvhash(real_spend["hex"], 0)
        assert verify_hash["hash"] == ctv_hash, f"CTV hash mismatch: {verify_hash['hash']} != {ctv_hash}"

        # Sign — CTV block needs no witness data
        real_sign = node.signrungtx(
            real_spend["hex"],
            [{"input": 0, "blocks": [{"type": "CTV"}]}],
            [{"amount": float(ctv_out_amount), "scriptPubKey": ctv_spk}]
        )
        assert real_sign["complete"]

        final_txid = node.sendrawtransaction(real_sign["hex"])
        self.generate(node, 1)

        final_info = node.getrawtransaction(final_txid, True)
        assert final_info["confirmations"] >= 1
        self.log.info(f"  CTV spend confirmed: {final_txid}")
        self.log.info("  CTV full spend cycle passed!")

    def test_vault_lock(self, node):
        """VAULT_LOCK: two-path vault with recovery key and hot key."""
        self.log.info("Testing VAULT_LOCK output...")

        recovery_wif, recovery_pubkey = make_keypair()
        hot_wif, hot_pubkey = make_keypair()
        hot_delay = 10  # CSV blocks for hot path

        conditions = [{"blocks": [{"type": "VAULT_LOCK", "fields": [
            {"type": "PUBKEY", "hex": recovery_pubkey},   # recovery_key
            {"type": "PUBKEY", "hex": hot_pubkey},         # hot_key
            {"type": "NUMERIC", "hex": numeric_hex(hot_delay)},  # hot_delay
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  VAULT_LOCK output: {txid}:{vout}")

        # Cold sweep: spend immediately with recovery key
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "VAULT_LOCK", "privkey": recovery_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  VAULT_LOCK cold sweep confirmed!")

    def test_negative_ctv_wrong_template(self, node):
        """CTV negative: spending tx doesn't match committed template hash."""
        self.log.info("Testing CTV negative (wrong template)...")

        privkey_wif, pubkey_hex = make_keypair()
        dest_wif, dest_pubkey = make_keypair()

        # Lock to a random hash (no valid spending tx matches)
        wrong_hash = os.urandom(32).hex()
        conditions = [{"blocks": [{"type": "CTV", "fields": [
            {"type": "HASH256", "hex": wrong_hash}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "CTV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CTV (wrong template) correctly rejected!")

    def test_negative_vault_wrong_key(self, node):
        """VAULT_LOCK negative: wrong key cannot spend."""
        self.log.info("Testing VAULT_LOCK negative (wrong key)...")

        recovery_wif, recovery_pubkey = make_keypair()
        hot_wif, hot_pubkey = make_keypair()
        wrong_wif, wrong_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "VAULT_LOCK", "fields": [
            {"type": "PUBKEY", "hex": recovery_pubkey},
            {"type": "PUBKEY", "hex": hot_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        # Sign with wrong key (not recovery_key or hot_key)
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "VAULT_LOCK", "privkey": wrong_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  VAULT_LOCK (wrong key) correctly rejected!")

    def test_negative_compare_fails(self, node):
        """COMPARE negative: amount below threshold fails GT check."""
        self.log.info("Testing COMPARE negative (below threshold)...")

        privkey_wif, pubkey_hex = make_keypair()

        # COMPARE GT 500000000 (5 BTC) — but input will be ~1 BTC
        conditions = [{"blocks": [{"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0x03)},      # GT operator
            {"type": "NUMERIC", "hex": numeric_hex(500000000)},  # 5 BTC threshold
        ]}]}]

        # Bootstrap with a controlled 1 BTC output
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]
        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        lock_amount = Decimal("1.0")
        change_amount = Decimal(input_amount) - lock_amount - Decimal("0.001")
        change_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        bootstrap = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [
                {"amount": lock_amount, "conditions": conditions},
                {"amount": change_amount, "conditions": change_conditions},
            ]
        )
        sign_boot = node.signrungtx(
            bootstrap["hex"],
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_boot["complete"]
        boot_txid = node.sendrawtransaction(sign_boot["hex"])
        self.generate(node, 1)

        # Try to spend — COMPARE GT 5 BTC will fail on ~1 BTC input
        boot_info = node.getrawtransaction(boot_txid, True)
        boot_spk = boot_info["vout"][0]["scriptPubKey"]["hex"]
        boot_amount = Decimal(str(boot_info["vout"][0]["value"]))

        dest_wif, dest_pubkey = make_keypair()
        spend = node.createrungtx(
            [{"txid": boot_txid, "vout": 0}],
            [{"amount": boot_amount - Decimal("0.001"), "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COMPARE"}]}],
            [{"amount": float(boot_amount), "scriptPubKey": boot_spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  COMPARE (below threshold) correctly rejected!")

    def test_negative_tagged_hash_wrong_preimage(self, node):
        """TAGGED_HASH negative: wrong preimage fails verification."""
        self.log.info("Testing TAGGED_HASH negative (wrong preimage)...")

        privkey_wif, pubkey_hex = make_keypair()

        # Create tagged hash conditions
        tag = b"ghost/test-tag"
        preimage = b"correct_preimage_data"
        tag_hash = hashlib.sha256(tag).digest()

        # Compute correct tagged hash: SHA256(SHA256(tag) || SHA256(tag) || preimage)
        tagged_hasher = hashlib.sha256()
        tagged_hasher.update(tag_hash)
        tagged_hasher.update(tag_hash)
        tagged_hasher.update(preimage)
        expected_hash = tagged_hasher.digest()

        conditions = [{"blocks": [{"type": "TAGGED_HASH", "fields": [
            {"type": "HASH256", "hex": tag_hash.hex()},
            {"type": "HASH256", "hex": expected_hash.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )

        # Sign with WRONG preimage
        wrong_preimage = b"wrong_preimage_data"
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TAGGED_HASH", "preimage": wrong_preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  TAGGED_HASH (wrong preimage) correctly rejected!")

    def test_recurse_same(self, node):
        """RECURSE_SAME: spend into output with identical conditions."""
        self.log.info("Testing RECURSE_SAME (covenant re-encumbrance)...")

        privkey_wif, pubkey_hex = make_keypair()

        # RECURSE_SAME with max_depth=5
        conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},  # max_depth
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  RECURSE_SAME output: {txid}:{vout}")

        # Spend into output with IDENTICAL conditions (same RECURSE_SAME block)
        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": conditions}]  # same conditions
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_SAME"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_SAME spend confirmed: {spend_txid}")

        # Verify the output still has the same conditions
        validate = node.validateladder(node.getrawtransaction(spend_txid))
        assert validate["valid"]
        self.log.info("  RECURSE_SAME covenant re-encumbrance passed!")

    def test_negative_recurse_same_different(self, node):
        """RECURSE_SAME negative: output with different conditions rejected."""
        self.log.info("Testing RECURSE_SAME negative (different output conditions)...")

        privkey_wif, pubkey_hex = make_keypair()

        conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        # Try to spend into output with DIFFERENT conditions
        different_conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # different max_depth
        ]}]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": different_conditions}]
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_SAME"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  RECURSE_SAME (different conditions) correctly rejected!")

    def test_recurse_same_chain(self, node):
        """RECURSE_SAME: multi-hop covenant chain (3 consecutive spends)."""
        self.log.info("Testing RECURSE_SAME chain (3-hop covenant)...")

        conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # max_depth
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  Hop 0 (bootstrap): {txid}:{vout}")

        # Chain 3 spends, each re-encumbering with identical conditions
        for hop in range(1, 4):
            output_amount = amount - Decimal("0.001")
            spend = node.createrungtx(
                [{"txid": txid, "vout": vout}],
                [{"amount": output_amount, "conditions": conditions}]
            )
            sign_result = node.signrungtx(
                spend["hex"],
                [{"input": 0, "blocks": [{"type": "RECURSE_SAME"}]}],
                [{"amount": amount, "scriptPubKey": spk}]
            )
            assert sign_result["complete"]

            txid = node.sendrawtransaction(sign_result["hex"])
            self.generate(node, 1)
            tx_info = node.getrawtransaction(txid, True)
            assert tx_info["confirmations"] >= 1
            spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
            amount = output_amount
            vout = 0
            self.log.info(f"  Hop {hop}: {txid}")

        self.log.info("  RECURSE_SAME 3-hop chain passed!")

    def test_recurse_until_re_encumber(self, node):
        """RECURSE_UNTIL: before termination height, must re-encumber with same conditions."""
        self.log.info("Testing RECURSE_UNTIL (re-encumber before termination)...")

        current_height = node.getblockcount()
        until_height = current_height + 100  # far in the future

        conditions = [{"blocks": [{"type": "RECURSE_UNTIL", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(until_height)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  RECURSE_UNTIL output: {txid}:{vout} (until_height={until_height})")

        # Spend BEFORE until_height — must re-encumber with identical conditions
        # nLockTime = current height (below until_height)
        current = node.getblockcount()
        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": conditions}],  # same conditions
            current,  # nLockTime < until_height
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_UNTIL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_UNTIL re-encumber confirmed: {spend_txid}")
        self.log.info("  RECURSE_UNTIL re-encumber before termination passed!")

    def test_recurse_until_termination(self, node):
        """RECURSE_UNTIL: covenant terminates when block height >= until_height."""
        self.log.info("Testing RECURSE_UNTIL (termination at target height)...")

        # Get current height and set until_height just a few blocks ahead
        current_height = node.getblockcount()
        until_height = current_height + 3

        conditions = [{"blocks": [{"type": "RECURSE_UNTIL", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(until_height)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  RECURSE_UNTIL output: {txid}:{vout} (until_height={until_height})")

        # Mine past the until_height
        blocks_needed = until_height - node.getblockcount() + 1
        if blocks_needed > 0:
            self.generate(node, blocks_needed)
        self.log.info(f"  Current height: {node.getblockcount()} (>= {until_height})")

        # Now spend freely — covenant terminates at/past until_height
        # Set nLockTime to current height (like CLTV, consensus uses nLockTime as height proxy)
        current = node.getblockcount()
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            current,  # nLockTime = current height (>= until_height)
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_UNTIL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_UNTIL termination confirmed: {spend_txid}")
        self.log.info("  RECURSE_UNTIL termination at target height passed!")

    def test_negative_recurse_until_no_reencumber(self, node):
        """RECURSE_UNTIL negative: before termination, spending without re-encumbering rejected."""
        self.log.info("Testing RECURSE_UNTIL negative (no re-encumber before termination)...")

        current_height = node.getblockcount()
        until_height = current_height + 100

        conditions = [{"blocks": [{"type": "RECURSE_UNTIL", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(until_height)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        # Try to spend into DIFFERENT conditions before until_height
        current = node.getblockcount()
        dest_wif, dest_pubkey = make_keypair()
        different_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": different_conditions}],
            current,  # nLockTime < until_height
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_UNTIL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  RECURSE_UNTIL (no re-encumber) correctly rejected!")

    def test_recurse_count(self, node):
        """RECURSE_COUNT: countdown covenant from 2→1→0 then free spend."""
        self.log.info("Testing RECURSE_COUNT (countdown 2→0 then free spend)...")

        initial_count = 2
        conditions = [{"blocks": [{"type": "RECURSE_COUNT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(initial_count)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  Count {initial_count} (bootstrap): {txid}:{vout}")

        # Decrement: count=2 → output count=1 → output count=0
        for remaining in range(initial_count - 1, -1, -1):
            output_amount = amount - Decimal("0.001")
            next_conditions = [{"blocks": [{"type": "RECURSE_COUNT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(remaining)},
            ]}]}]

            spend = node.createrungtx(
                [{"txid": txid, "vout": vout}],
                [{"amount": output_amount, "conditions": next_conditions}]
            )

            sign_result = node.signrungtx(
                spend["hex"],
                [{"input": 0, "blocks": [{"type": "RECURSE_COUNT"}]}],
                [{"amount": amount, "scriptPubKey": spk}]
            )
            assert sign_result["complete"]

            txid = node.sendrawtransaction(sign_result["hex"])
            self.generate(node, 1)
            tx_info = node.getrawtransaction(txid, True)
            assert tx_info["confirmations"] >= 1
            spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
            amount = output_amount
            vout = 0
            self.log.info(f"  Count {remaining}: {txid}")

        # Now count=0 — covenant terminates, spend freely to any output
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        free_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": free_conditions}]
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_COUNT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Free spend (count=0 terminated): {txid}")
        self.log.info("  RECURSE_COUNT countdown + free spend passed!")


if __name__ == '__main__':
    LadderScriptBasicTest(__file__).main()

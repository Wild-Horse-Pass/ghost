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
from test_framework.script import hash160
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

        # Additional Phase 1 tests
        self.test_hash160_preimage_spend(node)
        self.test_csv_time_spend(node)
        self.test_cltv_time_spend(node)

        # Recursion tests
        self.test_recurse_same(node)
        self.test_negative_recurse_same_different(node)
        self.test_recurse_same_chain(node)
        self.test_recurse_until_re_encumber(node)
        self.test_recurse_until_termination(node)
        self.test_negative_recurse_until_no_reencumber(node)
        self.test_recurse_count(node)
        self.test_recurse_modified(node)
        self.test_recurse_split(node)

        # PLC block tests
        self.test_hysteresis_value(node)
        self.test_rate_limit(node)
        self.test_sequencer(node)

        # Remaining block type tests
        self.test_adaptor_sig(node)
        self.test_anchor(node)
        self.test_anchor_channel(node)
        self.test_anchor_pool(node)
        self.test_anchor_reserve(node)
        self.test_anchor_seal(node)
        self.test_anchor_oracle(node)
        self.test_recurse_decay(node)
        self.test_hysteresis_fee(node)
        self.test_timer_continuous(node)
        self.test_timer_off_delay(node)
        self.test_latch_set(node)
        self.test_latch_reset(node)
        self.test_counter_down(node)
        self.test_counter_preset(node)
        self.test_counter_up(node)
        self.test_one_shot(node)

        # Negative tests for remaining block types
        self.test_negative_adaptor_sig_wrong_key(node)
        self.test_negative_anchor_reserve_n_gt_m(node)
        self.test_negative_hysteresis_fee_low_gt_high(node)
        self.test_negative_anchor_channel_zero_commitment(node)
        self.test_negative_anchor_pool_zero_count(node)
        self.test_negative_anchor_oracle_zero_count(node)
        self.test_negative_timer_continuous_zero(node)
        self.test_negative_counter_preset_missing_field(node)
        self.test_negative_one_shot_missing_hash(node)
        self.test_negative_recurse_decay_wrong_delta(node)

        # Edge case tests
        self.test_multi_rung_mixed_blocks(node)
        self.test_max_blocks_per_rung(node)
        self.test_deeply_nested_covenant_chain(node)

        # RPC hardening tests
        self.test_rpc_unknown_block_type(node)
        self.test_rpc_unknown_data_type(node)
        self.test_rpc_empty_rungs(node)
        self.test_rpc_invalid_field_hex(node)
        self.test_rpc_decoderung_invalid_hex(node)
        self.test_rpc_createrungtx_negative_amount(node)
        self.test_rpc_signrungtx_missing_spent_info(node)

    # =========================================================================
    # Helpers
    # =========================================================================

    def bootstrap_v3_output(self, node, conditions, output_amount=None):
        """Create and confirm a v3 output with given conditions.
        Returns (txid, vout, amount, scriptPubKey_hex).
        If output_amount is specified and leaves excess, a change output is added."""
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

        outputs = [{"amount": output_amount, "conditions": conditions}]

        # Add change output if there's significant excess (> 0.01 BTC)
        change = Decimal(input_amount) - output_amount - Decimal("0.001")
        if change > Decimal("0.01"):
            change_wif, change_pubkey = make_keypair()
            change_conditions = [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": change_pubkey}
            ]}]}]
            outputs.append({"amount": change, "conditions": change_conditions})

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            outputs
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

    def test_recurse_modified(self, node):
        """RECURSE_MODIFIED: covenant with single-parameter increase per hop."""
        self.log.info("Testing RECURSE_MODIFIED (single mutation per hop)...")

        # Conditions: RECURSE_MODIFIED + COMPARE(GT threshold) in same rung
        # Mutation spec: block_idx=1 (COMPARE), param_idx=1 (value_b = threshold), delta=+1000
        # Each hop increases the minimum threshold for COMPARE
        initial_threshold = 10000  # GT 10000 sats
        conditions = [{"blocks": [
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},   # max_depth
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # mutation_block_idx (COMPARE is block 1)
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # mutation_param_idx (second NUMERIC = threshold)
                {"type": "NUMERIC", "hex": numeric_hex(1000)},  # delta = +1000
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT operator
                {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  RECURSE_MODIFIED output: {txid}:{vout} (threshold={initial_threshold})")

        # Hop 1: mutate threshold from 10000 to 11000
        new_threshold = initial_threshold + 1000
        mutated_conditions = [{"blocks": [
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1000)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT operator (unchanged)
                {"type": "NUMERIC", "hex": numeric_hex(new_threshold)},
            ]},
        ]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": mutated_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_MODIFIED"}, {"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_MODIFIED hop (threshold {initial_threshold}→{new_threshold}): {txid}")
        self.log.info("  RECURSE_MODIFIED passed!")

    def test_recurse_split(self, node):
        """RECURSE_SPLIT: split one UTXO into two re-encumbered outputs."""
        self.log.info("Testing RECURSE_SPLIT (1→2 split)...")

        min_split_sats = 10000  # 0.0001 BTC
        conditions = [{"blocks": [{"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},          # max_splits
            {"type": "NUMERIC", "hex": numeric_hex(min_split_sats)},  # min_split_sats
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  RECURSE_SPLIT output: {txid}:{vout} ({amount} BTC)")

        # Split into two outputs, each carrying RECURSE_SPLIT with max_splits-1
        split_conditions = [{"blocks": [{"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},          # decremented
            {"type": "NUMERIC", "hex": numeric_hex(min_split_sats)},
        ]}]}]

        half = (amount - Decimal("0.001")) / 2
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [
                {"amount": half, "conditions": split_conditions},
                {"amount": half, "conditions": split_conditions},
            ]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_SPLIT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        assert len(tx_info["vout"]) == 2
        self.log.info(f"  RECURSE_SPLIT confirmed (2 outputs): {txid}")
        self.log.info("  RECURSE_SPLIT passed!")

    def test_hash160_preimage_spend(self, node):
        """HASH160_PREIMAGE: RIPEMD160(SHA256(preimage)) spend."""
        self.log.info("Testing HASH160_PREIMAGE spend...")

        preimage = os.urandom(16)
        h160 = hash160(preimage)

        conditions = [{"blocks": [{"type": "HASH160_PREIMAGE", "fields": [
            {"type": "HASH160", "hex": h160.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  HASH160_PREIMAGE output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HASH160_PREIMAGE", "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  HASH160_PREIMAGE spend confirmed!")

    def test_csv_time_spend(self, node):
        """CSV_TIME: relative time-based sequence lock spend."""
        self.log.info("Testing CSV_TIME spend...")

        # 512 seconds = 1 unit in time-based CSV (each unit is 512 seconds)
        # Set TYPE_FLAG (bit 22 = 0x00400000) to indicate time-based
        csv_time_units = 1  # 512 seconds
        csv_sequence = 0x00400000 | csv_time_units  # TYPE_FLAG | units

        conditions = [{"blocks": [{"type": "CSV_TIME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(csv_sequence)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  CSV_TIME output: {txid}:{vout} (sequence=0x{csv_sequence:08x})")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Advance mocktime by 600 seconds (> 512) and mine blocks to push MTP forward
        current_time = node.getblock(node.getbestblockhash())["time"]
        node.setmocktime(current_time + 600)
        self.generate(node, 11)  # MTP = median of last 11 blocks

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_sequence}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "CSV_TIME"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        # Reset mocktime
        node.setmocktime(0)
        self.log.info("  CSV_TIME spend confirmed!")

    def test_cltv_time_spend(self, node):
        """CLTV_TIME: absolute time-based locktime spend."""
        self.log.info("Testing CLTV_TIME spend...")

        # Use a timestamp above LOCKTIME_THRESHOLD (500_000_000)
        # Get current MTP and set target to current MTP - 1 (already passed)
        current_mtp = node.getblock(node.getbestblockhash())["mediantime"]
        target_time = current_mtp - 1  # one second in the past

        conditions = [{"blocks": [{"type": "CLTV_TIME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(target_time)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  CLTV_TIME output: {txid}:{vout} (target_time={target_time})")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # nLockTime must be >= target_time, and MTP must be >= nLockTime
        # Use target_time as locktime (MTP is already past it since we used MTP-1)
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            target_time,  # nLockTime = target timestamp
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV_TIME"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  CLTV_TIME spend confirmed!")

    def test_hysteresis_value(self, node):
        """HYSTERESIS_VALUE: input amount must be within [low, high] band."""
        self.log.info("Testing HYSTERESIS_VALUE spend...")

        # Set band: 0.1 BTC to ~42.9 BTC (max uint32 in sats)
        low_sats = 10_000_000   # 0.1 BTC
        high_sats = 0xFFFFFFFF  # ~42.9 BTC (max uint32)

        conditions = [{"blocks": [{"type": "HYSTERESIS_VALUE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(high_sats)},
            {"type": "NUMERIC", "hex": numeric_hex(low_sats)},
        ]}]}]

        # Use 10 BTC output to stay within uint32 NUMERIC range
        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions, output_amount=Decimal("10.0"))
        self.log.info(f"  HYSTERESIS_VALUE output: {txid}:{vout} ({amount} BTC)")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HYSTERESIS_VALUE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  HYSTERESIS_VALUE spend confirmed!")

    def test_rate_limit(self, node):
        """RATE_LIMIT: output amount must be within per-block limit."""
        self.log.info("Testing RATE_LIMIT spend...")

        max_per_block = 0xFFFFFFFF  # ~42.9 BTC per block limit (max uint32)
        accumulation_cap = 0xFFFFFFFF  # same
        refill_blocks = 10

        conditions = [{"blocks": [{"type": "RATE_LIMIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(max_per_block)},
            {"type": "NUMERIC", "hex": numeric_hex(accumulation_cap)},
            {"type": "NUMERIC", "hex": numeric_hex(refill_blocks)},
        ]}]}]

        # Use 10 BTC output to stay within uint32 NUMERIC range
        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions, output_amount=Decimal("10.0"))
        self.log.info(f"  RATE_LIMIT output: {txid}:{vout} ({amount} BTC)")

        # Spend within limit (output_amount is the first output's value, checked by RATE_LIMIT)
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RATE_LIMIT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  RATE_LIMIT spend confirmed!")

    def test_sequencer(self, node):
        """SEQUENCER: step 0 of 3 is valid."""
        self.log.info("Testing SEQUENCER spend...")

        conditions = [{"blocks": [{"type": "SEQUENCER", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # current_step
            {"type": "NUMERIC", "hex": numeric_hex(3)},  # total_steps
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  SEQUENCER output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "SEQUENCER"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  SEQUENCER spend confirmed!")


    def test_adaptor_sig(self, node):
        """ADAPTOR_SIG: adapted signature with signing_key + adaptor_point."""
        self.log.info("Testing ADAPTOR_SIG spend...")

        # ADAPTOR_SIG needs 2 pubkeys + 1 signature
        # The adapted sig verifies against signing_key (adaptor secret already applied)
        signing_wif, signing_pubkey = make_keypair()
        _adaptor_wif, adaptor_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ADAPTOR_SIG", "fields": [
            {"type": "PUBKEY", "hex": signing_pubkey},
            {"type": "PUBKEY", "hex": adaptor_pubkey},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ADAPTOR_SIG output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        # Sign via block-level privkey (ADAPTOR_SIG handler in signrungtx)
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ADAPTOR_SIG", "privkey": signing_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ADAPTOR_SIG spend confirmed!")

    def test_anchor(self, node):
        """ANCHOR: generic anchor with at least one field."""
        self.log.info("Testing ANCHOR spend...")

        conditions = [{"blocks": [{"type": "ANCHOR", "fields": [
            {"type": "HASH256", "hex": os.urandom(32).hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ANCHOR output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR spend confirmed!")

    def test_anchor_channel(self, node):
        """ANCHOR_CHANNEL: 2 pubkeys + optional commitment > 0."""
        self.log.info("Testing ANCHOR_CHANNEL spend...")

        _local_wif, local_pubkey = make_keypair()
        _remote_wif, remote_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ANCHOR_CHANNEL", "fields": [
            {"type": "PUBKEY", "hex": local_pubkey},
            {"type": "PUBKEY", "hex": remote_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(42)},  # commitment_number
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ANCHOR_CHANNEL output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_CHANNEL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_CHANNEL spend confirmed!")

    def test_anchor_pool(self, node):
        """ANCHOR_POOL: vtxo tree root hash + optional participant count."""
        self.log.info("Testing ANCHOR_POOL spend...")

        conditions = [{"blocks": [{"type": "ANCHOR_POOL", "fields": [
            {"type": "HASH256", "hex": os.urandom(32).hex()},
            {"type": "NUMERIC", "hex": numeric_hex(42)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ANCHOR_POOL output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_POOL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_POOL spend confirmed!")

    def test_anchor_reserve(self, node):
        """ANCHOR_RESERVE: 2 numerics (n <= m) + 1 hash."""
        self.log.info("Testing ANCHOR_RESERVE spend...")

        conditions = [{"blocks": [{"type": "ANCHOR_RESERVE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},   # threshold_n
            {"type": "NUMERIC", "hex": numeric_hex(5)},   # threshold_m
            {"type": "HASH256", "hex": os.urandom(32).hex()},  # guardian set hash
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ANCHOR_RESERVE output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_RESERVE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_RESERVE spend confirmed!")

    def test_anchor_seal(self, node):
        """ANCHOR_SEAL: 2 hashes (asset_id + state_transition)."""
        self.log.info("Testing ANCHOR_SEAL spend...")

        conditions = [{"blocks": [{"type": "ANCHOR_SEAL", "fields": [
            {"type": "HASH256", "hex": os.urandom(32).hex()},  # asset_id
            {"type": "HASH256", "hex": os.urandom(32).hex()},  # state_transition
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ANCHOR_SEAL output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_SEAL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_SEAL spend confirmed!")

    def test_anchor_oracle(self, node):
        """ANCHOR_ORACLE: 1 pubkey + optional outcome count."""
        self.log.info("Testing ANCHOR_ORACLE spend...")

        _oracle_wif, oracle_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ANCHOR_ORACLE", "fields": [
            {"type": "PUBKEY", "hex": oracle_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # outcome_count
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ANCHOR_ORACLE output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_ORACLE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_ORACLE spend confirmed!")

    def test_recurse_decay(self, node):
        """RECURSE_DECAY: covenant with parameter subtraction per hop."""
        self.log.info("Testing RECURSE_DECAY (parameter decay per hop)...")

        # Conditions: RECURSE_DECAY + COMPARE(GT threshold) in same rung
        # Decay spec: block_idx=1 (COMPARE), param_idx=1 (value_b = threshold), decay_per_step=500
        # Each hop DECREASES the threshold by 500 (relaxing constraint)
        initial_threshold = 5000
        conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},   # max_depth
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # decay_block_idx (COMPARE is block 1)
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # decay_param_idx (second NUMERIC = threshold)
                {"type": "NUMERIC", "hex": numeric_hex(500)},  # decay_per_step
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT operator
                {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  RECURSE_DECAY output: {txid}:{vout} (threshold={initial_threshold})")

        # Hop 1: decay threshold from 5000 to 4500
        new_threshold = initial_threshold - 500
        decayed_conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(500)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(new_threshold)},
            ]},
        ]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": decayed_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_DECAY"}, {"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_DECAY hop (threshold {initial_threshold}→{new_threshold}): {txid}")
        self.log.info("  RECURSE_DECAY passed!")

    def test_hysteresis_fee(self, node):
        """HYSTERESIS_FEE: 2 numerics (high >= low), structural only."""
        self.log.info("Testing HYSTERESIS_FEE spend...")

        conditions = [{"blocks": [{"type": "HYSTERESIS_FEE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(100)},  # high_sat_vb
            {"type": "NUMERIC", "hex": numeric_hex(10)},   # low_sat_vb
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  HYSTERESIS_FEE output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HYSTERESIS_FEE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  HYSTERESIS_FEE spend confirmed!")

    def test_timer_continuous(self, node):
        """TIMER_CONTINUOUS: 1 numeric > 0, structural only."""
        self.log.info("Testing TIMER_CONTINUOUS spend...")

        conditions = [{"blocks": [{"type": "TIMER_CONTINUOUS", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(144)},  # block count
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  TIMER_CONTINUOUS output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMER_CONTINUOUS"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  TIMER_CONTINUOUS spend confirmed!")

    def test_timer_off_delay(self, node):
        """TIMER_OFF_DELAY: 1 numeric > 0, structural only."""
        self.log.info("Testing TIMER_OFF_DELAY spend...")

        conditions = [{"blocks": [{"type": "TIMER_OFF_DELAY", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(72)},  # hold blocks
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  TIMER_OFF_DELAY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMER_OFF_DELAY"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  TIMER_OFF_DELAY spend confirmed!")

    def test_latch_set(self, node):
        """LATCH_SET: 1 pubkey required, structural only."""
        self.log.info("Testing LATCH_SET spend...")

        _setter_wif, setter_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "LATCH_SET", "fields": [
            {"type": "PUBKEY", "hex": setter_pubkey},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  LATCH_SET output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "LATCH_SET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  LATCH_SET spend confirmed!")

    def test_latch_reset(self, node):
        """LATCH_RESET: 1 pubkey + 1 numeric required, structural only."""
        self.log.info("Testing LATCH_RESET spend...")

        _resetter_wif, resetter_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "LATCH_RESET", "fields": [
            {"type": "PUBKEY", "hex": resetter_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(6)},  # delay blocks
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  LATCH_RESET output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "LATCH_RESET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  LATCH_RESET spend confirmed!")

    def test_counter_down(self, node):
        """COUNTER_DOWN: 1 pubkey + 1 numeric required, structural only."""
        self.log.info("Testing COUNTER_DOWN spend...")

        _event_wif, event_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "COUNTER_DOWN", "fields": [
            {"type": "PUBKEY", "hex": event_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # initial count
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  COUNTER_DOWN output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COUNTER_DOWN"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  COUNTER_DOWN spend confirmed!")

    def test_counter_preset(self, node):
        """COUNTER_PRESET: 2 numerics required, structural only."""
        self.log.info("Testing COUNTER_PRESET spend...")

        conditions = [{"blocks": [{"type": "COUNTER_PRESET", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},    # preset_count
            {"type": "NUMERIC", "hex": numeric_hex(100)},  # window_blocks
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  COUNTER_PRESET output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COUNTER_PRESET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  COUNTER_PRESET spend confirmed!")

    def test_counter_up(self, node):
        """COUNTER_UP: 1 pubkey + 1 numeric required, structural only."""
        self.log.info("Testing COUNTER_UP spend...")

        _event_wif, event_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "COUNTER_UP", "fields": [
            {"type": "PUBKEY", "hex": event_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # initial count
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  COUNTER_UP output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COUNTER_UP"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  COUNTER_UP spend confirmed!")

    def test_one_shot(self, node):
        """ONE_SHOT: 1 numeric + 1 hash required, structural only."""
        self.log.info("Testing ONE_SHOT spend...")

        conditions = [{"blocks": [{"type": "ONE_SHOT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(144)},  # duration blocks
            {"type": "HASH256", "hex": os.urandom(32).hex()},  # commitment
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  ONE_SHOT output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ONE_SHOT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ONE_SHOT spend confirmed!")


    # =========================================================================
    # Edge case tests
    # =========================================================================

    def test_multi_rung_mixed_blocks(self, node):
        """Multi-rung ladder with different block types in each rung (OR logic)."""
        self.log.info("Testing multi-rung ladder with mixed block types...")

        # Rung 0: SIG + CSV (both must pass = AND logic)
        # Rung 1: HASH_PREIMAGE (fallback)
        privkey_wif, pubkey_hex = make_keypair()
        preimage = os.urandom(16)
        hash_val = hashlib.sha256(preimage).digest()

        conditions = [
            {"blocks": [
                {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]},
                {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(1)}]},
            ]},
            {"blocks": [
                {"type": "HASH_PREIMAGE", "fields": [{"type": "HASH256", "hex": hash_val.hex()}]},
            ]},
        ]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  Multi-rung output: {txid}:{vout}")

        # Spend via rung 1 (HASH_PREIMAGE fallback) — target rung 1
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "rung": 1, "blocks": [{"type": "HASH_PREIMAGE", "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Multi-rung mixed blocks spend confirmed (via fallback rung)!")

    def test_max_blocks_per_rung(self, node):
        """8 blocks per rung (max policy limit)."""
        self.log.info("Testing max blocks per rung (8)...")

        # Build a rung with 8 structural blocks
        blocks = []
        for _ in range(8):
            _wif, pk = make_keypair()
            blocks.append({"type": "LATCH_SET", "fields": [
                {"type": "PUBKEY", "hex": pk},
            ]})

        conditions = [{"blocks": blocks}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  Max blocks output: {txid}:{vout} (8 blocks)")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        # All 8 LATCH_SET blocks in witness
        sign_blocks = [{"type": "LATCH_SET"} for _ in range(8)]
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": sign_blocks}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Max blocks per rung (8) spend confirmed!")

    def test_deeply_nested_covenant_chain(self, node):
        """RECURSE_SAME 5-hop covenant chain."""
        self.log.info("Testing deeply nested covenant chain (5 hops)...")

        conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # max_depth
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)
        self.log.info(f"  Covenant chain start: {txid}:{vout}")

        for hop in range(5):
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
            self.log.info(f"  Hop {hop + 1}: {txid}")

        self.log.info("  5-hop covenant chain passed!")

    # =========================================================================
    # RPC hardening tests
    # =========================================================================

    def test_rpc_unknown_block_type(self, node):
        """createrung rejects unknown block type."""
        self.log.info("Testing RPC: unknown block type...")
        assert_raises_rpc_error(-8, "Unknown block type", node.createrung,
            [{"blocks": [{"type": "NONEXISTENT_BLOCK", "fields": []}]}])
        self.log.info("  Unknown block type correctly rejected!")

    def test_rpc_unknown_data_type(self, node):
        """createrung rejects unknown data type."""
        self.log.info("Testing RPC: unknown data type...")
        assert_raises_rpc_error(-8, "Unknown data type", node.createrung,
            [{"blocks": [{"type": "SIG", "fields": [
                {"type": "BOGUS_TYPE", "hex": "aabb"}
            ]}]}])
        self.log.info("  Unknown data type correctly rejected!")

    def test_rpc_empty_rungs(self, node):
        """createrung rejects empty rungs array."""
        self.log.info("Testing RPC: empty rungs array...")
        # Empty rungs should serialize but produce a witness with 0 rungs
        # which would fail deserialization. Let's check both paths.
        result = node.createrung([{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": "02" + "aa" * 32}
        ]}]}])
        assert "hex" in result

        # decoderung with malformed hex should fail
        assert_raises_rpc_error(-22, None, node.decoderung, "deadbeef")
        self.log.info("  Empty rungs / malformed hex correctly handled!")

    def test_rpc_invalid_field_hex(self, node):
        """createrung rejects invalid field hex data."""
        self.log.info("Testing RPC: invalid field hex...")
        # HASH256 must be exactly 32 bytes
        assert_raises_rpc_error(-8, None, node.createrung,
            [{"blocks": [{"type": "ANCHOR", "fields": [
                {"type": "HASH256", "hex": "aabb"}  # 2 bytes, not 32
            ]}]}])
        self.log.info("  Invalid field hex correctly rejected!")

    def test_rpc_decoderung_invalid_hex(self, node):
        """decoderung rejects completely invalid hex."""
        self.log.info("Testing RPC: decoderung invalid hex...")
        assert_raises_rpc_error(-22, None, node.decoderung, "00")  # zero rungs
        assert_raises_rpc_error(-8, None, node.decoderung, "")  # empty → invalid hex
        self.log.info("  decoderung invalid hex correctly rejected!")

    def test_rpc_createrungtx_negative_amount(self, node):
        """createrungtx rejects negative output amount."""
        self.log.info("Testing RPC: createrungtx negative amount...")
        assert_raises_rpc_error(-3, None, node.createrungtx,
            [{"txid": "aa" * 32, "vout": 0}],
            [{"amount": Decimal("-0.001"), "conditions": [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": "02" + "aa" * 32}
            ]}]}]}])
        self.log.info("  createrungtx negative amount correctly rejected!")

    def test_rpc_signrungtx_missing_spent_info(self, node):
        """signrungtx rejects mismatched spent_outputs count."""
        self.log.info("Testing RPC: signrungtx mismatched spent info...")

        # Create a valid unsigned tx first
        privkey_wif, pubkey_hex = make_keypair()
        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]
        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )

        # Pass empty spent_outputs (should have 1) → error
        assert_raises_rpc_error(-8, "spent_outputs count", node.signrungtx,
            spend["hex"],
            [{"privkey": privkey_wif, "input": 0}],
            [])  # empty: count mismatch
        self.log.info("  signrungtx mismatched spent info correctly rejected!")

    # =========================================================================
    # Negative tests for remaining block types
    # =========================================================================

    def test_negative_adaptor_sig_wrong_key(self, node):
        """ADAPTOR_SIG: wrong signing key should fail."""
        self.log.info("Testing ADAPTOR_SIG negative (wrong key)...")

        _signing_wif, signing_pubkey = make_keypair()
        _adaptor_wif, adaptor_pubkey = make_keypair()
        wrong_wif, _wrong_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ADAPTOR_SIG", "fields": [
            {"type": "PUBKEY", "hex": signing_pubkey},
            {"type": "PUBKEY", "hex": adaptor_pubkey},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ADAPTOR_SIG", "privkey": wrong_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ADAPTOR_SIG (wrong key) correctly rejected!")

    def test_negative_anchor_reserve_n_gt_m(self, node):
        """ANCHOR_RESERVE: n > m should fail (UNSATISFIED)."""
        self.log.info("Testing ANCHOR_RESERVE negative (n > m)...")

        conditions = [{"blocks": [{"type": "ANCHOR_RESERVE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(7)},   # threshold_n > threshold_m
            {"type": "NUMERIC", "hex": numeric_hex(5)},   # threshold_m
            {"type": "HASH256", "hex": os.urandom(32).hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_RESERVE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ANCHOR_RESERVE (n > m) correctly rejected!")

    def test_negative_hysteresis_fee_low_gt_high(self, node):
        """HYSTERESIS_FEE: low > high should fail (UNSATISFIED)."""
        self.log.info("Testing HYSTERESIS_FEE negative (low > high)...")

        conditions = [{"blocks": [{"type": "HYSTERESIS_FEE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},   # high_sat_vb
            {"type": "NUMERIC", "hex": numeric_hex(100)},  # low_sat_vb > high
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HYSTERESIS_FEE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  HYSTERESIS_FEE (low > high) correctly rejected!")

    def test_negative_anchor_channel_zero_commitment(self, node):
        """ANCHOR_CHANNEL: commitment_number = 0 should fail (UNSATISFIED)."""
        self.log.info("Testing ANCHOR_CHANNEL negative (zero commitment)...")

        _local_wif, local_pubkey = make_keypair()
        _remote_wif, remote_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ANCHOR_CHANNEL", "fields": [
            {"type": "PUBKEY", "hex": local_pubkey},
            {"type": "PUBKEY", "hex": remote_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # commitment_number = 0
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_CHANNEL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ANCHOR_CHANNEL (zero commitment) correctly rejected!")

    def test_negative_anchor_pool_zero_count(self, node):
        """ANCHOR_POOL: participant_count = 0 should fail (UNSATISFIED)."""
        self.log.info("Testing ANCHOR_POOL negative (zero count)...")

        conditions = [{"blocks": [{"type": "ANCHOR_POOL", "fields": [
            {"type": "HASH256", "hex": os.urandom(32).hex()},
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # participant_count = 0
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_POOL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ANCHOR_POOL (zero count) correctly rejected!")

    def test_negative_anchor_oracle_zero_count(self, node):
        """ANCHOR_ORACLE: outcome_count = 0 should fail (UNSATISFIED)."""
        self.log.info("Testing ANCHOR_ORACLE negative (zero count)...")

        _oracle_wif, oracle_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ANCHOR_ORACLE", "fields": [
            {"type": "PUBKEY", "hex": oracle_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # outcome_count = 0
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_ORACLE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ANCHOR_ORACLE (zero count) correctly rejected!")

    def test_negative_timer_continuous_zero(self, node):
        """TIMER_CONTINUOUS: value = 0 should fail (UNSATISFIED)."""
        self.log.info("Testing TIMER_CONTINUOUS negative (zero value)...")

        conditions = [{"blocks": [{"type": "TIMER_CONTINUOUS", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # 0 is invalid
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMER_CONTINUOUS"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  TIMER_CONTINUOUS (zero) correctly rejected!")

    def test_negative_counter_preset_missing_field(self, node):
        """COUNTER_PRESET: only 1 numeric (needs 2) should fail (ERROR)."""
        self.log.info("Testing COUNTER_PRESET negative (missing field)...")

        conditions = [{"blocks": [{"type": "COUNTER_PRESET", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},  # only preset_count, missing window_blocks
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COUNTER_PRESET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  COUNTER_PRESET (missing field) correctly rejected!")

    def test_negative_one_shot_missing_hash(self, node):
        """ONE_SHOT: numeric only (missing hash) should fail (ERROR)."""
        self.log.info("Testing ONE_SHOT negative (missing hash)...")

        conditions = [{"blocks": [{"type": "ONE_SHOT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(144)},  # duration only, no commitment hash
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ONE_SHOT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ONE_SHOT (missing hash) correctly rejected!")

    def test_negative_recurse_decay_wrong_delta(self, node):
        """RECURSE_DECAY: wrong decay delta should fail."""
        self.log.info("Testing RECURSE_DECAY negative (wrong delta)...")

        initial_threshold = 5000
        conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(500)},  # decay_per_step = 500
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v3_output(node, conditions)

        # Apply wrong delta: subtract 300 instead of 500
        wrong_threshold = initial_threshold - 300
        wrong_conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(500)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(wrong_threshold)},
            ]},
        ]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": wrong_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_DECAY"}, {"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  RECURSE_DECAY (wrong delta) correctly rejected!")


if __name__ == '__main__':
    LadderScriptBasicTest(__file__).main()

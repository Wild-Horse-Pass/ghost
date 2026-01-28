#!/usr/bin/env python3
# Copyright (c) 2024-present The Ghost Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Ghost Lock creation and spending paths.

Tests the Ghost Lock P2TR structure:
- Key-path spending (normal unlock with lock_pubkey)
- Script-path normal spending (leaf 0: backup key-path)
- Script-path recovery after timelock expires (leaf 1)
- Recovery attempt before timelock (should fail)

Ghost Lock Taproot Structure:
- Internal key: lock_pubkey
- Leaf 0: <lock_pubkey> OP_CHECKSIG
- Leaf 1: <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP <recovery_pubkey> OP_CHECKSIG
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.messages import (
    CTransaction,
    CTxIn,
    CTxOut,
    COutPoint,
    CTxInWitness,
    tx_from_hex,
    COIN,
)
from test_framework.script import (
    CScript,
    OP_CHECKSIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    SIGHASH_DEFAULT,
    LEAF_VERSION_TAPSCRIPT,
    taproot_construct,
    TaprootSignatureHash,
)
from test_framework.key import ECKey, compute_xonly_pubkey, tweak_add_privkey, sign_schnorr
from decimal import Decimal

# For regtest, use shorter timelocks for testing
TEST_RECOVERY_TIMELOCK = 10  # 10 blocks


class WalletGhostLockSpendingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Testing Ghost Lock spending functionality...")

        node = self.nodes[0]

        # Generate blocks to have funds and activate CSV
        self.generate(node, 200)
        self.sync_all()

        # Run tests
        self.test_ghost_lock_construction()
        self.test_key_path_spending(node)
        self.test_script_path_normal_spending(node)
        self.test_recovery_before_timelock_fails(node)
        self.test_recovery_after_timelock(node)

    def build_ghost_lock(self, lock_key, recovery_key, timelock=TEST_RECOVERY_TIMELOCK):
        """Build a Ghost Lock Taproot output.

        Returns: (TaprootInfo, lock_privkey, recovery_privkey)
        """
        # Get x-only pubkeys from private keys
        lock_xonly, _ = compute_xonly_pubkey(lock_key.get_bytes())
        recovery_xonly, _ = compute_xonly_pubkey(recovery_key.get_bytes())

        # Leaf 0: <lock_pubkey> OP_CHECKSIG (backup spending path)
        normal_script = CScript([lock_xonly, OP_CHECKSIG])

        # Leaf 1: <timelock> OP_CSV OP_DROP <recovery_pubkey> OP_CHECKSIG
        recovery_script = CScript([
            timelock,  # CScript handles minimal encoding for integers
            OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            recovery_xonly,
            OP_CHECKSIG
        ])

        # Build Taproot tree with lock_pubkey as internal key
        scripts = [
            ("normal", normal_script),
            ("recovery", recovery_script),
        ]

        taproot_info = taproot_construct(lock_xonly, scripts)
        return taproot_info

    def test_ghost_lock_construction(self):
        """Test that Ghost Lock scripts are constructed correctly."""
        self.log.info("Test: Ghost Lock construction...")

        # Generate keys
        lock_key = ECKey()
        lock_key.generate()
        recovery_key = ECKey()
        recovery_key.generate()

        taproot_info = self.build_ghost_lock(lock_key, recovery_key)

        # Verify structure
        assert len(taproot_info.scriptPubKey) == 34, "P2TR should be 34 bytes"
        assert taproot_info.scriptPubKey[0] == 0x51, "Should start with OP_1"
        assert "normal" in taproot_info.leaves, "Should have normal leaf"
        assert "recovery" in taproot_info.leaves, "Should have recovery leaf"

        self.log.info(f"  Script: {taproot_info.scriptPubKey.hex()}")
        self.log.info(f"  Leaves: {list(taproot_info.leaves.keys())}")
        self.log.info("  Construction: OK")

    def test_key_path_spending(self, node):
        """Test spending Ghost Lock via key-path (normal spending)."""
        self.log.info("Test: Key-path spending...")

        # Generate keys
        lock_key = ECKey()
        lock_key.generate()
        recovery_key = ECKey()
        recovery_key.generate()

        taproot_info = self.build_ghost_lock(lock_key, recovery_key)

        # Create address from scriptPubKey
        # We need to encode it as a bech32m address
        from test_framework.address import program_to_witness
        address = program_to_witness(1, taproot_info.output_pubkey)

        self.log.info(f"  Ghost Lock address: {address}")

        # Fund the Ghost Lock
        amount = Decimal("0.01")
        txid = node.sendtoaddress(address, float(amount))
        self.generate(node, 1)

        # Get the funding transaction (use gettransaction for wallet txs)
        fund_tx_hex = node.gettransaction(txid)['hex']
        fund_tx = tx_from_hex(fund_tx_hex)

        # Find our output
        vout = None
        for i, out in enumerate(fund_tx.vout):
            if out.scriptPubKey == taproot_info.scriptPubKey:
                vout = i
                break

        assert vout is not None, "Should find Ghost Lock output"
        self.log.info(f"  Funded: {txid}:{vout}")

        # Create spending transaction
        spend_tx = CTransaction()
        spend_tx.version = 2
        spend_tx.vin = [CTxIn(COutPoint(int(txid, 16), vout))]

        # Get destination
        dest_addr = node.getnewaddress("", "bech32m")
        dest_script = bytes.fromhex(node.getaddressinfo(dest_addr)['scriptPubKey'])
        fee = 1000  # 1000 sats fee
        spend_tx.vout = [CTxOut(int(amount * COIN) - fee, dest_script)]

        # Sign with key-path (Schnorr signature)
        # For key-path, we sign with the tweaked private key
        sighash = TaprootSignatureHash(
            spend_tx, [fund_tx.vout[vout]], SIGHASH_DEFAULT, 0
        )

        # Tweak the lock key for key-path spending
        tweaked_privkey = tweak_add_privkey(lock_key.get_bytes(), taproot_info.tweak)
        assert tweaked_privkey is not None, "Failed to tweak private key"

        signature = sign_schnorr(tweaked_privkey, sighash)

        # Set witness for key-path (just signature)
        spend_tx.wit.vtxinwit = [CTxInWitness()]
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [signature]

        # Broadcast
        spend_txid = node.sendrawtransaction(spend_tx.serialize().hex())
        self.generate(node, 1)

        # Verify
        tx_info = node.gettransaction(spend_txid)
        assert_equal(tx_info['confirmations'], 1)
        self.log.info(f"  Key-path spend successful: {spend_txid}")

    def test_script_path_normal_spending(self, node):
        """Test spending Ghost Lock via script-path normal leaf."""
        self.log.info("Test: Script-path normal spending (leaf 0)...")

        # Generate keys
        lock_key = ECKey()
        lock_key.generate()
        recovery_key = ECKey()
        recovery_key.generate()

        taproot_info = self.build_ghost_lock(lock_key, recovery_key)

        # Get address
        from test_framework.address import program_to_witness
        address = program_to_witness(1, taproot_info.output_pubkey)

        # Fund
        amount = Decimal("0.01")
        txid = node.sendtoaddress(address, float(amount))
        self.generate(node, 1)

        # Get funding tx
        fund_tx_hex = node.gettransaction(txid)['hex']
        fund_tx = tx_from_hex(fund_tx_hex)

        vout = None
        for i, out in enumerate(fund_tx.vout):
            if out.scriptPubKey == taproot_info.scriptPubKey:
                vout = i
                break

        # Create spending tx
        spend_tx = CTransaction()
        spend_tx.version = 2
        spend_tx.vin = [CTxIn(COutPoint(int(txid, 16), vout))]

        dest_addr = node.getnewaddress("", "bech32m")
        dest_script = bytes.fromhex(node.getaddressinfo(dest_addr)['scriptPubKey'])
        fee = 1000
        spend_tx.vout = [CTxOut(int(amount * COIN) - fee, dest_script)]

        # Get normal leaf info
        normal_leaf = taproot_info.leaves["normal"]

        # Sign for script-path
        sighash = TaprootSignatureHash(
            spend_tx, [fund_tx.vout[vout]], SIGHASH_DEFAULT, 0,
            scriptpath=True,
            leaf_script=normal_leaf.script,
        )

        signature = sign_schnorr(lock_key.get_bytes(), sighash)

        # Build control block
        control_block = bytes([LEAF_VERSION_TAPSCRIPT + taproot_info.negflag]) + \
                        taproot_info.internal_pubkey + \
                        normal_leaf.merklebranch

        # Set witness: signature, script, control_block
        spend_tx.wit.vtxinwit = [CTxInWitness()]
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [
            signature,
            normal_leaf.script,
            control_block,
        ]

        # Broadcast
        spend_txid = node.sendrawtransaction(spend_tx.serialize().hex())
        self.generate(node, 1)

        tx_info = node.gettransaction(spend_txid)
        assert_equal(tx_info['confirmations'], 1)
        self.log.info(f"  Script-path normal spend successful: {spend_txid}")

    def test_recovery_before_timelock_fails(self, node):
        """Test that recovery spending fails before timelock expires."""
        self.log.info("Test: Recovery before timelock should fail...")

        # Generate keys
        lock_key = ECKey()
        lock_key.generate()
        recovery_key = ECKey()
        recovery_key.generate()

        taproot_info = self.build_ghost_lock(lock_key, recovery_key, TEST_RECOVERY_TIMELOCK)

        from test_framework.address import program_to_witness
        address = program_to_witness(1, taproot_info.output_pubkey)

        # Fund
        amount = Decimal("0.01")
        txid = node.sendtoaddress(address, float(amount))
        self.generate(node, 1)  # Only 1 confirmation

        fund_tx_hex = node.gettransaction(txid)['hex']
        fund_tx = tx_from_hex(fund_tx_hex)

        vout = None
        for i, out in enumerate(fund_tx.vout):
            if out.scriptPubKey == taproot_info.scriptPubKey:
                vout = i
                break

        # Create recovery spend tx
        spend_tx = CTransaction()
        spend_tx.version = 2
        # Set nSequence for CSV
        spend_tx.vin = [CTxIn(COutPoint(int(txid, 16), vout), nSequence=TEST_RECOVERY_TIMELOCK)]

        dest_addr = node.getnewaddress("", "bech32m")
        dest_script = bytes.fromhex(node.getaddressinfo(dest_addr)['scriptPubKey'])
        fee = 1000
        spend_tx.vout = [CTxOut(int(amount * COIN) - fee, dest_script)]

        # Get recovery leaf
        recovery_leaf = taproot_info.leaves["recovery"]

        # Sign
        sighash = TaprootSignatureHash(
            spend_tx, [fund_tx.vout[vout]], SIGHASH_DEFAULT, 0,
            scriptpath=True,
            leaf_script=recovery_leaf.script,
        )

        signature = sign_schnorr(recovery_key.get_bytes(), sighash)

        # Build control block
        control_block = bytes([LEAF_VERSION_TAPSCRIPT + taproot_info.negflag]) + \
                        taproot_info.internal_pubkey + \
                        recovery_leaf.merklebranch

        spend_tx.wit.vtxinwit = [CTxInWitness()]
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [
            signature,
            recovery_leaf.script,
            control_block,
        ]

        # Should fail due to CSV
        assert_raises_rpc_error(
            -26,
            "non-BIP68-final",
            node.sendrawtransaction,
            spend_tx.serialize().hex()
        )
        self.log.info("  Recovery correctly rejected (CSV not satisfied)")

        # Save for next test
        self.recovery_test_data = {
            'txid': txid,
            'vout': vout,
            'amount': amount,
            'recovery_key': recovery_key,
            'taproot_info': taproot_info,
            'fund_tx': fund_tx,
        }

    def test_recovery_after_timelock(self, node):
        """Test recovery spending after timelock expires."""
        self.log.info("Test: Recovery after timelock...")

        # Use saved data from previous test
        data = self.recovery_test_data
        txid = data['txid']
        vout = data['vout']
        amount = data['amount']
        recovery_key = data['recovery_key']
        taproot_info = data['taproot_info']
        fund_tx = data['fund_tx']

        # Mine enough blocks for timelock to expire
        self.generate(node, TEST_RECOVERY_TIMELOCK)

        # Create recovery spend tx
        spend_tx = CTransaction()
        spend_tx.version = 2
        spend_tx.vin = [CTxIn(COutPoint(int(txid, 16), vout), nSequence=TEST_RECOVERY_TIMELOCK)]

        dest_addr = node.getnewaddress("", "bech32m")
        dest_script = bytes.fromhex(node.getaddressinfo(dest_addr)['scriptPubKey'])
        fee = 1000
        spend_tx.vout = [CTxOut(int(amount * COIN) - fee, dest_script)]

        # Get recovery leaf
        recovery_leaf = taproot_info.leaves["recovery"]

        # Sign
        sighash = TaprootSignatureHash(
            spend_tx, [fund_tx.vout[vout]], SIGHASH_DEFAULT, 0,
            scriptpath=True,
            leaf_script=recovery_leaf.script,
        )

        signature = sign_schnorr(recovery_key.get_bytes(), sighash)

        # Build control block
        control_block = bytes([LEAF_VERSION_TAPSCRIPT + taproot_info.negflag]) + \
                        taproot_info.internal_pubkey + \
                        recovery_leaf.merklebranch

        spend_tx.wit.vtxinwit = [CTxInWitness()]
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [
            signature,
            recovery_leaf.script,
            control_block,
        ]

        # Should succeed now
        spend_txid = node.sendrawtransaction(spend_tx.serialize().hex())
        self.generate(node, 1)

        tx_info = node.gettransaction(spend_txid)
        assert_equal(tx_info['confirmations'], 1)
        self.log.info(f"  Recovery spend successful: {spend_txid}")


if __name__ == '__main__':
    WalletGhostLockSpendingTest(__file__).main()

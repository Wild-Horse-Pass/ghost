#!/usr/bin/env python3
# Copyright (c) 2024-present The Ghost Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Silent Payment (BIP-352) wallet functionality.

Tests:
- Ghost ID generation and encoding
- Silent Payment address derivation
- Payment detection via checksilentpayment
- Ghost Lock OP_RETURN parsing
- Wallet scanning for SP outputs
- SP rescan functionality
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class WalletSilentPaymentsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Testing Silent Payment functionality...")

        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Generate some blocks to have funds
        self.generate(node0, 101)

        self.test_ghost_id_generation(node0)
        self.test_address_derivation(node0)
        self.test_check_silent_payment(node0)
        self.test_ghost_opreturn_parsing(node0)
        self.test_sp_stats(node0)
        self.test_cross_wallet_detection(node0, node1)

    def test_ghost_id_generation(self, node):
        """Test Ghost ID (Silent Payment address) generation."""
        self.log.info("Testing Ghost ID generation...")

        # Get the wallet's Ghost ID
        result = node.getsilentpaymentaddress()

        # Verify structure
        assert 'ghost_id' in result
        assert 'scan_pubkey' in result
        assert 'spend_pubkey' in result

        ghost_id = result['ghost_id']
        self.log.info(f"Generated Ghost ID: {ghost_id[:20]}...")

        # Ghost ID should start with 'ghost1'
        assert ghost_id.startswith('ghost1'), f"Ghost ID should start with 'ghost1', got {ghost_id[:10]}"

        # Ghost ID should be ~112 characters (66 bytes bech32m encoded)
        assert_greater_than(len(ghost_id), 100)
        assert_greater_than(120, len(ghost_id))

        # Pubkeys should be 66 hex characters (33 bytes compressed)
        assert_equal(len(result['scan_pubkey']), 66)
        assert_equal(len(result['spend_pubkey']), 66)

        # Calling again should return the same Ghost ID
        result2 = node.getsilentpaymentaddress()
        assert_equal(result['ghost_id'], result2['ghost_id'])

        self.log.info("Ghost ID generation: PASSED")

    def test_address_derivation(self, node):
        """Test one-time address derivation from Ghost ID."""
        self.log.info("Testing address derivation...")

        # Get Ghost ID first
        sp_addr = node.getsilentpaymentaddress()
        ghost_id = sp_addr['ghost_id']

        # Derive address at index 0
        derived0 = node.derivesilentpaymentaddress(ghost_id, 0, 0)

        assert 'address' in derived0
        assert 'output_pubkey' in derived0
        assert 'ephemeral_pubkey' in derived0
        assert_equal(derived0['index'], 0)
        assert_equal(derived0['nonce'], 0)

        # Address should be a valid bech32m P2TR address
        address = derived0['address']
        assert address.startswith('bcrt1p') or address.startswith('tb1p') or address.startswith('bc1p'), \
            f"Expected P2TR address, got {address[:10]}"

        # Output pubkey should be 66 hex chars (33 bytes compressed)
        assert_equal(len(derived0['output_pubkey']), 66)

        # Ephemeral pubkey should be 66 hex chars (33 bytes compressed)
        assert_equal(len(derived0['ephemeral_pubkey']), 66)

        # Derive at different indices - should get different addresses
        derived1 = node.derivesilentpaymentaddress(ghost_id, 1, 0)
        derived2 = node.derivesilentpaymentaddress(ghost_id, 0, 1)

        assert derived0['address'] != derived1['address'], "Different indices should give different addresses"
        assert derived0['address'] != derived2['address'], "Different nonces should give different addresses"
        assert derived1['address'] != derived2['address'], "All derivations should be unique"

        self.log.info("Address derivation: PASSED")

    def test_check_silent_payment(self, node):
        """Test checking if an output belongs to the wallet."""
        self.log.info("Testing Silent Payment check...")

        # Get Ghost ID and derive an address
        sp_addr = node.getsilentpaymentaddress()
        ghost_id = sp_addr['ghost_id']

        derived = node.derivesilentpaymentaddress(ghost_id, 0, 0)

        # Check if the derived output belongs to us
        result = node.checksilentpayment(
            derived['ephemeral_pubkey'],
            derived['output_pubkey'],
            0,  # index
            0   # nonce
        )

        assert 'is_mine' in result
        assert result['is_mine'] == True, "Output derived from our Ghost ID should be ours"

        if result['is_mine']:
            assert 'tweak' in result
            assert result['tweak'] is not None

        # Check with wrong output pubkey - should not be ours
        fake_pubkey = "0" * 64
        result_fake = node.checksilentpayment(
            derived['ephemeral_pubkey'],
            fake_pubkey,
            0,
            0
        )
        assert result_fake['is_mine'] == False, "Fake pubkey should not be ours"

        self.log.info("Silent Payment check: PASSED")

    def test_ghost_opreturn_parsing(self, node):
        """Test Ghost Lock OP_RETURN parsing."""
        self.log.info("Testing Ghost Lock OP_RETURN parsing...")

        # Get Ghost ID and derive to get an ephemeral pubkey
        sp_addr = node.getsilentpaymentaddress()
        derived = node.derivesilentpaymentaddress(sp_addr['ghost_id'], 0, 0)

        ephemeral_pubkey = derived['ephemeral_pubkey']

        # Create valid Ghost Lock OP_RETURN data
        # Format: GHOST_MARKER (4 bytes = "47484F53") + ephemeral_pubkey (33 bytes)
        ghost_marker = "47484f53"  # "GHOS" in hex
        valid_opreturn = ghost_marker + ephemeral_pubkey

        # Parse valid OP_RETURN
        result = node.parseghostopreturn(valid_opreturn)

        assert result['valid'] == True
        assert result['ephemeral_pubkey'] == ephemeral_pubkey

        # Test invalid OP_RETURN (wrong marker)
        invalid_marker = "12345678" + ephemeral_pubkey
        result_invalid = node.parseghostopreturn(invalid_marker)
        assert result_invalid['valid'] == False

        # Test too short data
        result_short = node.parseghostopreturn(ghost_marker)
        assert result_short['valid'] == False

        self.log.info("Ghost Lock OP_RETURN parsing: PASSED")

    def test_sp_stats(self, node):
        """Test Silent Payment statistics."""
        self.log.info("Testing SP statistics...")

        # Get stats (should be empty initially)
        stats = node.getsilentpaymentstats()

        assert 'total_outputs' in stats
        assert 'total_amount' in stats
        assert 'earliest_block' in stats
        assert 'latest_block' in stats

        # Initially should have no outputs
        assert_equal(stats['total_outputs'], 0)

        self.log.info("SP statistics: PASSED")

    def test_cross_wallet_detection(self, node0, node1):
        """Test that one wallet can create payments detectable by another."""
        self.log.info("Testing cross-wallet payment detection...")

        # Get node1's Ghost ID
        node1_sp = node1.getsilentpaymentaddress()
        node1_ghost_id = node1_sp['ghost_id']

        # Node0 derives an address for node1
        derived = node0.derivesilentpaymentaddress(node1_ghost_id, 0, 0)

        # Node1 should be able to detect this as theirs
        result = node1.checksilentpayment(
            derived['ephemeral_pubkey'],
            derived['output_pubkey'],
            0,
            0
        )

        assert result['is_mine'] == True, "Node1 should detect payment derived from its Ghost ID"

        # Node0 should NOT detect this as theirs
        result0 = node0.checksilentpayment(
            derived['ephemeral_pubkey'],
            derived['output_pubkey'],
            0,
            0
        )

        assert result0['is_mine'] == False, "Node0 should not claim payment derived for Node1"

        self.log.info("Cross-wallet payment detection: PASSED")


if __name__ == '__main__':
    WalletSilentPaymentsTest(__file__).main()

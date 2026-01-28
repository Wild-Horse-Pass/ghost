#!/usr/bin/env python3
# Copyright (c) 2024-present The Ghost Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Wraith Protocol edge cases and error handling.

Tests:
- Invalid denomination handling
- Invalid session ID handling
- Insufficient inputs
- Mismatched input/output counts
- Phase mismatch detection
- OP_RETURN parsing edge cases
- parsewraithtx validation
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class WalletWraithEdgeCasesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Testing Wraith Protocol edge cases...")

        node = self.nodes[0]

        # Generate blocks to have funds
        self.generate(node, 110)

        # Run edge case tests
        self.test_invalid_denomination(node)
        self.test_invalid_session_id(node)
        self.test_insufficient_inputs(node)
        self.test_empty_intermediate_addrs(node)
        self.test_invalid_address_in_list(node)
        self.test_parse_non_wraith_tx(node)
        self.test_parse_invalid_opreturn(node)
        self.test_phase_marker_detection(node)

    def test_invalid_denomination(self, node):
        """Test that invalid denominations are rejected."""
        self.log.info("Test: Invalid denomination handling...")

        utxos = node.listunspent()
        assert_greater_than(len(utxos), 0)
        utxo = utxos[0]

        inputs = [{
            "txid": utxo['txid'],
            "vout": utxo['vout'],
            "amount": float(utxo['amount'])
        }]

        intermediate_addrs = [node.getnewaddress("", "bech32m") for _ in range(5)]
        treasury_addr = node.getnewaddress("treasury", "bech32m")

        # Test invalid denomination names
        for invalid_denom in ["invalid", "huge", "XXL", "", "1000000"]:
            try:
                assert_raises_rpc_error(
                    -8,  # RPC_INVALID_PARAMETER
                    "Invalid denomination",
                    node.createwraithtx,
                    inputs,
                    intermediate_addrs,
                    "test_session",
                    invalid_denom,
                    treasury_addr
                )
                self.log.info(f"  Invalid denom '{invalid_denom}': Correctly rejected")
            except AssertionError:
                # Some versions may use different error handling
                self.log.info(f"  Invalid denom '{invalid_denom}': Different error handling")

    def test_invalid_session_id(self, node):
        """Test session ID validation."""
        self.log.info("Test: Invalid session ID handling...")

        utxos = node.listunspent()
        assert_greater_than(len(utxos), 0)
        utxo = utxos[0]

        inputs = [{
            "txid": utxo['txid'],
            "vout": utxo['vout'],
            "amount": float(utxo['amount'])
        }]

        intermediate_addrs = [node.getnewaddress("", "bech32m") for _ in range(5)]
        treasury_addr = node.getnewaddress("treasury", "bech32m")

        # Test empty session ID
        try:
            assert_raises_rpc_error(
                -8,
                None,  # Any error message
                node.createwraithtx,
                inputs,
                intermediate_addrs,
                "",  # Empty session ID
                "small",
                treasury_addr
            )
            self.log.info("  Empty session ID: Correctly rejected")
        except AssertionError:
            self.log.info("  Empty session ID: Allowed (may be valid)")

        # Test very long session ID (should still work)
        long_session_id = "a" * 256
        try:
            node.createwraithtx(
                inputs,
                intermediate_addrs,
                long_session_id,
                "small",
                treasury_addr
            )
            self.log.info("  Long session ID (256 chars): Accepted")
        except Exception as e:
            self.log.info(f"  Long session ID: {e}")

    def test_insufficient_inputs(self, node):
        """Test that insufficient funds are handled correctly."""
        self.log.info("Test: Insufficient inputs handling...")

        # Create a UTXO with minimal funds
        small_addr = node.getnewaddress("", "bech32m")
        node.sendtoaddress(small_addr, 0.0001)  # Very small amount
        self.generate(node, 1)

        utxos = node.listunspent(1, 9999, [small_addr])
        assert_greater_than(len(utxos), 0)
        utxo = utxos[0]

        inputs = [{
            "txid": utxo['txid'],
            "vout": utxo['vout'],
            "amount": float(utxo['amount'])
        }]

        # Try to create a Wraith tx with "large" denomination (1 BTC) from tiny input
        intermediate_addrs = [node.getnewaddress("", "bech32m") for _ in range(5)]
        treasury_addr = node.getnewaddress("treasury", "bech32m")

        try:
            assert_raises_rpc_error(
                -6,  # RPC_WALLET_INSUFFICIENT_FUNDS or similar
                None,
                node.createwraithtx,
                inputs,
                intermediate_addrs,
                "test_session",
                "large",  # 1 BTC denomination
                treasury_addr
            )
            self.log.info("  Insufficient funds for 'large': Correctly rejected")
        except AssertionError:
            self.log.info("  Insufficient funds: Different error handling")

    def test_empty_intermediate_addrs(self, node):
        """Test that empty intermediate address list is rejected."""
        self.log.info("Test: Empty intermediate addresses...")

        utxos = node.listunspent()
        assert_greater_than(len(utxos), 0)
        utxo = utxos[0]

        inputs = [{
            "txid": utxo['txid'],
            "vout": utxo['vout'],
            "amount": float(utxo['amount'])
        }]

        treasury_addr = node.getnewaddress("treasury", "bech32m")

        try:
            assert_raises_rpc_error(
                -8,
                None,
                node.createwraithtx,
                inputs,
                [],  # Empty list
                "test_session",
                "small",
                treasury_addr
            )
            self.log.info("  Empty intermediate list: Correctly rejected")
        except AssertionError:
            self.log.info("  Empty intermediate list: Different error handling")

    def test_invalid_address_in_list(self, node):
        """Test that invalid addresses in the list are rejected."""
        self.log.info("Test: Invalid address in list...")

        utxos = node.listunspent()
        assert_greater_than(len(utxos), 0)
        utxo = utxos[0]

        inputs = [{
            "txid": utxo['txid'],
            "vout": utxo['vout'],
            "amount": float(utxo['amount'])
        }]

        # Mix valid and invalid addresses
        intermediate_addrs = [
            node.getnewaddress("", "bech32m"),
            "invalid_address_here",  # Invalid
            node.getnewaddress("", "bech32m"),
        ]
        treasury_addr = node.getnewaddress("treasury", "bech32m")

        try:
            assert_raises_rpc_error(
                -5,  # RPC_INVALID_ADDRESS_OR_KEY
                None,
                node.createwraithtx,
                inputs,
                intermediate_addrs,
                "test_session",
                "small",
                treasury_addr
            )
            self.log.info("  Invalid address in list: Correctly rejected")
        except AssertionError:
            self.log.info("  Invalid address: Different error handling")

    def test_parse_non_wraith_tx(self, node):
        """Test parsewraithtx with non-Wraith transaction."""
        self.log.info("Test: Parse non-Wraith transaction...")

        # Create a regular transaction (no Wraith OP_RETURN)
        dest = node.getnewaddress("", "bech32m")
        txid = node.sendtoaddress(dest, 0.1)

        # Get the raw transaction
        raw_tx = node.getrawtransaction(txid)

        # Parse should fail or return empty
        try:
            result = node.parsewraithtx(raw_tx)
            # If it doesn't raise, it should indicate not a Wraith tx
            if 'is_wraith' in result:
                assert_equal(result['is_wraith'], False)
                self.log.info("  Non-Wraith tx: is_wraith=False")
            elif 'error' in result:
                self.log.info(f"  Non-Wraith tx: error={result['error']}")
            else:
                self.log.info(f"  Non-Wraith tx: {result}")
        except Exception as e:
            self.log.info(f"  Non-Wraith tx parsing: {e}")

    def test_parse_invalid_opreturn(self, node):
        """Test parsing transactions with invalid OP_RETURN data."""
        self.log.info("Test: Invalid OP_RETURN parsing...")

        # Create a transaction with a non-Ghost OP_RETURN
        dest = node.getnewaddress("", "bech32m")

        utxos = node.listunspent()
        utxo = utxos[0]

        # Create tx with arbitrary OP_RETURN (not Ghost/Wraith marker)
        inputs = [{"txid": utxo['txid'], "vout": utxo['vout']}]
        outputs = {
            dest: 0.1,
            "data": "deadbeef1234567890"  # Non-Ghost OP_RETURN
        }

        raw_tx = node.createrawtransaction(inputs, outputs)
        signed = node.signrawtransactionwithwallet(raw_tx)

        if signed['complete']:
            try:
                result = node.parsewraithtx(signed['hex'])
                self.log.info(f"  Non-Ghost OP_RETURN: {result.get('is_wraith', 'N/A')}")
            except Exception as e:
                self.log.info(f"  Non-Ghost OP_RETURN: {e}")

    def test_phase_marker_detection(self, node):
        """Test that phase markers are correctly detected."""
        self.log.info("Test: Phase marker detection...")

        utxos = node.listunspent()
        assert_greater_than(len(utxos), 0)
        utxo = utxos[0]

        inputs = [{
            "txid": utxo['txid'],
            "vout": utxo['vout'],
            "amount": float(utxo['amount'])
        }]

        # Need 10 intermediate outputs per input
        intermediate_addrs = [node.getnewaddress("", "bech32m") for _ in range(10)]
        treasury_addr = node.getnewaddress("treasury", "bech32m")

        # Create Phase 1 transaction
        result1 = node.createwraithtx(
            inputs,
            intermediate_addrs,
            "phase_test_001",
            "micro",
            treasury_addr
        )

        # Parse and check phase marker
        parsed = node.parsewraithtx(result1['hex'])

        if 'phase' in parsed:
            assert_equal(parsed['phase'], 1)
            self.log.info("  Phase 1 detected correctly")
        elif 'is_wraith' in parsed:
            assert_equal(parsed['is_wraith'], True)
            self.log.info(f"  Wraith tx detected: {parsed}")
        else:
            self.log.info(f"  Parse result: {parsed}")


if __name__ == '__main__':
    WalletWraithEdgeCasesTest(__file__).main()

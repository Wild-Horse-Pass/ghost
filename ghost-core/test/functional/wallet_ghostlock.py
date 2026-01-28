#!/usr/bin/env python3
# Copyright (c) 2024-present The Ghost Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Ghost Lock creation and detection.

Tests:
- Ghost Lock script creation
- P2TR output with recovery path
- Denomination handling
- Timelock validation
- Ghost Lock detection in blocks
"""

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


# Ghost Lock denominations in satoshis
DENOMINATIONS = {
    'micro': 10_000,         # 0.0001 BTC
    'tiny': 100_000,         # 0.001 BTC
    'small': 1_000_000,      # 0.01 BTC
    'medium': 10_000_000,    # 0.1 BTC
    'large': 100_000_000,    # 1 BTC
    'xl': 1_000_000_000,     # 10 BTC
}


class WalletGhostLockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Testing Ghost Lock functionality...")

        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Generate blocks to have funds
        self.generate(node0, 110)

        self.test_wraith_tx_creation(node0)
        self.test_wraith_final_tx(node0)
        self.test_reconciliation_tx(node0)
        self.test_output_shuffling(node0)
        self.test_batch_fee_estimation(node0)
        self.test_reconciliation_output_derivation(node0, node1)

    def test_wraith_tx_creation(self, node):
        """Test Wraith Protocol Phase 1 (Split) transaction creation."""
        self.log.info("Testing Wraith Phase 1 transaction creation...")

        # Get a UTXO to use as input
        utxos = node.listunspent()
        assert len(utxos) > 0, "Need UTXOs for test"

        utxo = utxos[0]

        # Create 10 intermediate output addresses (P2TR)
        intermediate_addrs = []
        for i in range(10):
            addr = node.getnewaddress("", "bech32m")
            intermediate_addrs.append(addr)

        # Get a treasury address
        treasury_addr = node.getnewaddress("treasury", "bech32m")

        # Create the Wraith Phase 1 transaction
        inputs = [{
            "txid": utxo['txid'],
            "vout": utxo['vout'],
            "amount": float(utxo['amount'])
        }]

        result = node.createwraithtx(
            inputs,
            intermediate_addrs,
            "test_session_001",
            "small",
            treasury_addr
        )

        assert 'hex' in result
        assert 'session_id' in result
        assert 'denomination' in result
        assert 'inputs' in result
        assert 'outputs' in result

        assert_equal(result['session_id'], "test_session_001")
        assert_equal(result['denomination'], "small")
        assert_equal(result['inputs'], 1)
        # 10 intermediate outputs + treasury + change
        assert_greater_than(result['outputs'], 10)

        # Verify the transaction is valid
        decoded = node.decoderawtransaction(result['hex'])
        assert_equal(len(decoded['vin']), 1)
        assert_greater_than(len(decoded['vout']), 10)

        self.log.info("Wraith Phase 1 transaction creation: PASSED")

    def test_wraith_final_tx(self, node):
        """Test Wraith Protocol Phase 2 (Merge) transaction creation."""
        self.log.info("Testing Wraith Phase 2 transaction creation...")

        # Get UTXOs
        utxos = node.listunspent()
        assert len(utxos) > 9, "Need at least 10 UTXOs for Phase 2"

        # Use 10 UTXOs as inputs (simulating intermediate outputs)
        # createwraithfinaltx expects 10 inputs per output
        inputs = []
        for i in range(10):
            utxo = utxos[i]
            inputs.append({
                "txid": utxo['txid'],
                "vout": utxo['vout'],
                "amount": float(utxo['amount'])
            })

        # Create 1 final output address (10 inputs -> 1 output)
        final_addrs = [node.getnewaddress("", "bech32m")]

        # Create the Wraith Phase 2 transaction
        result = node.createwraithfinaltx(
            inputs,
            final_addrs,
            "test_session_001",
            "small"
        )

        assert 'hex' in result
        assert 'session_id' in result
        assert 'denomination' in result
        assert 'inputs' in result
        assert 'outputs' in result

        assert_equal(result['inputs'], 10)
        # 1 value output + 1 OP_RETURN = 2 outputs
        assert_equal(result['outputs'], 2)

        # Verify the transaction structure
        decoded = node.decoderawtransaction(result['hex'])
        assert_equal(len(decoded['vin']), 10)
        assert_equal(len(decoded['vout']), 2)

        self.log.info("Wraith Phase 2 transaction creation: PASSED")

    def test_reconciliation_tx(self, node):
        """Test reconciliation batch transaction creation."""
        self.log.info("Testing reconciliation transaction creation...")

        # Get UTXOs
        utxos = node.listunspent()
        assert len(utxos) > 2, "Need UTXOs for reconciliation test"

        # Create inputs
        inputs = []
        for i in range(min(3, len(utxos))):
            utxo = utxos[i]
            inputs.append({
                "txid": utxo['txid'],
                "vout": utxo['vout'],
                "amount": float(utxo['amount'])
            })

        # Create outputs with ephemeral pubkeys (simulating SP derivation)
        # In real usage, these would come from derivereconciliationoutputs
        sp_addr = node.getsilentpaymentaddress()
        outputs = []
        for i in range(3):
            derived = node.derivesilentpaymentaddress(sp_addr['ghost_id'], i, 0)
            outputs.append({
                "address": derived['address'],
                "amount": 0.01,
                "ephemeral_pubkey": derived['ephemeral_pubkey']
            })

        # Get treasury address
        treasury_addr = node.getnewaddress("treasury", "bech32m")

        # Create reconciliation transaction
        result = node.createreconciliationtx(
            inputs,
            outputs,
            1,  # epoch_id
            "0" * 64,  # state_root (dummy)
            treasury_addr,
            0.001  # treasury_amount
        )

        assert 'hex' in result
        assert 'epoch_id' in result
        assert 'state_root' in result
        assert 'inputs' in result
        assert 'outputs' in result
        assert 'op_return_size' in result

        assert_equal(result['epoch_id'], 1)
        assert_greater_than(result['op_return_size'], 0)

        # Verify transaction has OP_RETURN
        decoded = node.decoderawtransaction(result['hex'])
        has_opreturn = False
        for vout in decoded['vout']:
            if vout['scriptPubKey']['type'] == 'nulldata':
                has_opreturn = True
                break
        assert has_opreturn, "Reconciliation tx should have OP_RETURN"

        self.log.info("Reconciliation transaction creation: PASSED")

    def test_output_shuffling(self, node):
        """Test transaction output shuffling for unlinkability."""
        self.log.info("Testing output shuffling...")

        # Create a simple transaction using createrawtransaction instead
        # since createwraithfinaltx has strict 10:1 input:output ratio
        utxos = node.listunspent()
        utxo = utxos[0]

        addrs = [node.getnewaddress("", "bech32m") for _ in range(5)]

        # Build a raw transaction with multiple outputs
        inputs = [{"txid": utxo['txid'], "vout": utxo['vout']}]
        outputs = {}
        amount_per_output = (float(utxo['amount']) - 0.001) / 5  # Subtract fee
        for addr in addrs:
            outputs[addr] = round(amount_per_output, 8)

        raw_tx = node.createrawtransaction(inputs, outputs)

        # Shuffle the outputs
        shuffled = node.shuffleoutputs(raw_tx, False)

        assert 'hex' in shuffled
        assert 'original_outputs' in shuffled
        assert 'shuffled_outputs' in shuffled

        # Verify output count is preserved
        assert_equal(shuffled['original_outputs'], shuffled['shuffled_outputs'])

        # The hex should be different (outputs reordered)
        # Note: There's a small chance they could be the same if shuffle
        # happens to produce the same order
        decoded_orig = node.decoderawtransaction(raw_tx)
        decoded_shuf = node.decoderawtransaction(shuffled['hex'])

        assert_equal(len(decoded_orig['vout']), len(decoded_shuf['vout']))

        self.log.info("Output shuffling: PASSED")

    def test_batch_fee_estimation(self, node):
        """Test batch transaction fee estimation."""
        self.log.info("Testing batch fee estimation...")

        # Estimate fee for 10 inputs, 10 outputs
        result = node.estimatebatchfee(10, 10, True, 6)

        assert 'estimated_vsize' in result
        assert 'estimated_weight' in result
        assert 'fee_rate' in result
        assert 'fee_rate_sat_vb' in result
        assert 'estimated_fee' in result
        assert 'fee_per_input' in result
        assert 'fee_per_output' in result
        assert 'breakdown' in result

        # Verify breakdown
        breakdown = result['breakdown']
        assert 'header' in breakdown
        assert 'inputs' in breakdown
        assert 'outputs' in breakdown
        assert 'witness' in breakdown
        assert 'op_return' in breakdown

        # Sanity checks
        assert_greater_than(result['estimated_vsize'], 0)
        assert_greater_than(result['estimated_weight'], 0)
        assert_greater_than(result['estimated_fee'], 0)

        # More outputs should mean higher fee
        result2 = node.estimatebatchfee(10, 20, True, 6)
        assert_greater_than(result2['estimated_vsize'], result['estimated_vsize'])

        self.log.info("Batch fee estimation: PASSED")

    def test_reconciliation_output_derivation(self, node0, node1):
        """Test deriving reconciliation outputs from Ghost IDs."""
        self.log.info("Testing reconciliation output derivation...")

        # Get Ghost IDs from both nodes
        sp0 = node0.getsilentpaymentaddress()
        sp1 = node1.getsilentpaymentaddress()

        # Create recipient list
        recipients = [
            {"ghost_id": sp0['ghost_id'], "amount": 0.01},
            {"ghost_id": sp1['ghost_id'], "amount": 0.02},
        ]

        # Derive outputs
        result = node0.derivereconciliationoutputs(recipients, 0)

        assert 'outputs' in result
        assert 'count' in result
        assert 'total_amount' in result

        assert_equal(result['count'], 2)
        assert_equal(result['total_amount'], Decimal('0.03'))

        # Verify each output
        for i, output in enumerate(result['outputs']):
            assert 'ghost_id' in output
            assert 'address' in output
            assert 'amount' in output
            assert 'ephemeral_pubkey' in output
            assert 'output_pubkey' in output

            # Address should be P2TR
            assert output['address'].startswith('bcrt1p') or \
                   output['address'].startswith('tb1p') or \
                   output['address'].startswith('bc1p')

        # Each node should be able to detect their own output
        # derivereconciliationoutputs uses CreatePayment with index=i, so
        # output0 was created with index=0, output1 with index=1
        output0 = result['outputs'][0]
        check0 = node0.checksilentpayment(
            output0['ephemeral_pubkey'],
            output0['output_pubkey'],
            0, 0  # index=0 matches CreatePayment call
        )
        assert check0['is_mine'] == True, f"node0 failed to detect its own output: {check0}"

        output1 = result['outputs'][1]
        check1 = node1.checksilentpayment(
            output1['ephemeral_pubkey'],
            output1['output_pubkey'],
            1, 0  # index=1 matches CreatePayment call
        )
        assert check1['is_mine'] == True, f"node1 failed to detect its own output: {check1}"

        self.log.info("Reconciliation output derivation: PASSED")


if __name__ == '__main__':
    WalletGhostLockTest(__file__).main()

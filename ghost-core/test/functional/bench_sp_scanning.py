#!/usr/bin/env python3
# Copyright (c) 2024-present The Ghost Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Benchmark Silent Payment scanning performance.

This benchmark measures:
- SP address derivation speed
- Ghost Lock OP_RETURN parsing speed
- Block scanning throughput
- Full rescan performance

Run with: python bench_sp_scanning.py [options]
"""

import time
from test_framework.test_framework import BitcoinTestFramework


class BenchSpScanningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Silent Payment Scanning Benchmark")
        self.log.info("=" * 50)

        sender = self.nodes[0]
        receiver = self.nodes[1]

        # Generate initial blocks
        self.generate(sender, 110)
        self.sync_all()

        # Run benchmarks
        self.bench_ghost_id_generation(receiver)
        self.bench_address_derivation(sender, receiver)
        self.bench_opreturn_parsing(sender)
        self.bench_check_silent_payment(receiver)
        self.bench_create_ghost_locks(sender, receiver)
        self.bench_rescan(receiver)

        self.log.info("=" * 50)
        self.log.info("Benchmark complete")

    def bench_ghost_id_generation(self, node):
        """Benchmark Ghost ID generation (should be cached after first call)."""
        self.log.info("\n--- Ghost ID Generation ---")

        # First call (generates keys)
        start = time.perf_counter()
        node.getsilentpaymentaddress()
        first_time = time.perf_counter() - start

        # Subsequent calls (cached)
        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            node.getsilentpaymentaddress()
        cached_time = time.perf_counter() - start

        self.log.info(f"  First call (key gen): {first_time*1000:.2f} ms")
        self.log.info(f"  Cached calls ({iterations}x): {cached_time*1000:.2f} ms total")
        self.log.info(f"  Cached per call: {cached_time*1000/iterations:.3f} ms")

    def bench_address_derivation(self, sender, receiver):
        """Benchmark one-time address derivation from Ghost ID."""
        self.log.info("\n--- Address Derivation ---")

        receiver_sp = receiver.getsilentpaymentaddress()
        ghost_id = receiver_sp['ghost_id']

        # Warm-up
        sender.derivesilentpaymentaddress(ghost_id, 0, 0)

        # Benchmark single derivation
        iterations = 100
        start = time.perf_counter()
        for i in range(iterations):
            sender.derivesilentpaymentaddress(ghost_id, i, 0)
        elapsed = time.perf_counter() - start

        derivations_per_sec = iterations / elapsed

        self.log.info(f"  {iterations} derivations: {elapsed*1000:.2f} ms")
        self.log.info(f"  Per derivation: {elapsed*1000/iterations:.3f} ms")
        self.log.info(f"  Throughput: {derivations_per_sec:.0f} derivations/sec")

    def bench_opreturn_parsing(self, node):
        """Benchmark Ghost Lock OP_RETURN parsing."""
        self.log.info("\n--- OP_RETURN Parsing ---")

        sp_addr = node.getsilentpaymentaddress()
        derived = node.derivesilentpaymentaddress(sp_addr['ghost_id'], 0, 0)
        ephemeral_pubkey = derived['ephemeral_pubkey']

        # Create valid OP_RETURN data
        ghost_marker = "47484f53"  # "GHOS"
        valid_opreturn = ghost_marker + ephemeral_pubkey

        # Benchmark parsing
        iterations = 1000
        start = time.perf_counter()
        for _ in range(iterations):
            node.parseghostopreturn(valid_opreturn)
        elapsed = time.perf_counter() - start

        parses_per_sec = iterations / elapsed

        self.log.info(f"  {iterations} parses: {elapsed*1000:.2f} ms")
        self.log.info(f"  Per parse: {elapsed*1000/iterations:.4f} ms")
        self.log.info(f"  Throughput: {parses_per_sec:.0f} parses/sec")

    def bench_check_silent_payment(self, node):
        """Benchmark checking if output belongs to wallet."""
        self.log.info("\n--- Check Silent Payment ---")

        sp_addr = node.getsilentpaymentaddress()
        derived = node.derivesilentpaymentaddress(sp_addr['ghost_id'], 0, 0)

        ephemeral_pubkey = derived['ephemeral_pubkey']
        output_pubkey = derived['output_pubkey']

        # Benchmark checking (positive case - output is ours)
        iterations = 100
        start = time.perf_counter()
        for i in range(iterations):
            node.checksilentpayment(ephemeral_pubkey, output_pubkey, 0, 0)
        elapsed = time.perf_counter() - start

        checks_per_sec = iterations / elapsed

        self.log.info(f"  {iterations} checks (positive): {elapsed*1000:.2f} ms")
        self.log.info(f"  Per check: {elapsed*1000/iterations:.3f} ms")
        self.log.info(f"  Throughput: {checks_per_sec:.0f} checks/sec")

        # Benchmark checking (negative case - random pubkey)
        fake_pubkey = "0" * 64
        start = time.perf_counter()
        for i in range(iterations):
            node.checksilentpayment(ephemeral_pubkey, fake_pubkey, 0, 0)
        elapsed = time.perf_counter() - start

        self.log.info(f"  {iterations} checks (negative): {elapsed*1000:.2f} ms")
        self.log.info(f"  Per check (negative): {elapsed*1000/iterations:.3f} ms")

    def bench_create_ghost_locks(self, sender, receiver):
        """Create multiple Ghost Lock transactions for rescan benchmark."""
        self.log.info("\n--- Creating Ghost Locks for Rescan ---")

        receiver_sp = receiver.getsilentpaymentaddress()
        receiver_ghost_id = receiver_sp['ghost_id']

        num_locks = 10
        txids = []

        start = time.perf_counter()
        for i in range(num_locks):
            # Derive address
            derived = sender.derivesilentpaymentaddress(receiver_ghost_id, i, 0)
            derived_address = derived['address']
            ephemeral_pubkey = derived['ephemeral_pubkey']

            # Create OP_RETURN data
            ghost_marker = "47484f53"
            opreturn_data = ghost_marker + ephemeral_pubkey

            # Get UTXO
            utxos = sender.listunspent()
            if len(utxos) == 0:
                self.generate(sender, 1)
                utxos = sender.listunspent()
            utxo = utxos[0]

            # Create transaction
            inputs = [{"txid": utxo['txid'], "vout": utxo['vout']}]
            input_amount = float(utxo['amount'])
            ghost_lock_amount = 0.001
            fee = 0.0001

            change_addr = sender.getnewaddress("", "bech32m")
            outputs = {
                derived_address: ghost_lock_amount,
                change_addr: round(input_amount - ghost_lock_amount - fee, 8),
                "data": opreturn_data
            }

            raw_tx = sender.createrawtransaction(inputs, outputs)
            signed = sender.signrawtransactionwithwallet(raw_tx)
            txid = sender.sendrawtransaction(signed['hex'])
            txids.append(txid)

            # Mine every few transactions
            if (i + 1) % 5 == 0:
                self.generate(sender, 1)

        # Mine remaining
        self.generate(sender, 1)
        self.sync_all()

        elapsed = time.perf_counter() - start

        self.log.info(f"  Created {num_locks} Ghost Locks: {elapsed*1000:.2f} ms")
        self.log.info(f"  Per lock (including mining): {elapsed*1000/num_locks:.2f} ms")

        self.ghost_lock_count = num_locks
        return txids

    def bench_rescan(self, receiver):
        """Benchmark SP rescan over blocks with Ghost Locks."""
        self.log.info("\n--- SP Rescan ---")

        height = receiver.getblockcount()
        blocks_to_scan = height

        # Full rescan
        start = time.perf_counter()
        result = receiver.rescansilentpayments(0, height)
        elapsed = time.perf_counter() - start

        blocks_scanned = result.get('blocks_scanned', blocks_to_scan)
        outputs_found = result.get('outputs_found', 0)

        blocks_per_sec = blocks_scanned / elapsed if elapsed > 0 else 0

        self.log.info(f"  Scanned {blocks_scanned} blocks: {elapsed*1000:.2f} ms")
        self.log.info(f"  Blocks per second: {blocks_per_sec:.0f}")
        self.log.info(f"  Outputs found: {outputs_found}")
        self.log.info(f"  Time per block: {elapsed*1000/blocks_scanned:.3f} ms")

        # Partial rescan (last 20 blocks)
        if height >= 20:
            start = time.perf_counter()
            result = receiver.rescansilentpayments(height - 20, height)
            elapsed = time.perf_counter() - start

            self.log.info(f"  Partial rescan (20 blocks): {elapsed*1000:.2f} ms")
            self.log.info(f"  Time per block (partial): {elapsed*1000/20:.3f} ms")


if __name__ == '__main__':
    BenchSpScanningTest(__file__).main()

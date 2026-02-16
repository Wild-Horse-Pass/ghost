#!/usr/bin/env python3
"""Quick test: can two ghostd nodes sync blocks at all? (no haze flags)"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import ECKey
from test_framework.address import key_to_p2wpkh

class QuickSyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ['-disablewallet'],
            ['-disablewallet'],
        ]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        key = ECKey()
        key.set(b'\x01' * 32, compressed=True)
        addr = key_to_p2wpkh(key.get_pubkey().get_bytes())
        self.log.info('Mining 10 blocks on node0...')
        self.generatetoaddress(self.nodes[0], 10, addr)
        self.log.info('Checking sync...')
        assert_equal(self.nodes[0].getblockcount(), self.nodes[1].getblockcount())
        self.log.info('PASSED: nodes synced')

if __name__ == "__main__":
    QuickSyncTest(__file__).main()

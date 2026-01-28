# Bitcoin Ghost Core

Bitcoin Ghost Core is a Bitcoin-compatible node distribution that enhances Bitcoin's infrastructure without modifying consensus rules.

## What is Bitcoin Ghost?

Bitcoin Ghost is a derivative of Bitcoin Core v30.1 that adds:

- **BUDS Integration** - Bitcoin Unified Data Standard for transaction classification
- **Enhanced Pruning** - VW/OW/AW window system for intelligent data retention
- **Ghost Mode** - Privacy-preserving relay options for operators
- **Integrated Mining Pool** - Fair 1% fee pool with node operator rewards
- **Node Incentives** - 4-share reward system for network participation

## Key Features

- ✅ **100% Bitcoin Compatible** - No consensus changes, works with standard Bitcoin network
- ✅ **Enhanced Privacy** - Ghost Mode for private node operation
- ✅ **Node Rewards** - Earn rewards for running infrastructure
- ✅ **Smart Pruning** - Keep what matters, prune what doesn't
- ✅ **Integrated Pool** - Built-in mining pool with fair economics

## Documentation

- Website: https://bitcoinghost.org/
- GitHub: https://github.com/bitcoin-ghost
- Whitepaper: https://bitcoinghost.org/whitepaper

## Installation
```bash
# Clone
git clone https://github.com/bitcoin-ghost/ghost-core.git
cd ghost-core

# Build
./autogen.sh
./configure
make -j$(nproc)

# Run
./src/ghostd
```

## License

Bitcoin Ghost Core is released under the MIT license. See [COPYING](COPYING) for details.

Bitcoin Ghost is based on Bitcoin Core. For the original Bitcoin Core license and contributors, see the Bitcoin Core repository.

## Credits

- Bitcoin Core developers - For the foundational Bitcoin implementation
- Bitcoin Ghost developers - For Ghost enhancements and features


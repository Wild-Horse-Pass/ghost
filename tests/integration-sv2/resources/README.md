# Resources

This folder contains resources/data files that can be used during tests.

## high_diff_chain.tar.gz

Premined signet blockchain data for high difficulty testing (`DifficultyLevel::High`).

The premined blocks raise the network difficulty, making block discovery
significantly harder - useful for testing scenarios where finding a block takes considerable time.

**WARNING**: Take care when deleting or modifing this folder and its contents. Changes will affect users who install
this crate from crates.io, as they will fallback to downloading from GitHub if this file is missing.


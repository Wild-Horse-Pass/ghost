#!/bin/bash

set -e  # Exit on error

tarpaulin() {
  workspace_name=$1
  output_dir="target/tarpaulin-reports/$workspace_name-coverage"
  
  echo "Running tarpaulin for $workspace_name..."
  mkdir -p "$output_dir"
  # Use command-line arguments to ensure correct output location
  cargo +nightly tarpaulin --verbose --all-features --workspace --timeout 120 --out Xml --output-dir "$output_dir"
  
  # Verify the output file was created
  if [ -f "$output_dir/cobertura.xml" ]; then
    echo "✅ Coverage report created at: $output_dir/cobertura.xml"
  else
    echo "❌ Error: cobertura.xml not found at $output_dir/cobertura.xml"
    exit 1
  fi
}

echo "Running coverage analysis for bitcoin_core_sv2 crate..."
echo "================================================="

# bitcoin_core_sv2 Coverage
cd bitcoin-core-sv2 || exit 1
tarpaulin "bitcoin-core-sv2"
cd - > /dev/null || exit 1
echo ""

echo "Running coverage analysis for SV2 Applications..."
echo "================================================="

# stratum-apps Coverage (library crate with all utilities)
echo ""
echo "Running coverage for stratum-apps workspace..."
cd stratum-apps || exit 1
tarpaulin "stratum-apps"
cd - > /dev/null || exit 1

# Pool Apps Coverage (includes pool and jd-server)
echo ""
echo "Running coverage for pool-apps workspace..."
cd pool-apps || exit 1
tarpaulin "pool-apps"
cd - > /dev/null || exit 1

# Miner Apps Coverage (includes jd-client, translator, and test-utils)
echo ""
echo "Running coverage for miner-apps workspace..."
cd miner-apps || exit 1
tarpaulin "miner-apps"
cd - > /dev/null || exit 1

echo ""
echo "✅ Coverage analysis completed for all available workspaces."
echo ""
echo "Reports generated:"
echo "  - stratum-apps/target/tarpaulin-reports/stratum-apps-coverage/"
echo "  - pool-apps/target/tarpaulin-reports/pool-apps-coverage/"
echo "  - miner-apps/target/tarpaulin-reports/miner-apps-coverage/"
echo "  - integration-tests/target/tarpaulin-reports/integration-tests-coverage/"
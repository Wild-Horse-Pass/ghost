# Skipped Functional Tests

This document explains the 15 functional tests that are skipped during normal test runs
and the conditions required to run them.

## Summary

| Test | Skip Reason | Required For |
|------|-------------|--------------|
| feature_bind_port_discover.py | Special network config | Network testing |
| feature_bind_port_externalip.py | Special network config | Network testing |
| feature_coinstatsindex_compatibility.py | No previous releases | Upgrade testing |
| feature_unsupported_utxo_db.py | No previous releases | Upgrade testing |
| interface_ipc.py | IPC/Cap'n Proto not built | Multiprocess |
| interface_usdt_*.py (5 tests) | Linux + BPF/USDT tracing | Performance tracing |
| interface_zmq.py | ZMQ not built | Event notifications |
| mempool_compatibility.py | No previous releases | Upgrade testing |
| tool_bitcoin_chainstate.py | Tool not built | Chainstate inspection |
| wallet_backwards_compatibility.py | No previous releases | Upgrade testing |
| wallet_migration.py | No previous releases | Wallet upgrade |

---

## Network Configuration Tests (2 tests)

### feature_bind_port_discover.py

**Skip Condition:** Requires `--ihave1111and2222` flag and special network setup.

**Purpose:** Tests port discovery when binding to multiple routable IP addresses.

**Requirements:**
- Two routable IP addresses (1.1.1.1 and 2.2.2.2 patterns) assigned to local interfaces
- Run with: `--ihave1111and2222`

**Why Skipped:** Requires special network configuration that isn't available in standard
CI environments. This tests edge cases in network binding that only apply to specific
deployment scenarios.

### feature_bind_port_externalip.py

**Skip Condition:** Requires `--ihave1111` flag and special network setup.

**Purpose:** Tests external IP address configuration.

**Requirements:**
- A routable IP address (1.1.1.1 pattern) assigned to a local interface
- Run with: `--ihave1111`

**Why Skipped:** Same as above - requires special network configuration.

---

## Previous Release Tests (5 tests)

These tests require downloading and running previous Bitcoin Core releases to test
upgrade paths and compatibility.

### feature_coinstatsindex_compatibility.py

**Skip Condition:** `skip_if_no_previous_releases()`

**Purpose:** Tests that coinstatsindex data is compatible across versions.

**Why Skipped:** Requires previous release binaries. Ghost Core is a new fork without
published previous releases yet.

### feature_unsupported_utxo_db.py

**Skip Condition:** `skip_if_no_previous_releases()`

**Purpose:** Tests handling of UTXO databases from unsupported old versions.

**Why Skipped:** Same as above.

### mempool_compatibility.py

**Skip Condition:** `skip_if_no_previous_releases()`

**Purpose:** Tests mempool data compatibility during upgrades.

**Why Skipped:** Same as above.

### wallet_backwards_compatibility.py

**Skip Condition:** `skip_if_no_previous_releases()`

**Purpose:** Tests that wallets created with older versions can be loaded.

**Why Skipped:** Same as above.

### wallet_migration.py

**Skip Condition:** `skip_if_no_previous_releases()`

**Purpose:** Tests wallet database migration from legacy to descriptor wallets.

**Why Skipped:** Same as above.

---

## IPC/Multiprocess Test (1 test)

### interface_ipc.py

**Skip Condition:** `skip_if_no_ipc()` and `skip_if_no_py_capnp()`

**Purpose:** Tests inter-process communication for multiprocess Bitcoin Core.

**Requirements:**
- Build with `-DENABLE_IPC=ON`
- Python Cap'n Proto library (`pip install pycapnp`)

**Why Skipped:** Ghost Core CI builds with `-DENABLE_IPC=OFF` as multiprocess support
is experimental and not needed for Ghost Network functionality.

---

## USDT Tracing Tests (5 tests)

These tests use User-Space Defined Tracing (USDT) probes for performance analysis.

### interface_usdt_coinselection.py
### interface_usdt_mempool.py
### interface_usdt_net.py
### interface_usdt_utxocache.py
### interface_usdt_validation.py

**Skip Conditions:**
- `skip_if_platform_not_linux()` - Linux only
- `skip_if_no_bitcoind_tracepoints()` - Requires tracepoint-enabled build
- `skip_if_no_python_bcc()` - Requires BCC Python bindings
- `skip_if_no_bpf_permissions()` - Requires CAP_BPF or root

**Purpose:** Tests USDT tracepoints for:
- Coin selection performance
- Mempool operations
- Network I/O
- UTXO cache efficiency
- Block validation

**Requirements:**
- Linux operating system
- Build with tracepoints enabled
- BCC toolkit installed (`apt install bpfcc-tools python3-bpfcc`)
- Root or CAP_BPF capability

**Why Skipped:** USDT tracing is a specialized debugging/profiling feature that:
1. Only works on Linux
2. Requires elevated permissions
3. Needs additional build configuration and dependencies
4. Is used for performance analysis, not functional correctness

---

## ZMQ Test (1 test)

### interface_zmq.py

**Skip Condition:** `skip_if_no_py3_zmq()` and `skip_if_no_bitcoind_zmq()`

**Purpose:** Tests ZeroMQ notification interface for real-time events.

**Requirements:**
- Build with ZMQ support (requires libzmq)
- Python ZMQ library (`pip install pyzmq`)

**Why Skipped:** Ghost Core CI doesn't install ZMQ dependencies. ZMQ is optional
and primarily used by external applications that want real-time notifications.

---

## Chainstate Tool Test (1 test)

### tool_bitcoin_chainstate.py

**Skip Condition:** `skip_if_no_bitcoin_chainstate()`

**Purpose:** Tests the `bitcoin-chainstate` utility for chainstate inspection.

**Requirements:**
- Build the `bitcoin-chainstate` binary (experimental tool)

**Why Skipped:** The chainstate inspection tool is experimental and not built
in standard configurations.

---

## Running Skipped Tests

### Previous Release Tests

To run tests requiring previous releases:

```bash
# Download previous releases
./test/get_previous_releases.py -b v27.0 v26.0

# Run tests
./test/functional/test_runner.py wallet_backwards_compatibility.py
```

Note: Ghost Core doesn't have previous releases yet. These tests will become
relevant once Ghost Core has published releases to test upgrade paths.

### USDT Tests (Linux only)

```bash
# Install dependencies
sudo apt install bpfcc-tools python3-bpfcc

# Build with tracepoints
cmake -B build -DWITH_USDT=ON
cmake --build build

# Run with elevated permissions
sudo ./test/functional/test_runner.py interface_usdt_mempool.py
```

### ZMQ Test

```bash
# Install dependencies
sudo apt install libzmq3-dev
pip install pyzmq

# Rebuild with ZMQ
cmake -B build -DWITH_ZMQ=ON
cmake --build build

# Run test
./test/functional/test_runner.py interface_zmq.py
```

### IPC Test

```bash
# Install dependencies
pip install pycapnp

# Rebuild with IPC
cmake -B build -DENABLE_IPC=ON
cmake --build build

# Run test
./test/functional/test_runner.py interface_ipc.py
```

---

## Impact on Ghost Network

**None of these skipped tests affect Ghost Network functionality:**

| Category | Impact |
|----------|--------|
| Network binding | Edge case network configs, not Ghost-specific |
| Previous releases | No previous Ghost releases exist yet |
| USDT tracing | Performance profiling only |
| ZMQ | Optional notification system |
| IPC | Experimental multiprocess feature |
| Chainstate tool | Developer debugging utility |

All Ghost-specific functionality (Ghost Lock, Silent Payments, Wraith Protocol)
is fully tested in the 321 passing tests.

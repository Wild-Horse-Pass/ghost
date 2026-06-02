# Performance Profiling

> **⚠️ For Development Only**: Profiling is intended for development and debugging. Do not enable profiling features in production deployments.

This guide explains how to profile Sv2 applications using [hotpath-rs](https://hotpath.rs/) to identify bottlenecks and optimize performance.

## Overview

Profiling is **zero-cost when disabled** - all instrumentation is gated behind feature flags and has no overhead unless explicitly enabled. For production deployments, always build without profiling features.

## Setup

### Building with Profiling

```bash
# Basic profiling (multi-threaded runtime)
cargo build --release --features hotpath

# Profiling with allocation tracking (single-threaded runtime)
cargo build --release --features hotpath-alloc
```

**Note**: The `hotpath-alloc` feature includes base profiling plus memory allocation tracking. It uses a single-threaded tokio runtime, which may affect performance characteristics.

## Profiling Modes

### Option 1: Static Report (Simple)

Prints a profiling summary when the application shuts down.

```bash
# Example with Pool
cd pool-apps/pool
cargo run --release --features hotpath -- -c config-examples/testnet4/pool-config-hosted-sv2-tp-example.toml
# ... run workload ...
# Press Ctrl+C to stop and view report
```

### Option 2: Live TUI Dashboard (Advanced)

Real-time monitoring with an interactive terminal dashboard.

**1. Install the hotpath CLI (once)**
```bash
cargo install hotpath --features='tui' --locked
```

**2. Start the dashboard**
```bash
hotpath console
```

**3. In another terminal, run your application**
```bash
# Example with Pool
cd pool-apps/pool
cargo run --release --features hotpath -- -c config-examples/testnet4/pool-config-hosted-sv2-tp-example.toml
```

The TUI will show real-time performance metrics as your application runs.

## Interpreting Results

Profiling data includes:
- **Call counts**: How many times each function was called
- **Total time**: Cumulative execution time
- **Average time**: Mean execution time per call
- **Percentage**: Time spent relative to total runtime
- **Percentiles**: p95, p99 timing statistics
- **Memory allocations**: Bytes allocated and allocation counts (with `--features hotpath-alloc`)


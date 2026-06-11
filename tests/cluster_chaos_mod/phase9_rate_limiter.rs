//! Phase 9: Rate Limiter Characterization
//!
//! Measurement-only tests — no strict assertions, just printed reports.
//! Characterizes burst size, per-node vs global budget, recovery time,
//! per-endpoint limits, sustained rate, and overall summary.

use std::time::{Duration, Instant};

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
}

/// Sequential requests until the first 429 — measures burst allowance.
#[tokio::test]
#[ignore]
async fn rate_limiter_01_burst_size() {
    let client = setup();
    let ip = client.config.nodes[0].ip;
    let endpoint = "/health";

    println!("\n=== Rate Limiter: Burst Size ===");
    println!(
        "  Sending sequential requests to {} {} until first 429...",
        ip, endpoint
    );

    let mut count = 0u32;
    loop {
        let r = client.get(ip, endpoint).await;
        count += 1;
        if r.status == Some(429) {
            println!("  First 429 after {} requests", count);
            break;
        }
        if count >= 500 {
            println!(
                "  No 429 after 500 requests — rate limiter may not be active on {}",
                endpoint
            );
            break;
        }
    }
    println!(
        "  Burst allowance: {} requests before rate limit",
        count - 1
    );
    println!("===================\n");
}

/// Hit the rate limit on VM2, then immediately test VM3 — determines per-node vs global.
#[tokio::test]
#[ignore]
async fn rate_limiter_02_per_node_budget() {
    let client = setup();
    let vm2_ip = client.config.node_by_name("VM2").unwrap().ip;
    let vm3_ip = client.config.node_by_name("VM3").unwrap().ip;
    let endpoint = "/health";

    println!("\n=== Rate Limiter: Per-Node Budget ===");

    // Exhaust VM2's budget
    let mut vm2_burst = 0u32;
    loop {
        let r = client.get(vm2_ip, endpoint).await;
        vm2_burst += 1;
        if r.status == Some(429) || vm2_burst >= 500 {
            break;
        }
    }
    println!("  VM2 rate-limited after {} requests", vm2_burst);

    // Immediately test VM3
    let vm3_results = client
        .timed_sequential_requests(vm3_ip, endpoint, 5, Duration::ZERO)
        .await;
    let vm3_successes = vm3_results.iter().filter(|r| r.status == Some(200)).count();
    println!(
        "  VM3 immediately after VM2 limit: {}/5 succeeded",
        vm3_successes
    );

    if vm3_successes >= 4 {
        println!("  Conclusion: Rate limiting is PER-NODE (VM3 unaffected)");
    } else {
        println!("  Conclusion: Rate limiting may be GLOBAL or per-source-IP");
    }
    println!("===================\n");
}

/// Trigger a 429, then poll once per second to find recovery time.
#[tokio::test]
#[ignore]
async fn rate_limiter_03_recovery_time() {
    let client = setup();
    let ip = client.config.nodes[0].ip;
    let endpoint = "/health";

    println!("\n=== Rate Limiter: Recovery Time ===");

    // Exhaust the budget
    let mut sent = 0u32;
    loop {
        let r = client.get(ip, endpoint).await;
        sent += 1;
        if r.status == Some(429) {
            println!("  Rate-limited after {} requests", sent);
            break;
        }
        if sent >= 500 {
            println!("  No 429 after 500 requests — skipping recovery measurement");
            return;
        }
    }

    // Poll 1/s until 200 returns
    let start = Instant::now();
    let mut seconds = 0u32;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        seconds += 1;
        let r = client.get(ip, endpoint).await;
        if r.status == Some(200) {
            println!("  Recovered after {} seconds", seconds);
            break;
        }
        if seconds >= 120 {
            println!("  Did not recover within 120 seconds");
            break;
        }
    }
    let elapsed = start.elapsed();
    println!("  Recovery wall-clock time: {:?}", elapsed);
    println!("===================\n");
}

/// Measure burst size across 5 different endpoints.
#[tokio::test]
#[ignore]
async fn rate_limiter_04_per_endpoint() {
    let client = setup();
    let ip = client.config.nodes[0].ip;
    let endpoints = [
        "/health",
        "/api/v1/node/status",
        "/api/v1/network/peers",
        "/api/v1/mining/status",
        "/metrics",
    ];

    println!("\n=== Rate Limiter: Per-Endpoint Burst ===");

    for endpoint in &endpoints {
        // Wait between endpoints to avoid cross-contamination
        tokio::time::sleep(Duration::from_secs(5)).await;

        let mut count = 0u32;
        loop {
            let r = client.get(ip, endpoint).await;
            count += 1;
            if r.status == Some(429) {
                println!("  {}: burst = {} requests", endpoint, count - 1);
                break;
            }
            if count >= 200 {
                println!("  {}: no 429 after 200 requests", endpoint);
                break;
            }
        }
    }
    println!("===================\n");
}

/// Binary search for the maximum sustainable request rate (zero 429s over 30s).
#[tokio::test]
#[ignore]
async fn rate_limiter_05_sustained_rate() {
    let client = setup();
    let ip = client.config.nodes[0].ip;
    let endpoint = "/health";
    let test_duration = Duration::from_secs(30);

    println!("\n=== Rate Limiter: Sustained Rate (30s window) ===");

    // Binary search between 0.1 and 50 req/s
    let mut lo: f64 = 0.1;
    let mut hi: f64 = 50.0;
    let mut best_rate: f64 = 0.0;

    for iteration in 0..8 {
        let mid = (lo + hi) / 2.0;
        let interval = Duration::from_secs_f64(1.0 / mid);

        // Wait for rate limiter to reset
        tokio::time::sleep(Duration::from_secs(10)).await;

        let start = Instant::now();
        let mut total = 0u32;
        let mut rate_limited = 0u32;

        while start.elapsed() < test_duration {
            let r = client.get(ip, endpoint).await;
            total += 1;
            if r.status == Some(429) {
                rate_limited += 1;
            }
            let target_elapsed = interval * total;
            if let Some(remaining) = target_elapsed.checked_sub(start.elapsed()) {
                tokio::time::sleep(remaining).await;
            }
        }

        println!(
            "  Iteration {}: {:.1} req/s → {}/{} rate-limited",
            iteration, mid, rate_limited, total
        );

        if rate_limited == 0 {
            best_rate = mid;
            lo = mid;
        } else {
            hi = mid;
        }
    }

    println!(
        "  Max sustained rate with zero 429s: {:.2} req/s",
        best_rate
    );
    println!(
        "  Recommended interval: {:.0}ms",
        1000.0 / best_rate.max(0.01)
    );
    println!("===================\n");
}

/// Full summary: 60 requests at 1/s with latency report.
#[tokio::test]
#[ignore]
async fn rate_limiter_06_summary_report() {
    let client = setup();
    let ip = client.config.nodes[0].ip;
    let endpoint = "/health";

    println!("\n=== Rate Limiter: Summary Report (60 req @ 1/s) ===");

    // Wait for any prior rate limiting to clear
    tokio::time::sleep(Duration::from_secs(10)).await;

    let results = client
        .timed_sequential_requests(ip, endpoint, 60, Duration::from_secs(1))
        .await;

    let mut metrics = TestMetrics::new();
    for r in results {
        metrics.record(r);
    }
    metrics.finish();
    metrics.print_report("Rate Limiter Summary: 60 req @ 1/s");

    let rate_429 = metrics.rate_limited_count();
    let success = metrics.success_count();
    println!("  200 OK:          {}", success);
    println!("  429 Rate-Limited: {}", rate_429);
    println!(
        "  Success (excl 429): {:.1}%",
        metrics.success_rate_excluding_429() * 100.0
    );
    println!(
        "  Recommended delay: {}ms between requests",
        if rate_429 > 0 { "1500-2000" } else { "1000" }
    );
    println!("===================\n");
}

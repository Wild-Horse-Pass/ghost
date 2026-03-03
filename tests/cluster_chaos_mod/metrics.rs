//! Response time aggregation and reporting.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::client::RequestResult;

pub struct TestMetrics {
    pub results: Vec<RequestResult>,
    pub start_time: Instant,
    pub end_time: Option<Instant>,
}

impl TestMetrics {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            start_time: Instant::now(),
            end_time: None,
        }
    }

    pub fn record(&mut self, result: RequestResult) {
        self.results.push(result);
    }

    pub fn finish(&mut self) {
        self.end_time = Some(Instant::now());
    }

    pub fn success_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.error.is_none() && r.status.is_some_and(|s| s < 400))
            .count()
    }

    pub fn success_rate(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        self.success_count() as f64 / self.results.len() as f64
    }

    /// Success rate excluding 429 (rate-limited) responses.
    /// Rate limiting is expected behavior, not a service error.
    pub fn success_rate_excluding_429(&self) -> f64 {
        let non_429: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.status != Some(429))
            .collect();
        if non_429.is_empty() {
            // All requests were rate-limited — zero service errors observed
            return 1.0;
        }
        let successes = non_429
            .iter()
            .filter(|r| r.error.is_none() && r.status.is_some_and(|s| s < 400))
            .count();
        successes as f64 / non_429.len() as f64
    }

    /// Count of 429 rate-limited responses.
    pub fn rate_limited_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status == Some(429))
            .count()
    }

    /// Success rate excluding 429 for a specific node IP.
    pub fn success_rate_excluding_429_for_node(&self, ip: &str) -> f64 {
        let node_results: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.node_ip == ip)
            .collect();
        let non_429: Vec<_> = node_results
            .iter()
            .filter(|r| r.status != Some(429))
            .collect();
        if non_429.is_empty() {
            return 1.0;
        }
        let successes = non_429
            .iter()
            .filter(|r| r.error.is_none() && r.status.is_some_and(|s| s < 400))
            .count();
        successes as f64 / non_429.len() as f64
    }

    pub fn avg_latency(&self) -> Duration {
        if self.results.is_empty() {
            return Duration::ZERO;
        }
        let total: Duration = self.results.iter().map(|r| r.latency).sum();
        total / self.results.len() as u32
    }

    fn sorted_latencies(&self) -> Vec<Duration> {
        let mut latencies: Vec<Duration> = self.results.iter().map(|r| r.latency).collect();
        latencies.sort();
        latencies
    }

    fn percentile(&self, p: f64) -> Duration {
        let sorted = self.sorted_latencies();
        if sorted.is_empty() {
            return Duration::ZERO;
        }
        let idx = ((sorted.len() as f64 * p) as usize).min(sorted.len() - 1);
        sorted[idx]
    }

    pub fn p50_latency(&self) -> Duration {
        self.percentile(0.50)
    }

    pub fn p95_latency(&self) -> Duration {
        self.percentile(0.95)
    }

    pub fn p99_latency(&self) -> Duration {
        self.percentile(0.99)
    }

    pub fn requests_per_second(&self) -> f64 {
        let elapsed = self
            .end_time
            .unwrap_or_else(Instant::now)
            .duration_since(self.start_time);
        if elapsed.is_zero() {
            return 0.0;
        }
        self.results.len() as f64 / elapsed.as_secs_f64()
    }

    pub fn errors_by_status(&self) -> HashMap<u16, usize> {
        let mut map = HashMap::new();
        for r in &self.results {
            if let Some(status) = r.status {
                if status >= 400 {
                    *map.entry(status).or_insert(0) += 1;
                }
            }
        }
        map
    }

    pub fn error_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.error.is_some() || r.status.is_none_or(|s| s >= 400))
            .count()
    }

    pub fn print_report(&self, label: &str) {
        println!("\n=== {} ===", label);
        println!("  Total requests:  {}", self.results.len());
        println!("  Successful:      {}", self.success_count());
        println!("  Failed:          {}", self.error_count());
        println!("  Success rate:    {:.1}%", self.success_rate() * 100.0);
        println!("  Avg latency:     {:?}", self.avg_latency());
        println!("  p50 latency:     {:?}", self.p50_latency());
        println!("  p95 latency:     {:?}", self.p95_latency());
        println!("  p99 latency:     {:?}", self.p99_latency());
        println!("  RPS:             {:.1}", self.requests_per_second());

        let errors = self.errors_by_status();
        if !errors.is_empty() {
            println!("  HTTP errors:");
            for (status, count) in &errors {
                println!("    {} → {} occurrences", status, count);
            }
        }

        // Show connection errors
        let conn_errors: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.error.is_some())
            .collect();
        if !conn_errors.is_empty() {
            println!(
                "  Connection errors: {} (first: {})",
                conn_errors.len(),
                conn_errors[0].error.as_deref().unwrap_or("unknown")
            );
        }
        println!("==================\n");
    }
}

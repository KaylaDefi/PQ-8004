use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ReputationError {
    #[error("agent not found: {0}")]
    AgentNotFound(String),
}

/// Immutable snapshot of an agent's reputation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationRecord {
    pub pq_address: String,
    pub successes: u64,
    pub failures: u64,
    pub total_volume: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl ReputationRecord {
    fn new(pq_address: String, now: u64) -> Self {
        Self {
            pq_address,
            successes: 0,
            failures: 0,
            total_volume: 0,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Bayesian mean of a Beta(successes+1, failures+1) distribution,
    /// multiplied by an exponential time-decay factor.
    ///
    /// score = [(s+1)/(s+f+2)] * e^(-λ * days_since_last_seen)
    ///
    /// New agents with no history start at 0.5 * decay(0) = 0.5.
    /// λ controls how fast dormancy hurts: λ=0.01 halves the score
    /// after ~69 days; λ=0.001 is much more lenient.
    pub fn score(&self, now_secs: u64, lambda: f64) -> f64 {
        let raw = (self.successes as f64 + 1.0) / (self.successes as f64 + self.failures as f64 + 2.0);

        let days_inactive = if now_secs > self.last_seen {
            (now_secs - self.last_seen) as f64 / 86_400.0
        } else {
            0.0
        };

        let decay = (-lambda * days_inactive).exp();
        raw * decay
    }

    pub fn total_events(&self) -> u64 {
        self.successes + self.failures
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_events() == 0 {
            return 0.0;
        }
        self.successes as f64 / self.total_events() as f64
    }
}

/// Stores and updates agent reputation over time.
///
/// `lambda` is the exponential decay rate (per day).
/// `now_fn` is injected for testability — in production pass `|| unix_now()`.
pub struct ReputationStore {
    records: HashMap<String, ReputationRecord>,
    lambda: f64,
}

impl ReputationStore {
    /// `lambda` — decay rate per day. 0.01 halves score after ~69 days.
    pub fn new(lambda: f64) -> Self {
        Self {
            records: HashMap::new(),
            lambda,
        }
    }

    /// Restore a store from a previously persisted snapshot (e.g. reputation.json).
    pub fn from_records(records: HashMap<String, ReputationRecord>, lambda: f64) -> Self {
        Self { records, lambda }
    }

    /// Read-only snapshot of all records; use this for persistence on shutdown.
    pub fn all_records(&self) -> &HashMap<String, ReputationRecord> {
        &self.records
    }

    pub fn record_success(&mut self, pq_address: &str, amount: u64, now: u64) {
        let record = self
            .records
            .entry(pq_address.to_string())
            .or_insert_with(|| ReputationRecord::new(pq_address.to_string(), now));
        record.successes += 1;
        record.total_volume += amount;
        record.last_seen = now;
    }

    pub fn record_failure(&mut self, pq_address: &str, now: u64) {
        let record = self
            .records
            .entry(pq_address.to_string())
            .or_insert_with(|| ReputationRecord::new(pq_address.to_string(), now));
        record.failures += 1;
        record.last_seen = now;
    }

    pub fn get_score(&self, pq_address: &str, now: u64) -> Option<f64> {
        self.records.get(pq_address).map(|r| r.score(now, self.lambda))
    }

    pub fn get_record(&self, pq_address: &str) -> Option<&ReputationRecord> {
        self.records.get(pq_address)
    }

    pub fn lambda(&self) -> f64 {
        self.lambda
    }
}

/// Returns the current Unix timestamp in seconds.
/// Use this in production; pass explicit timestamps in tests.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

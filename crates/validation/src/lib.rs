use reputation::ReputationRecord;
use types::{PaymentIntent, PQAgentRecord, PubKeyAlgorithm};

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("algorithm {0:?} is not permitted by policy")]
    AlgorithmNotAllowed(PubKeyAlgorithm),

    #[error("amount {amount} exceeds maximum {max}")]
    AmountTooHigh { amount: u64, max: u64 },

    #[error("amount {amount} is below minimum {min}")]
    AmountTooLow { amount: u64, min: u64 },

    #[error("agent has {events} events, minimum required is {min}")]
    InsufficientHistory { events: u64, min: u64 },

    #[error("reputation score {score:.3} is below minimum {min:.3}")]
    ReputationTooLow { score: f64, min: f64 },
}

/// Policy parameters. All fields have sensible defaults via `Default`.
#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    /// Minimum reputation score to accept a payment (0.0–1.0).
    /// A brand-new agent with no history starts at 0.5 (Bayesian prior),
    /// so setting this at or below 0.5 allows first-time agents through.
    pub min_reputation_score: f64,

    /// Minimum number of recorded events (successes + failures) before
    /// the reputation score is trusted. 0 = allow brand-new agents.
    pub min_volume_events: u64,

    /// Inclusive upper bound on payment amount.
    pub max_amount: u64,

    /// Inclusive lower bound on payment amount.
    pub min_amount: u64,

    /// Which signing algorithms are accepted. Checked against the agent record.
    pub allowed_algorithms: Vec<PubKeyAlgorithm>,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            min_reputation_score: 0.4,
            min_volume_events: 0,
            max_amount: u64::MAX,
            min_amount: 1,
            allowed_algorithms: vec![PubKeyAlgorithm::MlDsa44],
        }
    }
}

pub struct Validator {
    policy: ValidationPolicy,
}

impl Validator {
    pub fn new(policy: ValidationPolicy) -> Self {
        Self { policy }
    }

    /// Run all policy checks in cheapest-first order.
    ///
    /// `reputation` is `None` when the agent has no recorded history yet.
    /// `now` and `lambda` are forwarded to `ReputationRecord::score`.
    pub fn validate(
        &self,
        intent: &PaymentIntent,
        agent: &PQAgentRecord,
        reputation: Option<&ReputationRecord>,
        now: u64,
        lambda: f64,
    ) -> Result<(), ValidationError> {
        // 1. Algorithm
        if !self.policy.allowed_algorithms.contains(&agent.algorithm) {
            return Err(ValidationError::AlgorithmNotAllowed(agent.algorithm));
        }

        // 2. Amount range
        if intent.amount > self.policy.max_amount {
            return Err(ValidationError::AmountTooHigh {
                amount: intent.amount,
                max: self.policy.max_amount,
            });
        }
        if intent.amount < self.policy.min_amount {
            return Err(ValidationError::AmountTooLow {
                amount: intent.amount,
                min: self.policy.min_amount,
            });
        }

        // 3. Event count — skip if min_volume_events == 0
        if self.policy.min_volume_events > 0 {
            let events = reputation.map(|r| r.total_events()).unwrap_or(0);
            if events < self.policy.min_volume_events {
                return Err(ValidationError::InsufficientHistory {
                    events,
                    min: self.policy.min_volume_events,
                });
            }
        }

        // 4. Reputation score
        // An agent with no history uses the Bayesian prior (0.5, no decay).
        let score = match reputation {
            Some(r) => r.score(now, lambda),
            None => 0.5,
        };
        if score < self.policy.min_reputation_score {
            return Err(ValidationError::ReputationTooLow {
                score,
                min: self.policy.min_reputation_score,
            });
        }

        Ok(())
    }

    pub fn policy(&self) -> &ValidationPolicy {
        &self.policy
    }
}

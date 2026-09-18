use reputation::ReputationStore;
use types::{PQAgentRecord, PaymentIntent, PubKeyAlgorithm};
use validation::{ValidationError, ValidationPolicy, Validator};

const LAMBDA: f64 = 0.01;
const NOW: u64 = 1_700_000_000;

fn default_agent() -> PQAgentRecord {
    PQAgentRecord {
        pq_address: "yp1qtest".to_string(),
        public_key: vec![0u8; 1312],
        algorithm: PubKeyAlgorithm::MlDsa44,
    }
}

fn default_intent() -> PaymentIntent {
    PaymentIntent {
        pq_address: "yp1qtest".to_string(),
        recipient: "bob".to_string(),
        amount: 1_000,
        nonce: "nonce-1".to_string(),
        expires_at: u64::MAX,
    }
}

fn default_validator() -> Validator {
    Validator::new(ValidationPolicy::default())
}

// ── happy path ────────────────────────────────────────────────────────────────

#[test]
fn brand_new_agent_passes_with_default_policy() {
    // No reputation record → score defaults to 0.5, default min is 0.4
    let v = default_validator();
    let result = v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA);
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn agent_with_good_history_passes() {
    let mut store = ReputationStore::new(LAMBDA);
    for _ in 0..50 {
        store.record_success("yp1qtest", 1_000, NOW);
    }
    let rep = store.get_record("yp1qtest");
    let v = default_validator();
    assert!(v.validate(&default_intent(), &default_agent(), rep, NOW, LAMBDA).is_ok());
}

// ── algorithm ────────────────────────────────────────────────────────────────

#[test]
fn disallowed_algorithm_rejected() {
    let policy = ValidationPolicy {
        allowed_algorithms: vec![],
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    let err = v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::AlgorithmNotAllowed(_)), "{err}");
}

#[test]
fn allowed_algorithm_passes() {
    let policy = ValidationPolicy {
        allowed_algorithms: vec![PubKeyAlgorithm::MlDsa44],
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    assert!(v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).is_ok());
}

// ── amount range ──────────────────────────────────────────────────────────────

#[test]
fn amount_above_max_rejected() {
    let policy = ValidationPolicy {
        max_amount: 500,
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    let err = v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::AmountTooHigh { amount: 1_000, max: 500 }), "{err}");
}

#[test]
fn amount_below_min_rejected() {
    let policy = ValidationPolicy {
        min_amount: 5_000,
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    let err = v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::AmountTooLow { amount: 1_000, min: 5_000 }), "{err}");
}

#[test]
fn amount_at_exact_max_passes() {
    let policy = ValidationPolicy {
        max_amount: 1_000,
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    assert!(v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).is_ok());
}

#[test]
fn amount_at_exact_min_passes() {
    let policy = ValidationPolicy {
        min_amount: 1_000,
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    assert!(v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).is_ok());
}

// ── min_volume_events ────────────────────────────────────────────────────────

#[test]
fn zero_min_volume_allows_new_agent() {
    let policy = ValidationPolicy {
        min_volume_events: 0,
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    assert!(v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).is_ok());
}

#[test]
fn nonzero_min_volume_rejects_new_agent() {
    let policy = ValidationPolicy {
        min_volume_events: 5,
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    let err = v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::InsufficientHistory { events: 0, min: 5 }), "{err}");
}

#[test]
fn nonzero_min_volume_passes_when_met() {
    let policy = ValidationPolicy {
        min_volume_events: 3,
        min_reputation_score: 0.0, // disable score gate for this test
        ..ValidationPolicy::default()
    };
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("yp1qtest", 100, NOW);
    store.record_success("yp1qtest", 100, NOW);
    store.record_success("yp1qtest", 100, NOW);
    let rep = store.get_record("yp1qtest");
    let v = Validator::new(policy);
    assert!(v.validate(&default_intent(), &default_agent(), rep, NOW, LAMBDA).is_ok());
}

#[test]
fn nonzero_min_volume_rejects_when_just_short() {
    let policy = ValidationPolicy {
        min_volume_events: 3,
        ..ValidationPolicy::default()
    };
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("yp1qtest", 100, NOW);
    store.record_success("yp1qtest", 100, NOW);
    let rep = store.get_record("yp1qtest");
    let v = Validator::new(policy);
    let err = v.validate(&default_intent(), &default_agent(), rep, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::InsufficientHistory { events: 2, min: 3 }), "{err}");
}

// ── reputation score ──────────────────────────────────────────────────────────

#[test]
fn low_reputation_score_rejected() {
    let policy = ValidationPolicy {
        min_reputation_score: 0.8,
        ..ValidationPolicy::default()
    };
    // Many failures → score near 0
    let mut store = ReputationStore::new(LAMBDA);
    for _ in 0..100 {
        store.record_failure("yp1qtest", NOW);
    }
    let rep = store.get_record("yp1qtest");
    let v = Validator::new(policy);
    let err = v.validate(&default_intent(), &default_agent(), rep, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::ReputationTooLow { .. }), "{err}");
}

#[test]
fn high_reputation_score_passes() {
    let policy = ValidationPolicy {
        min_reputation_score: 0.8,
        ..ValidationPolicy::default()
    };
    let mut store = ReputationStore::new(LAMBDA);
    for _ in 0..200 {
        store.record_success("yp1qtest", 1_000, NOW);
    }
    let rep = store.get_record("yp1qtest");
    let v = Validator::new(policy);
    assert!(v.validate(&default_intent(), &default_agent(), rep, NOW, LAMBDA).is_ok());
}

#[test]
fn decayed_score_can_fail_threshold() {
    let policy = ValidationPolicy {
        min_reputation_score: 0.6,
        ..ValidationPolicy::default()
    };
    // Good score right now
    let mut store = ReputationStore::new(LAMBDA);
    for _ in 0..20 {
        store.record_success("yp1qtest", 1_000, NOW);
    }
    let rep = store.get_record("yp1qtest");
    let v = Validator::new(policy);
    assert!(v.validate(&default_intent(), &default_agent(), rep, NOW, LAMBDA).is_ok());

    // Same record, 200 days later — decay pulls score below threshold
    let far_future = NOW + 200 * 86_400;
    let err = v
        .validate(&default_intent(), &default_agent(), rep, far_future, LAMBDA)
        .unwrap_err();
    assert!(matches!(err, ValidationError::ReputationTooLow { .. }), "{err}");
}

#[test]
fn no_reputation_uses_prior_of_half() {
    // min_reputation_score = 0.49 → prior of 0.5 passes
    let policy = ValidationPolicy {
        min_reputation_score: 0.49,
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    assert!(v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).is_ok());

    // min_reputation_score = 0.51 → prior of 0.5 fails
    let strict = ValidationPolicy {
        min_reputation_score: 0.51,
        ..ValidationPolicy::default()
    };
    let v2 = Validator::new(strict);
    let err = v2.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::ReputationTooLow { .. }), "{err}");
}

// ── check ordering ────────────────────────────────────────────────────────────

#[test]
fn algorithm_check_fires_before_amount_check() {
    // Both algorithm and amount are wrong — algorithm error should win
    let policy = ValidationPolicy {
        allowed_algorithms: vec![],
        max_amount: 1, // also wrong
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    let err = v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::AlgorithmNotAllowed(_)), "{err}");
}

#[test]
fn amount_check_fires_before_reputation_check() {
    // Amount too high AND reputation would fail — amount error should win
    let policy = ValidationPolicy {
        max_amount: 1,
        min_reputation_score: 0.99, // would also fail
        ..ValidationPolicy::default()
    };
    let v = Validator::new(policy);
    let err = v.validate(&default_intent(), &default_agent(), None, NOW, LAMBDA).unwrap_err();
    assert!(matches!(err, ValidationError::AmountTooHigh { .. }), "{err}");
}

// ── error messages ────────────────────────────────────────────────────────────

#[test]
fn error_messages_contain_relevant_values() {
    let e1 = ValidationError::AmountTooHigh { amount: 9000, max: 500 };
    assert!(e1.to_string().contains("9000") && e1.to_string().contains("500"));

    let e2 = ValidationError::ReputationTooLow { score: 0.123, min: 0.6 };
    assert!(e2.to_string().contains("0.123") || e2.to_string().contains("0.12"));

    let e3 = ValidationError::InsufficientHistory { events: 2, min: 10 };
    assert!(e3.to_string().contains("2") && e3.to_string().contains("10"));
}

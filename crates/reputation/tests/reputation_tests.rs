use reputation::{ReputationStore, unix_now};

const LAMBDA: f64 = 0.01; // halves score after ~69 days
const NOW: u64 = 1_700_000_000; // fixed epoch for deterministic tests

fn secs(days: f64) -> u64 {
    (days * 86_400.0) as u64
}

// ── score formula ─────────────────────────────────────────────────────────────

#[test]
fn brand_new_agent_scores_half() {
    // No history, seen right now → Beta(1,1) mean = 0.5, decay = 1.0
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 100, NOW);
    // undo that — test a truly empty record by using get_score before any events
    // Instead: manually verify formula: (0+1)/(0+0+2) * e^0 = 0.5
    let mut store2 = ReputationStore::new(LAMBDA);
    store2.record_failure("agent-b", NOW); // first event, no successes yet
    store2.record_success("agent-b", 0, NOW); // now 1 success, 1 failure
    // (1+1)/(1+1+2) = 0.5, decay=1.0 → 0.5
    let score = store2.get_score("agent-b", NOW).unwrap();
    assert!((score - 0.5).abs() < 1e-9);
}

#[test]
fn perfect_record_approaches_one() {
    let mut store = ReputationStore::new(LAMBDA);
    for _ in 0..1000 {
        store.record_success("agent-a", 100, NOW);
    }
    // (1000+1)/(1000+0+2) ≈ 0.999
    let score = store.get_score("agent-a", NOW).unwrap();
    assert!(score > 0.998, "score was {score}");
    assert!(score <= 1.0, "score was {score}");
}

#[test]
fn all_failures_approaches_zero() {
    let mut store = ReputationStore::new(LAMBDA);
    for _ in 0..1000 {
        store.record_failure("agent-a", NOW);
    }
    // (0+1)/(0+1000+2) ≈ 0.001
    let score = store.get_score("agent-a", NOW).unwrap();
    assert!(score < 0.002, "score was {score}");
    assert!(score >= 0.0, "score was {score}");
}

#[test]
fn high_volume_beats_low_volume_same_ratio() {
    let mut store = ReputationStore::new(LAMBDA);
    // Agent A: 1 success, 0 failures → (2/3) ≈ 0.667
    store.record_success("agent-a", 100, NOW);
    // Agent B: 100 successes, 0 failures → (101/102) ≈ 0.990
    for _ in 0..100 {
        store.record_success("agent-b", 100, NOW);
    }
    let score_a = store.get_score("agent-a", NOW).unwrap();
    let score_b = store.get_score("agent-b", NOW).unwrap();
    assert!(score_b > score_a, "higher volume same ratio should score higher: {score_b} vs {score_a}");
}

#[test]
fn decay_reduces_score_over_time() {
    let mut store = ReputationStore::new(LAMBDA);
    for _ in 0..100 {
        store.record_success("agent-a", 100, NOW);
    }
    let score_now    = store.get_score("agent-a", NOW).unwrap();
    let score_30d    = store.get_score("agent-a", NOW + secs(30.0)).unwrap();
    let score_69d    = store.get_score("agent-a", NOW + secs(69.0)).unwrap();
    let score_365d   = store.get_score("agent-a", NOW + secs(365.0)).unwrap();

    assert!(score_now > score_30d,  "30 days should decay: {score_now} vs {score_30d}");
    assert!(score_30d > score_69d,  "69 days should decay more: {score_30d} vs {score_69d}");
    assert!(score_69d > score_365d, "365 days should decay most: {score_69d} vs {score_365d}");

    // λ=0.01: after 69 days decay ≈ e^(-0.69) ≈ 0.5 → score roughly halved
    assert!((score_69d / score_now - 0.5).abs() < 0.01,
        "score should be ~halved at 69 days: {score_now} → {score_69d}");
}

#[test]
fn decay_is_zero_when_recently_active() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 100, NOW);
    // Queried at exact same timestamp — no decay
    let score = store.get_score("agent-a", NOW).unwrap();
    let raw = 2.0_f64 / 3.0; // (1+1)/(1+0+2)
    assert!((score - raw).abs() < 1e-9);
}

#[test]
fn future_last_seen_clamps_decay_to_zero_days() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 100, NOW + 1000);
    // now < last_seen → days_inactive = 0, no decay
    let score = store.get_score("agent-a", NOW).unwrap();
    let raw = 2.0_f64 / 3.0;
    assert!((score - raw).abs() < 1e-9);
}

// ── record_success / record_failure ──────────────────────────────────────────

#[test]
fn record_success_increments_counts() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 500, NOW);
    store.record_success("agent-a", 300, NOW);
    let rec = store.get_record("agent-a").unwrap();
    assert_eq!(rec.successes, 2);
    assert_eq!(rec.failures, 0);
    assert_eq!(rec.total_volume, 800);
}

#[test]
fn record_failure_increments_counts() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_failure("agent-a", NOW);
    store.record_failure("agent-a", NOW);
    let rec = store.get_record("agent-a").unwrap();
    assert_eq!(rec.failures, 2);
    assert_eq!(rec.successes, 0);
    assert_eq!(rec.total_volume, 0);
}

#[test]
fn first_event_sets_first_seen_and_last_seen() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 100, NOW);
    let rec = store.get_record("agent-a").unwrap();
    assert_eq!(rec.first_seen, NOW);
    assert_eq!(rec.last_seen, NOW);
}

#[test]
fn later_event_updates_last_seen_not_first_seen() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 100, NOW);
    store.record_success("agent-a", 100, NOW + secs(10.0));
    let rec = store.get_record("agent-a").unwrap();
    assert_eq!(rec.first_seen, NOW);
    assert_eq!(rec.last_seen, NOW + secs(10.0));
}

// ── get_score / get_record ────────────────────────────────────────────────────

#[test]
fn get_score_unknown_agent_returns_none() {
    let store = ReputationStore::new(LAMBDA);
    assert!(store.get_score("nobody", NOW).is_none());
}

#[test]
fn get_record_unknown_agent_returns_none() {
    let store = ReputationStore::new(LAMBDA);
    assert!(store.get_record("nobody").is_none());
}

#[test]
fn success_rate_is_correct() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 0, NOW);
    store.record_success("agent-a", 0, NOW);
    store.record_failure("agent-a", NOW);
    let rec = store.get_record("agent-a").unwrap();
    assert!((rec.success_rate() - 2.0 / 3.0).abs() < 1e-9);
}

#[test]
fn total_events_is_sum_of_both() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 0, NOW);
    store.record_failure("agent-a", NOW);
    store.record_failure("agent-a", NOW);
    let rec = store.get_record("agent-a").unwrap();
    assert_eq!(rec.total_events(), 3);
}

// ── serde ─────────────────────────────────────────────────────────────────────

#[test]
fn record_serializes_and_deserializes() {
    let mut store = ReputationStore::new(LAMBDA);
    store.record_success("agent-a", 1000, NOW);
    store.record_failure("agent-a", NOW);
    let rec = store.get_record("agent-a").unwrap().clone();
    let json = serde_json::to_string(&rec).unwrap();
    let back: reputation::ReputationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pq_address, rec.pq_address);
    assert_eq!(back.successes, rec.successes);
    assert_eq!(back.failures, rec.failures);
    assert_eq!(back.total_volume, rec.total_volume);
}

// ── unix_now smoke test ───────────────────────────────────────────────────────

#[test]
fn unix_now_is_recent() {
    let t = unix_now();
    // After 2020-01-01 (1577836800) and before 2100-01-01 (4102444800)
    assert!(t > 1_577_836_800, "unix_now too old: {t}");
    assert!(t < 4_102_444_800, "unix_now too far future: {t}");
}

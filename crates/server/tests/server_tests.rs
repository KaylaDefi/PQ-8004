use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    middleware,
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use http_body_util::BodyExt;
use tower::ServiceExt; // for `.oneshot()`

use agent::PQAgent;
use registry::PQRegistry;
use reputation::ReputationStore;
use server::{ServerState, x402_pq_layer};
use types::PaymentIntent;
use validation::{ValidationPolicy, Validator};

const AMOUNT: u64 = 1_000;
const RECIPIENT: &str = "test-recipient";

async fn build_app() -> (Router, Arc<PQAgent>) {
    let (app, agent, _, _) = build_app_with_rep().await;
    (app, agent)
}

async fn build_app_with_rep() -> (Router, Arc<PQAgent>, Arc<Mutex<ReputationStore>>, Arc<ServerState>) {
    let registry = Arc::new(RwLock::new(PQRegistry::new()));
    let agent = Arc::new(PQAgent::new().unwrap());

    registry
        .write()
        .await
        .register(agent.agent_record())
        .unwrap();

    let reputation = Arc::new(Mutex::new(ReputationStore::new(0.01)));
    let validator = Validator::new(ValidationPolicy::default());
    let state = Arc::new(ServerState::new(
        registry,
        reputation.clone(),
        validator,
        AMOUNT,
        RECIPIENT,
    ));

    let app = Router::new()
        .route("/resource", get(|| async { "ok" }))
        .route_layer(middleware::from_fn_with_state(state.clone(), x402_pq_layer));

    (app, agent, reputation, state)
}

fn get_request(headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder().uri("/resource").method("GET");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder.body(Body::empty()).unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ── 402 challenge ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn no_header_returns_402() {
    let (app, _) = build_app().await;
    let resp = app.oneshot(get_request(&[])).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn challenge_body_is_valid_json() {
    let (app, _) = build_app().await;
    let resp = app.oneshot(get_request(&[])).await.unwrap();
    let text = body_text(resp).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(json.get("nonce").is_some());
    assert!(json.get("amount").is_some());
    assert!(json.get("scheme").is_some());
    assert_eq!(json["scheme"], "ml-dsa-44");
    assert_eq!(json["amount"], AMOUNT);
}

// ── valid payment ─────────────────────────────────────────────────────────────

async fn make_payment_header(agent: &PQAgent, nonce: &str) -> String {
    let intent = PaymentIntent {
        pq_address: agent.pq_address.clone(),
        recipient: RECIPIENT.to_string(),
        amount: AMOUNT,
        nonce: nonce.to_string(),
        expires_at: u64::MAX,
    };
    let signed = agent.sign_payment(intent).unwrap();
    B64.encode(serde_json::to_vec(&signed).unwrap())
}

#[tokio::test]
async fn valid_payment_returns_200() {
    let (app, agent) = build_app().await;
    let header = make_payment_header(&agent, "nonce-valid-1").await;
    let resp = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn valid_payment_response_body_is_correct() {
    let (app, agent) = build_app().await;
    let header = make_payment_header(&agent, "nonce-valid-2").await;
    let resp = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(body_text(resp).await, "ok");
}

// ── nonce replay ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn replay_same_nonce_is_rejected() {
    let (app, agent) = build_app().await;
    let header = make_payment_header(&agent, "nonce-replay").await;

    // First request succeeds
    let r1 = app
        .clone()
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    // Second request with same nonce is rejected
    let r2 = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::PAYMENT_REQUIRED);
}

// ── rejection cases ───────────────────────────────────────────────────────────

#[tokio::test]
async fn malformed_header_not_base64_returns_402() {
    let (app, _) = build_app().await;
    let resp = app
        .oneshot(get_request(&[("x-payment", "!!!not-base64!!!")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn malformed_header_not_json_returns_402() {
    let (app, _) = build_app().await;
    let bad = B64.encode(b"this is not json");
    let resp = app
        .oneshot(get_request(&[("x-payment", &bad)]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn unknown_agent_returns_402() {
    let (app, _) = build_app().await;

    // Agent that was never registered
    let stranger = PQAgent::new().unwrap();
    let header = make_payment_header(&stranger, "nonce-stranger").await;

    let resp = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn wrong_amount_returns_402() {
    let (app, agent) = build_app().await;
    let intent = PaymentIntent {
        pq_address: agent.pq_address.clone(),
        recipient: RECIPIENT.to_string(),
        amount: AMOUNT + 1, // wrong
        nonce: "nonce-amount".to_string(),
        expires_at: u64::MAX,
    };
    let signed = agent.sign_payment(intent).unwrap();
    let header = B64.encode(serde_json::to_vec(&signed).unwrap());

    let resp = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn wrong_recipient_returns_402() {
    let (app, agent) = build_app().await;
    let intent = PaymentIntent {
        pq_address: agent.pq_address.clone(),
        recipient: "wrong-recipient".to_string(),
        amount: AMOUNT,
        nonce: "nonce-recipient".to_string(),
        expires_at: u64::MAX,
    };
    let signed = agent.sign_payment(intent).unwrap();
    let header = B64.encode(serde_json::to_vec(&signed).unwrap());

    let resp = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn tampered_signature_returns_402() {
    let (app, agent) = build_app().await;
    let intent = PaymentIntent {
        pq_address: agent.pq_address.clone(),
        recipient: RECIPIENT.to_string(),
        amount: AMOUNT,
        nonce: "nonce-tamper".to_string(),
        expires_at: u64::MAX,
    };
    let mut signed = agent.sign_payment(intent).unwrap();
    // Flip a byte in the signature
    signed.signature[100] ^= 0xFF;
    let header = B64.encode(serde_json::to_vec(&signed).unwrap());

    let resp = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

// ── expiry ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn expired_payment_returns_402() {
    let (app, agent) = build_app().await;
    // expires_at of 1 is well in the past
    let intent = PaymentIntent {
        pq_address: agent.pq_address.clone(),
        recipient: RECIPIENT.to_string(),
        amount: AMOUNT,
        nonce: "nonce-expired".to_string(),
        expires_at: 1,
    };
    let signed = agent.sign_payment(intent).unwrap();
    let header = B64.encode(serde_json::to_vec(&signed).unwrap());

    let resp = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

// ── nonce replay reputation integrity ────────────────────────────────────────

#[tokio::test]
async fn nonce_replay_does_not_update_reputation() {
    let (app, agent, reputation, _) = build_app_with_rep().await;
    let header = make_payment_header(&agent, "nonce-rep-check").await;

    // First request: succeeds and records one success
    let r1 = app
        .clone()
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    let successes_after_first = reputation
        .lock()
        .await
        .get_record(&agent.pq_address)
        .map(|r| r.successes)
        .unwrap_or(0);

    // Second request: nonce replay — must be rejected and must NOT bump reputation
    let r2 = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::PAYMENT_REQUIRED);

    let successes_after_replay = reputation
        .lock()
        .await
        .get_record(&agent.pq_address)
        .map(|r| r.successes)
        .unwrap_or(0);

    assert_eq!(
        successes_after_first, successes_after_replay,
        "nonce replay must not increment reputation (was {successes_after_first}, now {successes_after_replay})"
    );
}

// ── nonce store pruning ───────────────────────────────────────────────────────

#[tokio::test]
async fn expired_nonces_are_pruned_on_next_payment() {
    let (app, agent, _, state) = build_app_with_rep().await;

    // Manually populate the store with stale entries (expires_at = 1, year 1970).
    // These simulate nonces from payments that have long since expired.
    {
        let mut nonces = state.nonce_store.lock().await;
        nonces.insert("stale-nonce-1".to_string(), 1);
        nonces.insert("stale-nonce-2".to_string(), 1);
        nonces.insert("stale-nonce-3".to_string(), 1);
        assert_eq!(nonces.len(), 3, "pre-condition: 3 stale entries");
    }

    // A new valid payment triggers pruning before inserting its own nonce.
    let header = make_payment_header(&agent, "nonce-after-prune").await;
    let resp = app
        .oneshot(get_request(&[("x-payment", &header)]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The three stale entries must be gone; only the new nonce remains.
    let count = state.nonce_store.lock().await.len();
    assert_eq!(count, 1, "expected 1 nonce after pruning stale entries, got {count}");
}

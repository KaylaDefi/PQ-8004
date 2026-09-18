pub mod dashboard;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ml_dsa::{MlDsa44, Signature, VerifyingKey, signature::Verifier};
use uuid::Uuid;

use registry::PQRegistry;
use reputation::ReputationStore;
use types::{PaymentChallenge, SignedPayment, X402PqError, canonical_bytes};
use validation::Validator;

pub struct ServerState {
    pub registry: Arc<RwLock<PQRegistry>>,
    pub reputation: Arc<Mutex<ReputationStore>>,
    pub validator: Validator,
    pub nonce_store: Mutex<HashMap<String, u64>>,
    pub payment_amount: u64,
    pub recipient: String,
}

impl ServerState {
    pub fn new(
        registry: Arc<RwLock<PQRegistry>>,
        reputation: Arc<Mutex<ReputationStore>>,
        validator: Validator,
        amount: u64,
        recipient: impl Into<String>,
    ) -> Self {
        Self {
            registry,
            reputation,
            validator,
            nonce_store: Mutex::new(HashMap::new()),
            payment_amount: amount,
            recipient: recipient.into(),
        }
    }
}

pub async fn x402_pq_layer(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    match headers.get("x-payment") {
        None => issue_challenge(&state).await.into_response(),
        Some(value) => match verify_payment(&state, value.as_bytes()).await {
            Ok(()) => next.run(request).await,
            Err(e) => (StatusCode::PAYMENT_REQUIRED, e.to_string()).into_response(),
        },
    }
}

async fn issue_challenge(state: &ServerState) -> impl IntoResponse {
    let challenge = PaymentChallenge {
        nonce: Uuid::new_v4().to_string(),
        amount: state.payment_amount,
        recipient: state.recipient.clone(),
        scheme: "ml-dsa-44".to_string(),
    };
    (StatusCode::PAYMENT_REQUIRED, Json(challenge))
}

async fn verify_payment(state: &ServerState, raw: &[u8]) -> Result<(), X402PqError> {
    let decoded = B64
        .decode(raw)
        .map_err(|e| X402PqError::MalformedHeader(e.to_string()))?;

    let signed: SignedPayment = serde_json::from_slice(&decoded)
        .map_err(|e| X402PqError::MalformedHeader(e.to_string()))?;

    if signed.intent.recipient != state.recipient {
        return Err(X402PqError::MalformedHeader("recipient mismatch".into()));
    }
    if signed.intent.amount != state.payment_amount {
        return Err(X402PqError::MalformedHeader("amount mismatch".into()));
    }

    // Reject expired payments before any expensive work.
    let now = reputation::unix_now();
    if now > signed.intent.expires_at {
        return Err(X402PqError::Expired);
    }

    // Resolve agent from registry
    let registry = state.registry.read().await;
    let agent_record = registry
        .resolve(&signed.intent.pq_address)
        .ok_or_else(|| X402PqError::UnknownAgent(signed.intent.pq_address.clone()))?;

    // Verify ML-DSA signature against registry-authoritative key
    let vk_bytes = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(agent_record.public_key.as_slice())
        .map_err(|_| X402PqError::InvalidSignature)?;
    let vk = VerifyingKey::<MlDsa44>::decode(&vk_bytes);

    let sig_bytes = ml_dsa::EncodedSignature::<MlDsa44>::try_from(signed.signature.as_slice())
        .map_err(|_| X402PqError::InvalidSignature)?;
    let sig = Signature::<MlDsa44>::decode(&sig_bytes)
        .ok_or(X402PqError::InvalidSignature)?;

    let msg = canonical_bytes(&signed.intent);
    vk.verify(&msg, &sig).map_err(|_| X402PqError::InvalidSignature)?;

    // Consume nonce before updating reputation — a replayed nonce must not
    // count as a payment event and inflate the agent's reputation score.
    // Prune entries whose expiry has already passed; since the expiry check
    // above rejected any payment with expires_at < now, evicted nonces can
    // never be replayed, so this is safe to do unconditionally.
    {
        let mut nonces = state.nonce_store.lock().await;
        nonces.retain(|_, exp| *exp >= now);
        if nonces.insert(signed.intent.nonce.clone(), signed.intent.expires_at).is_some() {
            return Err(X402PqError::NonceReused(signed.intent.nonce));
        }
    }

    // Run validation policy against current reputation
    let lambda = state.reputation.lock().await.lambda();
    let rep_record = state
        .reputation
        .lock()
        .await
        .get_record(&signed.intent.pq_address)
        .cloned();

    let validation_result = state.validator.validate(
        &signed.intent,
        agent_record,
        rep_record.as_ref(),
        now,
        lambda,
    );

    // Record outcome — genuine validation pass/fail updates the agent's history
    match &validation_result {
        Ok(()) => {
            state.reputation.lock().await
                .record_success(&signed.intent.pq_address, signed.intent.amount, now);
        }
        Err(_) => {
            state.reputation.lock().await
                .record_failure(&signed.intent.pq_address, now);
        }
    }

    validation_result.map_err(|e| X402PqError::MalformedHeader(e.to_string()))
}

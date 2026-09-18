use types::{
    PaymentChallenge, PaymentIntent, PQAgentRecord, PubKeyAlgorithm, SignedPayment, X402PqError,
    canonical_bytes,
};

fn sample_intent() -> PaymentIntent {
    PaymentIntent {
        pq_address: "yp1qtest".to_string(),
        recipient: "alice".to_string(),
        amount: 500,
        nonce: "abc-123".to_string(),
        expires_at: 9999999999,
    }
}

// ── canonical_bytes ───────────────────────────────────────────────────────────

#[test]
fn canonical_bytes_is_deterministic() {
    let intent = sample_intent();
    assert_eq!(canonical_bytes(&intent), canonical_bytes(&intent));
}

#[test]
fn canonical_bytes_changes_with_each_field() {
    let base = canonical_bytes(&sample_intent());

    let changed_address = canonical_bytes(&PaymentIntent {
        pq_address: "yp1qother".to_string(),
        ..sample_intent()
    });
    assert_ne!(base, changed_address, "pq_address change not reflected");

    let changed_recipient = canonical_bytes(&PaymentIntent {
        recipient: "bob".to_string(),
        ..sample_intent()
    });
    assert_ne!(base, changed_recipient, "recipient change not reflected");

    let changed_amount = canonical_bytes(&PaymentIntent {
        amount: 501,
        ..sample_intent()
    });
    assert_ne!(base, changed_amount, "amount change not reflected");

    let changed_nonce = canonical_bytes(&PaymentIntent {
        nonce: "xyz-999".to_string(),
        ..sample_intent()
    });
    assert_ne!(base, changed_nonce, "nonce change not reflected");

    let changed_expiry = canonical_bytes(&PaymentIntent {
        expires_at: 1,
        ..sample_intent()
    });
    assert_ne!(base, changed_expiry, "expires_at change not reflected");
}

#[test]
fn canonical_bytes_non_empty() {
    assert!(!canonical_bytes(&sample_intent()).is_empty());
}

// ── serde round-trips ─────────────────────────────────────────────────────────

#[test]
fn payment_intent_serde_round_trip() {
    let intent = sample_intent();
    let json = serde_json::to_string(&intent).unwrap();
    let back: PaymentIntent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pq_address, intent.pq_address);
    assert_eq!(back.recipient, intent.recipient);
    assert_eq!(back.amount, intent.amount);
    assert_eq!(back.nonce, intent.nonce);
    assert_eq!(back.expires_at, intent.expires_at);
}

#[test]
fn signed_payment_serde_round_trip() {
    let signed = SignedPayment {
        intent: sample_intent(),
        algorithm: PubKeyAlgorithm::MlDsa44,
        public_key: vec![1, 2, 3],
        signature: vec![4, 5, 6],
    };
    let json = serde_json::to_string(&signed).unwrap();
    let back: SignedPayment = serde_json::from_str(&json).unwrap();
    assert_eq!(back.public_key, signed.public_key);
    assert_eq!(back.signature, signed.signature);
    assert_eq!(back.algorithm, signed.algorithm);
}

#[test]
fn payment_challenge_serde_round_trip() {
    let challenge = PaymentChallenge {
        nonce: "n1".to_string(),
        amount: 100,
        recipient: "rec".to_string(),
        scheme: "ml-dsa-44".to_string(),
    };
    let json = serde_json::to_string(&challenge).unwrap();
    let back: PaymentChallenge = serde_json::from_str(&json).unwrap();
    assert_eq!(back.nonce, challenge.nonce);
    assert_eq!(back.scheme, challenge.scheme);
}

#[test]
fn pq_agent_record_serde_round_trip() {
    let record = PQAgentRecord {
        pq_address: "yp1q...".to_string(),
        public_key: vec![0xab; 32],
        algorithm: PubKeyAlgorithm::MlDsa44,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: PQAgentRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pq_address, record.pq_address);
    assert_eq!(back.public_key, record.public_key);
}

// ── PubKeyAlgorithm ───────────────────────────────────────────────────────────

#[test]
fn pub_key_algorithm_scheme_name() {
    assert_eq!(PubKeyAlgorithm::MlDsa44.scheme_name(), "ml-dsa-44");
}

#[test]
fn pub_key_algorithm_serde_kebab_case() {
    let json = serde_json::to_string(&PubKeyAlgorithm::MlDsa44).unwrap();
    assert_eq!(json, "\"ml-dsa-44\"");
    let back: PubKeyAlgorithm = serde_json::from_str(&json).unwrap();
    assert_eq!(back, PubKeyAlgorithm::MlDsa44);
}

// ── X402PqError ───────────────────────────────────────────────────────────────

#[test]
fn error_display_messages() {
    assert!(X402PqError::UnknownAgent("x".into()).to_string().contains("x"));
    assert!(X402PqError::InvalidSignature.to_string().contains("invalid"));
    assert!(X402PqError::AddressMismatch.to_string().contains("address"));
    assert!(X402PqError::NonceReused("n".into()).to_string().contains("n"));
    assert!(X402PqError::Expired.to_string().contains("expired"));
    assert!(X402PqError::MalformedHeader("bad".into()).to_string().contains("bad"));
}

#[test]
fn error_from_serde_json() {
    let err: Result<PaymentIntent, _> = serde_json::from_str("not json");
    let x402_err: X402PqError = err.unwrap_err().into();
    assert!(matches!(x402_err, X402PqError::Serialization(_)));
}

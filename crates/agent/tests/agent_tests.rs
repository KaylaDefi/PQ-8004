use ml_dsa::{MlDsa44, Signature, VerifyingKey, signature::Verifier};
use agent::PQAgent;
use types::{PaymentIntent, PubKeyAlgorithm, canonical_bytes};

fn sample_intent(agent: &PQAgent) -> PaymentIntent {
    PaymentIntent {
        pq_address: agent.pq_address.clone(),
        recipient: "bob".to_string(),
        amount: 1_000,
        nonce: "unique-nonce-1".to_string(),
        expires_at: 9999999999,
    }
}

// ── PQAgent::new ──────────────────────────────────────────────────────────────

#[test]
fn new_produces_valid_mainnet_address() {
    let agent = PQAgent::new().unwrap();
    // Mainnet addresses start with "yp"
    assert!(
        agent.pq_address.starts_with("yp"),
        "expected mainnet address, got: {}",
        agent.pq_address
    );
}

#[test]
fn new_address_is_64_chars() {
    let agent = PQAgent::new().unwrap();
    assert_eq!(agent.pq_address.len(), 64);
}

#[test]
fn new_public_key_is_1312_bytes() {
    let agent = PQAgent::new().unwrap();
    assert_eq!(agent.public_key.len(), 1312, "ML-DSA-44 verifying key must be 1312 bytes");
}

#[test]
fn two_agents_have_different_keys() {
    let a1 = PQAgent::new().unwrap();
    let a2 = PQAgent::new().unwrap();
    assert_ne!(a1.public_key, a2.public_key);
    assert_ne!(a1.pq_address, a2.pq_address);
}

// ── agent_record ──────────────────────────────────────────────────────────────

#[test]
fn agent_record_matches_agent() {
    let agent = PQAgent::new().unwrap();
    let record = agent.agent_record();
    assert_eq!(record.pq_address, agent.pq_address);
    assert_eq!(record.public_key, agent.public_key);
    assert_eq!(record.algorithm, PubKeyAlgorithm::MlDsa44);
}

// ── sign_payment ──────────────────────────────────────────────────────────────

#[test]
fn sign_payment_returns_signed_payment() {
    let agent = PQAgent::new().unwrap();
    let intent = sample_intent(&agent);
    let signed = agent.sign_payment(intent.clone()).unwrap();

    assert_eq!(signed.intent.nonce, intent.nonce);
    assert_eq!(signed.intent.amount, intent.amount);
    assert_eq!(signed.algorithm, PubKeyAlgorithm::MlDsa44);
    assert!(!signed.signature.is_empty());
    assert!(!signed.public_key.is_empty());
}

#[test]
fn signature_is_2420_bytes() {
    let agent = PQAgent::new().unwrap();
    let signed = agent.sign_payment(sample_intent(&agent)).unwrap();
    assert_eq!(signed.signature.len(), 2420, "ML-DSA-44 signature must be 2420 bytes");
}

#[test]
fn signature_verifies_with_own_public_key() {
    let agent = PQAgent::new().unwrap();
    let intent = sample_intent(&agent);
    let signed = agent.sign_payment(intent.clone()).unwrap();

    let vk_enc = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(signed.public_key.as_slice())
        .expect("valid vk bytes");
    let vk = VerifyingKey::<MlDsa44>::decode(&vk_enc);

    let sig_enc = ml_dsa::EncodedSignature::<MlDsa44>::try_from(signed.signature.as_slice())
        .expect("valid sig bytes");
    let sig = Signature::<MlDsa44>::decode(&sig_enc).expect("valid signature");

    let msg = canonical_bytes(&intent);
    assert!(vk.verify(&msg, &sig).is_ok(), "signature should verify");
}

#[test]
fn signature_fails_on_tampered_message() {
    let agent = PQAgent::new().unwrap();
    let intent = sample_intent(&agent);
    let signed = agent.sign_payment(intent).unwrap();

    let vk_enc = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(signed.public_key.as_slice())
        .unwrap();
    let vk = VerifyingKey::<MlDsa44>::decode(&vk_enc);

    let sig_enc = ml_dsa::EncodedSignature::<MlDsa44>::try_from(signed.signature.as_slice())
        .unwrap();
    let sig = Signature::<MlDsa44>::decode(&sig_enc).unwrap();

    // Different intent — canonical bytes differ
    let tampered = PaymentIntent {
        amount: 9_999_999,
        ..sample_intent(&agent)
    };
    let bad_msg = canonical_bytes(&tampered);
    assert!(vk.verify(&bad_msg, &sig).is_err(), "tampered message should not verify");
}

#[test]
fn signature_fails_with_different_agents_key() {
    let agent1 = PQAgent::new().unwrap();
    let agent2 = PQAgent::new().unwrap();

    let intent = sample_intent(&agent1);
    let signed = agent1.sign_payment(intent.clone()).unwrap();

    // Verify with agent2's key — should fail
    let vk_enc = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(agent2.public_key.as_slice())
        .unwrap();
    let vk = VerifyingKey::<MlDsa44>::decode(&vk_enc);

    let sig_enc = ml_dsa::EncodedSignature::<MlDsa44>::try_from(signed.signature.as_slice())
        .unwrap();
    let sig = Signature::<MlDsa44>::decode(&sig_enc).unwrap();

    let msg = canonical_bytes(&intent);
    assert!(vk.verify(&msg, &sig).is_err(), "wrong key should not verify");
}

#[test]
fn two_signs_of_same_intent_produce_same_signature() {
    // sign_payment uses sign_deterministic (zero rnd), so it's reproducible
    let agent = PQAgent::new().unwrap();
    let intent = sample_intent(&agent);
    let s1 = agent.sign_payment(intent.clone()).unwrap();
    let s2 = agent.sign_payment(intent).unwrap();
    assert_eq!(s1.signature, s2.signature);
}

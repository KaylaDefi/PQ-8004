use ml_dsa::{KeyGen, MlDsa44};
use pq_address::{AddressParams, Network, PubKeyType, Version, encode_address};
use registry::PQRegistry;
use types::{PQAgentRecord, PubKeyAlgorithm};

fn make_record() -> PQAgentRecord {
    let keypair = MlDsa44::key_gen_internal(&Default::default());
    let vk_bytes = <_ as AsRef<[u8]>>::as_ref(&keypair.verifying_key().encode()).to_vec();

    let address = encode_address(&AddressParams {
        network: Network::Mainnet,
        version: Version::V1,
        pubkey_type: PubKeyType::MlDsa44,
        pubkey_bytes: &vk_bytes,
    })
    .unwrap();

    PQAgentRecord {
        pq_address: address,
        public_key: vk_bytes,
        algorithm: PubKeyAlgorithm::MlDsa44,
    }
}

// ── register ──────────────────────────────────────────────────────────────────

#[test]
fn register_valid_record_succeeds() {
    let mut registry = PQRegistry::new();
    let record = make_record();
    assert!(registry.register(record).is_ok());
}

#[test]
fn register_wrong_pubkey_for_address_fails() {
    let mut registry = PQRegistry::new();
    let mut record = make_record();
    // Corrupt the public key — hash will no longer match the address
    record.public_key[0] ^= 0xFF;
    let result = registry.register(record);
    assert!(result.is_err());
}

#[test]
fn register_bad_address_string_fails() {
    let mut registry = PQRegistry::new();
    let record = PQAgentRecord {
        pq_address: "not-a-valid-bech32m-address".to_string(),
        public_key: vec![0u8; 1312],
        algorithm: PubKeyAlgorithm::MlDsa44,
    };
    assert!(registry.register(record).is_err());
}

#[test]
fn register_two_distinct_agents() {
    let mut registry = PQRegistry::new();
    let r1 = make_record();
    // Generate a second keypair with a different seed
    let kp2 = MlDsa44::key_gen_internal(&ml_dsa::B32::from([1u8; 32]));
    let vk2 = <_ as AsRef<[u8]>>::as_ref(&kp2.verifying_key().encode()).to_vec();
    let addr2 = encode_address(&AddressParams {
        network: Network::Mainnet,
        version: Version::V1,
        pubkey_type: PubKeyType::MlDsa44,
        pubkey_bytes: &vk2,
    })
    .unwrap();
    let r2 = PQAgentRecord {
        pq_address: addr2,
        public_key: vk2,
        algorithm: PubKeyAlgorithm::MlDsa44,
    };

    assert!(registry.register(r1).is_ok());
    assert!(registry.register(r2).is_ok());
}

// ── resolve ───────────────────────────────────────────────────────────────────

#[test]
fn resolve_registered_agent() {
    let mut registry = PQRegistry::new();
    let record = make_record();
    let address = record.pq_address.clone();
    registry.register(record).unwrap();

    let resolved = registry.resolve(&address);
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().pq_address, address);
}

#[test]
fn resolve_unknown_address_returns_none() {
    let registry = PQRegistry::new();
    assert!(registry.resolve("yp1qnonexistent").is_none());
}

#[test]
fn resolve_returns_correct_public_key() {
    let mut registry = PQRegistry::new();
    let record = make_record();
    let address = record.pq_address.clone();
    let expected_key = record.public_key.clone();
    registry.register(record).unwrap();

    let resolved = registry.resolve(&address).unwrap();
    assert_eq!(resolved.public_key, expected_key);
}

// ── default ───────────────────────────────────────────────────────────────────

#[test]
fn default_registry_is_empty() {
    let registry = PQRegistry::default();
    assert!(registry.resolve("anything").is_none());
}

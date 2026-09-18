use ml_dsa::{
    EncodedSigningKey, KeyGen, MlDsa44, Signature, SigningKey,
    signature::Signer,
};
use pq_address::{AddressParams, Network, PubKeyType, Version, encode_address};
use rand::rngs::OsRng;
use types::{PQAgentRecord, PaymentIntent, PubKeyAlgorithm, SignedPayment, X402PqError, canonical_bytes};

/// ML-DSA-44 key sizes (fixed by the spec).
pub const SIGNING_KEY_BYTES: usize = 2560;
pub const VERIFYING_KEY_BYTES: usize = 1312;

pub struct PQAgent {
    signing_key: SigningKey<MlDsa44>,
    pub pq_address: String,
    pub public_key: Vec<u8>, // encoded verifying key, 1312 bytes
}

impl PQAgent {
    /// Generate a fresh keypair.
    pub fn new() -> Result<Self, X402PqError> {
        let keypair = MlDsa44::key_gen(&mut OsRng);
        let public_key = <_ as AsRef<[u8]>>::as_ref(&keypair.verifying_key().encode()).to_vec();
        let pq_address = derive_address(&public_key)?;

        Ok(Self {
            signing_key: keypair.signing_key().clone(),
            pq_address,
            public_key,
        })
    }

    /// Reconstruct from stored key bytes (e.g. loaded from key.bin).
    /// `sk_bytes` is 2560 bytes; `vk_bytes` is 1312 bytes.
    pub fn from_key_bytes(sk_bytes: &[u8], vk_bytes: &[u8]) -> Result<Self, X402PqError> {
        let sk_enc = EncodedSigningKey::<MlDsa44>::try_from(sk_bytes)
            .map_err(|_| X402PqError::InvalidSignature)?;
        let signing_key = SigningKey::<MlDsa44>::decode(&sk_enc);
        let public_key = vk_bytes.to_vec();
        let pq_address = derive_address(vk_bytes)?;

        Ok(Self { signing_key, pq_address, public_key })
    }

    /// Export (signing_key_bytes, verifying_key_bytes) for persistence.
    pub fn export_key_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        let sk = <_ as AsRef<[u8]>>::as_ref(&self.signing_key.encode()).to_vec();
        (sk, self.public_key.clone())
    }

    pub fn agent_record(&self) -> PQAgentRecord {
        PQAgentRecord {
            pq_address: self.pq_address.clone(),
            public_key: self.public_key.clone(),
            algorithm: PubKeyAlgorithm::MlDsa44,
        }
    }

    pub fn sign_payment(&self, intent: PaymentIntent) -> Result<SignedPayment, X402PqError> {
        let msg = canonical_bytes(&intent);
        let sig: Signature<MlDsa44> = self.signing_key.sign(&msg);
        let signature = <_ as AsRef<[u8]>>::as_ref(&sig.encode()).to_vec();

        Ok(SignedPayment {
            intent,
            algorithm: PubKeyAlgorithm::MlDsa44,
            public_key: self.public_key.clone(),
            signature,
        })
    }
}

fn derive_address(vk_bytes: &[u8]) -> Result<String, X402PqError> {
    encode_address(&AddressParams {
        network: Network::Mainnet,
        version: Version::V1,
        pubkey_type: PubKeyType::MlDsa44,
        pubkey_bytes: vk_bytes,
    })
    .map_err(|_| X402PqError::AddressMismatch)
}

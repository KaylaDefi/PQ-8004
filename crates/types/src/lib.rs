use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PubKeyAlgorithm {
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
}

impl PubKeyAlgorithm {
    pub fn scheme_name(&self) -> &'static str {
        match self {
            PubKeyAlgorithm::MlDsa44 => "ml-dsa-44",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub pq_address: String,
    pub recipient: String,
    pub amount: u64,
    pub nonce: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayment {
    pub intent: PaymentIntent,
    pub algorithm: PubKeyAlgorithm,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentChallenge {
    pub nonce: String,
    pub amount: u64,
    pub recipient: String,
    pub scheme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQAgentRecord {
    pub pq_address: String,
    pub public_key: Vec<u8>,
    pub algorithm: PubKeyAlgorithm,
}

#[derive(Debug, thiserror::Error)]
pub enum X402PqError {
    #[error("unknown agent: {0}")]
    UnknownAgent(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("address does not match public key")]
    AddressMismatch,
    #[error("nonce already used: {0}")]
    NonceReused(String),
    #[error("payment challenge expired")]
    Expired,
    #[error("malformed payment header: {0}")]
    MalformedHeader(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Deterministic byte encoding of a `PaymentIntent`, used as the message
/// both the signer and verifier hash/sign over. Field order is fixed
/// explicitly (not derived from struct/JSON field order) so the encoding
/// is stable even if the struct definition changes order later.
pub fn canonical_bytes(intent: &PaymentIntent) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(intent.pq_address.as_bytes());
    buf.push(0);
    buf.extend_from_slice(intent.recipient.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&intent.amount.to_be_bytes());
    buf.extend_from_slice(intent.nonce.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&intent.expires_at.to_be_bytes());
    buf
}

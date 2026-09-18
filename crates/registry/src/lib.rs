use std::collections::HashMap;
use sha2::{Digest, Sha256};
use types::{PQAgentRecord, X402PqError};
use pq_address::decode_address;

pub struct PQRegistry {
    records: HashMap<String, PQAgentRecord>,
}

impl PQRegistry {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Register an agent record, verifying that sha256(pubkey_bytes) matches
    /// the hash embedded in the pq_address bech32m string.
    pub fn register(&mut self, record: PQAgentRecord) -> Result<(), X402PqError> {
        let decoded = decode_address(&record.pq_address)
            .map_err(|_| X402PqError::AddressMismatch)?;

        let expected_hash: Vec<u8> = Sha256::digest(&record.public_key).to_vec();

        if decoded.pubkey_hash != expected_hash {
            return Err(X402PqError::AddressMismatch);
        }

        self.records.insert(record.pq_address.clone(), record);
        Ok(())
    }

    pub fn resolve(&self, pq_address: &str) -> Option<&PQAgentRecord> {
        self.records.get(pq_address)
    }

    pub fn all_records(&self) -> impl Iterator<Item = &PQAgentRecord> + '_ {
        self.records.values()
    }
}

impl Default for PQRegistry {
    fn default() -> Self {
        Self::new()
    }
}

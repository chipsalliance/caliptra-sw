// Licensed under the Apache-2.0 license

use serde::{Deserialize, Serialize};

/// This file contains the test vectors as defined in Appendix A of
/// https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/03/.
const HPKE_TEST_VECTOR_PQ: &str = include_str!("../../crypto/test_vectors/hpke-pq.json");

#[derive(Deserialize, Serialize)]
pub struct Encryption {
    #[serde(with = "hex::serde")]
    pub aad: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub pt: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
pub struct HpkeTestArgs {
    pub mode: u8,
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    #[serde(with = "hex::serde")]
    pub info: Vec<u8>,
    #[serde(with = "hex::serde", rename = "ikmE")]
    pub ikm_e: Vec<u8>,
    #[serde(with = "hex::serde", rename = "ikmR")]
    pub ikm_r: Vec<u8>,
    #[serde(with = "hex::serde", rename = "skRm")]
    pub sk_rm: Vec<u8>,
    #[serde(with = "hex::serde", rename = "pkRm")]
    pub pk_rm: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub enc: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub shared_secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub suite_id: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub base_nonce: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub exporter_secret: Vec<u8>,
    pub encryptions: Vec<Encryption>,
}

impl HpkeTestArgs {
    /// Returns the HPKE Test vector for the chosen KEM.
    pub fn new(kem_id: u16) -> Self {
        let kdf_id = 2;
        let aead_id = 2;
        let test_vectors: Vec<HpkeTestArgs> = serde_json::from_str(HPKE_TEST_VECTOR_PQ).unwrap();

        test_vectors
            .into_iter()
            .find(|args| args.kem_id == kem_id && args.kdf_id == kdf_id && aead_id == args.aead_id)
            .unwrap()
    }
}

// Licensed under the Apache-2.0 license

use hkdf::Hkdf;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub struct Hmac384Kdf;
impl Hmac384Kdf {
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<sha2::Sha384>::extract(Some(salt), ikm);
        prk.to_vec()
    }
    pub fn expand(prk: &[u8], info: &[u8], l: usize) -> Vec<u8> {
        let mut okm = vec![0; l];
        let hkdf = Hkdf::<sha2::Sha384>::from_prk(prk).unwrap();
        hkdf.expand(info, &mut okm).unwrap();
        okm
    }
}

pub struct Shake256Kdf;
impl Shake256Kdf {
    pub fn labeled_derive(
        suite_id: &[u8],
        ikm: &[u8],
        label: &[u8],
        context: &[u8],
        l: usize,
    ) -> Vec<u8> {
        let label_len = u16::try_from(label.len()).unwrap().to_be_bytes();
        let label_with_len = [&label_len, label].concat();
        let labeled_ikm = {
            let mut data = Vec::new();
            data.extend_from_slice(ikm);
            data.extend_from_slice(b"HPKE-v1");
            data.extend_from_slice(suite_id);
            data.extend_from_slice(&label_with_len);
            data.extend_from_slice(&u16::try_from(l).unwrap().to_be_bytes());
            data.extend_from_slice(context);
            data
        };

        Self::derive(&labeled_ikm, l)
    }

    pub fn derive(ikm: &[u8], len: usize) -> Vec<u8> {
        let mut shake = sha3::Shake256::default();
        shake.update(ikm);

        let mut res = vec![0; len];
        let mut reader = shake.finalize_xof();
        reader.read(&mut res);
        res
    }
}

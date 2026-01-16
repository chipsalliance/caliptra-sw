// Licensed under the Apache-2.0 license

use std::marker::PhantomData;

/// HPKE Implementation intended to be used in OCP LOCK tests
///
/// Implements:
/// * ML-KEM-1024-HKDF-SHA-384-AES-256-GCM
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem},
    EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params, B32,
};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    pkey_ml_kem::{PKeyMlKemBuilder, PKeyMlKemParams, Variant},
    sign::Signer,
};
use rand::Rng;
use zerocopy::IntoBytes;

pub mod kdf;
pub mod test_vector;

const BASE_MODE: u8 = 0x0;

pub trait Role {}

pub struct Sender;
pub struct Receiver;

impl Role for Sender {}
impl Role for Receiver {}

/// Implements an HPKE Encryption Context with AES-256-GCM.
pub struct EncryptionContext<Role> {
    pub key: Vec<u8>,
    pub base_nonce: Vec<u8>,
    pub exporter_secret: Vec<u8>,
    pub nonce: usize,
    _role: PhantomData<Role>,
}

impl<Role> EncryptionContext<Role> {
    const NN: usize = 12;
    pub fn new(key: Vec<u8>, base_nonce: Vec<u8>, exporter_secret: Vec<u8>) -> Self {
        Self {
            key,
            base_nonce,
            nonce: 0,
            exporter_secret,
            _role: PhantomData::<Role>,
        }
    }

    pub fn computed_nonce(&self) -> Vec<u8> {
        let nonce_bytes = self.nonce.to_be_bytes();
        let mut current_nonce = vec![0; Self::NN];
        let padding = Self::NN - nonce_bytes.len();
        current_nonce[padding..].clone_from_slice(&nonce_bytes);

        for (nonce, base) in current_nonce.iter_mut().zip(self.base_nonce.iter()) {
            *nonce ^= base;
        }
        current_nonce
    }
}

impl<Sender> EncryptionContext<Sender> {
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let nonce = self.computed_nonce();
        let payload = Payload { aad, msg: pt };
        let cipher = Aes256Gcm::new(self.key.as_slice().into());
        let ct = cipher.encrypt(nonce.as_slice().into(), payload).unwrap();
        self.nonce = self
            .nonce
            .checked_add(1)
            .expect("NONCE overflowed. This should never happen!");
        ct
    }
}

impl<Receiver> EncryptionContext<Receiver> {
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let nonce = self.computed_nonce();
        let payload = Payload { aad, msg: ct };
        let cipher = Aes256Gcm::new(self.key.as_slice().into());
        let pt = cipher.decrypt(nonce.as_slice().into(), payload).unwrap();
        self.nonce = self
            .nonce
            .checked_add(1)
            .expect("NONCE overflowed. This should never happen!");
        pt
    }
}

/// HPKE trait
///
/// NOTE: Does not implement [secret
/// export](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#name-secret-export-2) as
/// this is not used in OCP LOCK.
pub trait Hpke {
    const LABEL_DERIVE_SUITE_ID: &'static [u8];
    const ALG_ID: &'static [u8];
    const NK: usize;
    const NT: usize;
    const NH: usize;
    fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
        let suite_id: Vec<u8> = [&b"HPKE"[..], Self::ALG_ID].concat();
        let labeled_ikm = {
            let mut ikm_builder = Vec::new();
            ikm_builder.extend_from_slice(b"HPKE-v1");
            ikm_builder.extend_from_slice(&suite_id);
            ikm_builder.extend_from_slice(label);
            ikm_builder.extend_from_slice(ikm);
            ikm_builder
        };
        kdf::Hmac384Kdf::extract(salt, &labeled_ikm)
    }

    fn labeled_expand(prk: &[u8], label: &[u8], info: &[u8], l: usize) -> Vec<u8> {
        let suite_id: Vec<u8> = [&b"HPKE"[..], Self::ALG_ID].concat();
        let labeled_info = {
            let mut ikm_builder = Vec::new();
            ikm_builder.extend_from_slice(&u16::try_from(l).unwrap().to_be_bytes());
            ikm_builder.extend_from_slice(b"HPKE-v1");
            ikm_builder.extend_from_slice(&suite_id);
            ikm_builder.extend_from_slice(label);
            ikm_builder.extend_from_slice(info);
            ikm_builder
        };
        kdf::Hmac384Kdf::expand(prk, &labeled_info, l)
    }

    /// NOTE: This impementation does not support `psk` and `psk_id`.
    fn key_schedule<R: Role>(
        mode: u8,
        shared_secret: &[u8],
        info: Option<&[u8]>,
    ) -> EncryptionContext<R> {
        let psk_id_hash = Self::labeled_extract(&[], b"psk_id_hash", &[]);
        let info_hash = Self::labeled_extract(&[], b"info_hash", info.unwrap_or_default());
        let key_schedule_context: Vec<u8> = {
            let mut key_schedule_context = Vec::new();
            key_schedule_context.extend_from_slice(mode.as_bytes());
            key_schedule_context.extend_from_slice(psk_id_hash.as_bytes());
            key_schedule_context.extend_from_slice(info_hash.as_bytes());
            key_schedule_context
        };
        let secret = Self::labeled_extract(shared_secret, b"secret", &[]);
        let key = Self::labeled_expand(&secret, b"key", &key_schedule_context, Self::NK);
        let base_nonce = Self::labeled_expand(
            &secret,
            b"base_nonce",
            &key_schedule_context,
            EncryptionContext::<R>::NN,
        );
        let exporter_secret =
            Self::labeled_expand(&secret, b"exp", &key_schedule_context, Self::NH);
        EncryptionContext::new(key, base_nonce, exporter_secret)
    }

    fn setup_base_r(&self, enc: &[u8], sk_r: &[u8], info: &[u8]) -> EncryptionContext<Receiver> {
        let shared_secret = self.decap(enc, sk_r);
        Self::key_schedule(BASE_MODE, &shared_secret, Some(info))
    }

    fn setup_base_s(&self, pkr: &[u8], info: &[u8]) -> (Vec<u8>, EncryptionContext<Sender>) {
        let (shared_secret, enc) = self.encap(pkr);
        (
            enc,
            Self::key_schedule(BASE_MODE, &shared_secret, Some(info)),
        )
    }

    fn decap(&self, enc: &[u8], sk_r: &[u8]) -> Vec<u8>;
    fn encap(&self, pk_r: &[u8]) -> (Vec<u8>, Vec<u8>);
    fn derive_key_pair(ikm: Vec<u8>) -> Self;
    fn generate_key_pair() -> Self;
}

pub struct HpkeMlKem1024 {
    pub dk: Vec<u8>,
    pub ek: EncapsulationKey<MlKem1024Params>,
}

impl Hpke for HpkeMlKem1024 {
    // ML-KEM-1024: KEM\x00\x42 (hex: 4b454d0042) + KEM ID (0x00 0x42)
    const LABEL_DERIVE_SUITE_ID: &'static [u8] = &[0x4b, 0x45, 0x4d, 0x00, 0x42];
    // KDF + KDF + AAD
    const ALG_ID: &'static [u8] = &[0x0, 0x42, 0x0, 0x02, 0x0, 0x02];
    const NK: usize = 32;
    const NT: usize = 16;
    const NH: usize = 48;

    fn decap(&self, enc: &[u8], sk_r: &[u8]) -> Vec<u8> {
        let d = B32::try_from(&sk_r[..32]).unwrap();
        let z = B32::try_from(&sk_r[32..]).unwrap();
        let (dk, _) = MlKem1024::generate_deterministic(&d, &z);
        let pt = dk.decapsulate(enc.try_into().unwrap()).unwrap();
        pt.to_vec()
    }

    fn encap(&self, pk_r: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let ek_bytes =
            Encoded::<<Kem<MlKem1024Params> as KemCore>::EncapsulationKey>::try_from(pk_r).unwrap();
        let ek = <<Kem<MlKem1024Params> as KemCore>::EncapsulationKey>::from_bytes(&ek_bytes);

        let (enc, shared_secret) = ek.encapsulate(&mut rng).unwrap();
        (shared_secret.to_vec(), enc.to_vec())
    }

    fn derive_key_pair(ikm: Vec<u8>) -> Self {
        let expanded_ikm = kdf::Shake256Kdf::labeled_derive(
            Self::LABEL_DERIVE_SUITE_ID,
            &ikm,
            b"DeriveKeyPair",
            b"",
            64,
        );
        let d = B32::try_from(&expanded_ikm[..32]).unwrap();
        let z = B32::try_from(&expanded_ikm[32..]).unwrap();
        let (_, ek) = MlKem1024::generate_deterministic(&d, &z);
        Self {
            dk: expanded_ikm,
            ek,
        }
    }

    fn generate_key_pair() -> Self {
        let mut rng = rand::thread_rng();
        let mut dz = vec![0; 64];
        rng.fill(&mut dz[..]);
        Self::derive_key_pair(dz)
    }
}

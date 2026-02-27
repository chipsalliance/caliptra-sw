// Licensed under the Apache-2.0 license

use std::marker::PhantomData;

/// HPKE Implementation intended to be used in OCP LOCK tests
///
/// Implements:
/// * ML-KEM-1024-HKDF-SHA-384-AES-256-GCM
/// * DH(P-384,SHA-384)-HKDF-SHA-384-AES-256-GCM
/// * ML-KEM-1024-P384-HKDF-SHA-384-AES-256-GCM
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use hpke::{
    kem::{DhP384HkdfSha384, Kem as HpkeKem},
    Deserializable, Serializable,
};
use kdf::Shake256Kdf;
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
use p384::ecdh::diffie_hellman;
use p384::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p384::{
    elliptic_curve::{ops::Reduce, Scalar},
    AffinePoint, ProjectivePoint,
};
use p384::{
    EncodedPoint, NonZeroScalar, PublicKey as P384PublicKey, Scalar as P384Scalar, SecretKey,
};
use rand::Rng;
use sha2::{
    digest::{consts::P338, generic_array::GenericArray},
    Digest,
};
use sha3::Sha3_256;
use test_vector::HpkeTestArgs;
use zerocopy::IntoBytes;

use super::{HYBRID_KEM_ID, P384_KEM_ID};

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
    const NK: usize = 32;
    const NT: usize = 16;
    const NH: usize = 48;
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
    fn serialize_dk(&self) -> Vec<u8>;
    fn serialize_ek(&self) -> Vec<u8>;
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

    fn serialize_ek(&self) -> Vec<u8> {
        self.ek.as_bytes().to_vec()
    }

    fn serialize_dk(&self) -> Vec<u8> {
        self.dk.clone()
    }
}

pub struct HpkeP384 {
    pub sk: <DhP384HkdfSha384 as HpkeKem>::PrivateKey,
    pub pk: <DhP384HkdfSha384 as HpkeKem>::PublicKey,
}

impl Hpke for HpkeP384 {
    // DHKEM(P-384, HKDF-SHA384): KEM ID 0x0011
    const LABEL_DERIVE_SUITE_ID: &'static [u8] = &[0x4b, 0x45, 0x4d, 0x00, 0x11];
    // KEM (0x0011) + KDF (0x0002) + AEAD (0x0002)
    const ALG_ID: &'static [u8] = &[0x0, 0x11, 0x0, 0x02, 0x0, 0x02];

    fn decap(&self, enc: &[u8], sk_r: &[u8]) -> Vec<u8> {
        let sk = <DhP384HkdfSha384 as HpkeKem>::PrivateKey::from_bytes(sk_r).unwrap();
        let enc = <DhP384HkdfSha384 as HpkeKem>::EncappedKey::from_bytes(enc).unwrap();
        DhP384HkdfSha384::decap(&sk, None, &enc).unwrap().0.to_vec()
    }

    fn encap(&self, pk_r: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pk = <DhP384HkdfSha384 as HpkeKem>::PublicKey::from_bytes(pk_r).unwrap();
        let mut rng = rand::thread_rng();
        let (shared_secret, enc) = DhP384HkdfSha384::encap(&pk, None, &mut rng).unwrap();
        (shared_secret.0.to_vec(), enc.to_bytes().to_vec())
    }

    fn derive_key_pair(ikm: Vec<u8>) -> Self {
        let (sk, pk) = DhP384HkdfSha384::derive_keypair(&ikm);
        Self { sk, pk }
    }

    fn generate_key_pair() -> Self {
        let mut rng = rand::thread_rng();
        let (sk, pk) = DhP384HkdfSha384::gen_keypair(&mut rng);
        Self { sk, pk }
    }

    fn serialize_ek(&self) -> Vec<u8> {
        self.pk.to_bytes().to_vec()
    }

    fn serialize_dk(&self) -> Vec<u8> {
        self.sk.to_bytes().to_vec()
    }
}

pub struct HpkeHybrid {
    pub pq_dk: Vec<u8>,
    pub pq_ek: Vec<u8>,
    pub trad_dk: SecretKey,
    pub trad_ek: P384PublicKey,
    pub seed: Vec<u8>,
}

impl HpkeHybrid {
    fn derive_pq(pq_seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pq_dk = pq_seed.to_vec();
        let pq_ek = {
            let d = B32::try_from(&pq_seed[..32]).unwrap();
            let z = B32::try_from(&pq_seed[32..]).unwrap();
            let (_, ek) = MlKem1024::generate_deterministic(&d, &z);
            ek
        };
        (pq_dk, pq_ek.as_bytes().to_vec())
    }

    fn derive_trad(trad_seed: &[u8]) -> (SecretKey, P384PublicKey) {
        let trad_dk = SecretKey::from_bytes(
            &P384Scalar::reduce_bytes(GenericArray::from_slice(trad_seed)).to_bytes(),
        )
        .unwrap();
        let trad_ek = trad_dk.public_key();
        (trad_dk, trad_ek)
    }

    fn derive_from_seed(seed: Vec<u8>) -> Self {
        let mlkem_seed_size = 64;
        let p384_seed_size = 48;

        let seed_full = kdf::Shake256Kdf::derive(&seed, mlkem_seed_size + p384_seed_size);

        let pq_seed = &seed_full[..mlkem_seed_size];
        let trad_seed = &seed_full[mlkem_seed_size..mlkem_seed_size + p384_seed_size];

        let (pq_dk, pq_ek) = Self::derive_pq(pq_seed);
        let (trad_dk, trad_ek) = Self::derive_trad(trad_seed);

        Self {
            pq_dk,
            pq_ek,
            trad_dk,
            trad_ek,
            seed,
        }
    }

    fn encap_pq(&self, pk_rm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let ek_bytes =
            Encoded::<<Kem<MlKem1024Params> as KemCore>::EncapsulationKey>::try_from(pk_rm)
                .unwrap();
        let ek = <<Kem<MlKem1024Params> as KemCore>::EncapsulationKey>::from_bytes(&ek_bytes);
        let (enc, shared_secret) = ek.encapsulate(&mut rng).unwrap();
        (enc.as_bytes().to_vec(), shared_secret.as_bytes().to_vec())
    }

    fn encap_trad(&self, pk_rm: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let sk_e = SecretKey::random(&mut rng);
        let enc = sk_e.public_key().to_encoded_point(false);
        let shared_secret = self.ecdh(pk_rm, &sk_e);
        (enc.as_bytes().to_vec(), shared_secret)
    }

    fn decap_pq(&self, enc_pq: &[u8]) -> Vec<u8> {
        let d = B32::try_from(&self.pq_dk[..32]).unwrap();
        let z = B32::try_from(&self.pq_dk[32..]).unwrap();
        let (dk, _) = MlKem1024::generate_deterministic(&d, &z);
        dk.decapsulate(enc_pq.try_into().unwrap()).unwrap().to_vec()
    }

    fn ecdh(&self, encoded_point: &[u8], priv_key: &SecretKey) -> Vec<u8> {
        let public_key = P384PublicKey::from_sec1_bytes(encoded_point).unwrap();
        let shared_secret = diffie_hellman(priv_key.to_nonzero_scalar(), public_key.as_affine());

        // We need to include the raw `X` bytes in the `C2PRICombiner`.
        shared_secret.raw_secret_bytes().to_vec()
    }

    fn decap_trad(&self, enc_trad: &[u8]) -> Vec<u8> {
        self.ecdh(enc_trad, &self.trad_dk)
    }
}

impl Hpke for HpkeHybrid {
    // KEM ID 0x0051
    const LABEL_DERIVE_SUITE_ID: &'static [u8] = &[0x4b, 0x45, 0x4d, 0x00, 0x51];
    // KEM (0x0051) + KDF (0x0002) + AEAD (0x0002)
    const ALG_ID: &'static [u8] = &[0x0, 0x51, 0x0, 0x02, 0x0, 0x02];

    fn decap(&self, enc: &[u8], sk_r: &[u8]) -> Vec<u8> {
        let hpke = Self::derive_from_seed(sk_r.to_vec());

        let enc_pq = &enc[..1568];
        let enc_trad = &enc[1568..];

        let pq_shared_secret = hpke.decap_pq(enc_pq);
        let trad_shared_secret = hpke.decap_trad(enc_trad);

        let mut ss_combined = Vec::new();
        ss_combined.extend_from_slice(&pq_shared_secret);
        ss_combined.extend_from_slice(&trad_shared_secret);
        ss_combined.extend_from_slice(enc_trad);
        ss_combined.extend_from_slice(hpke.trad_ek.to_encoded_point(false).as_bytes());
        ss_combined.extend_from_slice(&b"MLKEM1024-P384"[..]);

        let mut hasher = Sha3_256::new();
        hasher.update(&ss_combined);
        hasher.finalize().to_vec()
    }

    fn encap(&self, pk_r: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pk_pq_bytes = &pk_r[..1568];
        let pk_trad_bytes = &pk_r[1568..];

        let (enc_pq, ss_pq) = self.encap_pq(pk_pq_bytes);
        let (enc_trad, ss_trad) = self.encap_trad(pk_trad_bytes);

        let mut enc = Vec::new();
        enc.extend_from_slice(&enc_pq);
        enc.extend_from_slice(enc_trad.as_bytes());

        let mut ss_combined = Vec::new();
        ss_combined.extend_from_slice(&ss_pq);
        ss_combined.extend_from_slice(&ss_trad);
        ss_combined.extend_from_slice(enc_trad.as_bytes());
        ss_combined.extend_from_slice(pk_trad_bytes);
        ss_combined.extend_from_slice(&b"MLKEM1024-P384"[..]);

        let mut hasher = Sha3_256::new();
        hasher.update(&ss_combined);
        let ss = hasher.finalize().to_vec();

        (ss, enc)
    }

    fn derive_key_pair(ikm: Vec<u8>) -> Self {
        let seed = kdf::Shake256Kdf::labeled_derive(
            Self::LABEL_DERIVE_SUITE_ID,
            &ikm,
            b"DeriveKeyPair",
            b"",
            32,
        );
        Self::derive_from_seed(seed)
    }

    fn generate_key_pair() -> Self {
        let mut rng = rand::thread_rng();
        let mut dz = vec![0; 64];
        rng.fill(&mut dz[..]);
        Self::derive_key_pair(dz)
    }

    fn serialize_dk(&self) -> Vec<u8> {
        self.seed.clone()
    }

    fn serialize_ek(&self) -> Vec<u8> {
        let mut ek = Vec::new();
        ek.extend_from_slice(self.pq_ek.as_bytes());
        ek.extend_from_slice(self.trad_ek.to_encoded_point(false).as_bytes());
        ek
    }
}

#[test]
fn test_hpke_p384_self_talk() {
    let hpke_receiver = HpkeP384::generate_key_pair();
    let pk_r = hpke_receiver.pk.to_bytes().to_vec();
    let sk_r = hpke_receiver.sk.to_bytes().to_vec();

    let info = b"HPKE P-384 Info";
    let aad = b"HPKE P-384 AAD";
    let pt = b"Not all those who wander are lost";

    let (enc, mut sender_ctx) = hpke_receiver.setup_base_s(&pk_r, info);
    let ct = sender_ctx.seal(aad, pt);

    let mut receiver_ctx = hpke_receiver.setup_base_r(&enc, &sk_r, info);
    let decrypted_pt = receiver_ctx.open(aad, &ct);

    assert_eq!(pt, decrypted_pt.as_slice());
}

#[test]
fn test_hpke_p384_vectors() {
    let args = HpkeTestArgs::new(P384_KEM_ID);
    assert_eq!(args.kem_id, 17);
    let hpke = HpkeP384::derive_key_pair(args.ikm_r.clone());
    assert_eq!(hpke.serialize_ek(), args.pk_rm.as_slice(),);
    assert_eq!(hpke.serialize_dk(), args.sk_rm.as_slice(),);

    let mut recipient_ctx = hpke.setup_base_r(&args.enc, &args.sk_rm, &args.info);
    assert_eq!(recipient_ctx.key, args.key);
    assert_eq!(recipient_ctx.base_nonce, args.base_nonce,);
    assert_eq!(recipient_ctx.exporter_secret, args.exporter_secret,);

    for enc_test in &args.encryptions {
        let pt = recipient_ctx.open(&enc_test.aad, &enc_test.ct);
        assert_eq!(pt, enc_test.pt);
    }
}

#[test]
fn test_hpke_hybrid_vectors() {
    let args = HpkeTestArgs::new(HYBRID_KEM_ID);
    assert_eq!(args.kem_id, 81);
    let hpke = HpkeHybrid::derive_key_pair(args.ikm_r.clone());
    assert_eq!(hpke.serialize_dk(), args.sk_rm.as_slice());
    assert_eq!(hpke.serialize_ek(), args.pk_rm.as_slice());

    let mut recipient_ctx = hpke.setup_base_r(&args.enc, &args.sk_rm, &args.info);
    assert_eq!(recipient_ctx.key, args.key);
    assert_eq!(recipient_ctx.base_nonce, args.base_nonce,);
    assert_eq!(recipient_ctx.exporter_secret, args.exporter_secret,);

    for enc_test in &args.encryptions {
        let pt = recipient_ctx.open(&enc_test.aad, &enc_test.ct);
        assert_eq!(pt, enc_test.pt);
    }
}

#[test]
fn test_hpke_hybrid_self_talk() {
    let hpke_receiver = HpkeHybrid::generate_key_pair();
    let pk_r = hpke_receiver.serialize_ek();
    let sk_r = hpke_receiver.serialize_dk();

    let info = b"HPKE Hybrid Info";
    let aad = b"HPKE Hybrid AAD";
    let pt = b"All that is gold does not glitter";

    let (enc, mut sender_ctx) = hpke_receiver.setup_base_s(&pk_r, info);
    let ct = sender_ctx.seal(aad, pt);

    let mut receiver_ctx = hpke_receiver.setup_base_r(&enc, &sk_r, info);
    let decrypted_pt = receiver_ctx.open(aad, &ct);

    assert_eq!(pt, decrypted_pt.as_slice());
}

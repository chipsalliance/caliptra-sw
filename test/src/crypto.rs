// Licensed under the Apache-2.0 license

#![allow(unused)]

/// Cryptographic operations implemented for readability rather than
/// performance, implemented independently from the rest of Caliptra for use in
/// end-to-end test cases.
///
/// DO NOT REFACTOR THIS FILE TO RE-USE CODE FROM OTHER PARTS OF CALIPTRA
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::{PKey, Public},
};

// Derives a key using a DRBG. Returns (priv, pub_x, pub_y)
pub fn derive_ecdsa_keypair(seed: &[u8]) -> ([u8; 48], [u8; 48], [u8; 48]) {
    let priv_key = hmac384_drbg_keygen(seed, &[0; 48]);
    let pub_key = derive_ecdsa_key(&priv_key);
    let ec_key = EcKey::try_from(pub_key).unwrap();

    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut bn_ctx = BigNumContext::new().unwrap();
    let mut pub_x = BigNum::new().unwrap();
    let mut pub_y = BigNum::new().unwrap();
    ec_key
        .public_key()
        .affine_coordinates(&group, &mut pub_x, &mut pub_y, &mut bn_ctx)
        .unwrap();
    (
        priv_key,
        pub_x.to_vec_padded(48).unwrap().try_into().unwrap(),
        pub_y.to_vec_padded(48).unwrap().try_into().unwrap(),
    )
}

#[test]
fn test_derive_ecdsa_keypair() {
    let (priv_key, pub_x, pub_y) = derive_ecdsa_keypair(&[
        0x75, 0xb7, 0x66, 0x26, 0x10, 0x09, 0x7e, 0xb6, 0x58, 0xc4, 0x2c, 0x44, 0xa5, 0xe3, 0xf1,
        0x4f, 0x64, 0xd2, 0xc7, 0xde, 0x15, 0x4d, 0xbd, 0xda, 0x03, 0x1c, 0x18, 0xbc, 0x1a, 0x8a,
        0xfa, 0xd4, 0xcb, 0x61, 0x3d, 0x5b, 0x85, 0x69, 0x96, 0x53, 0x9b, 0x14, 0x55, 0xab, 0x89,
        0xa1, 0xd0, 0x3f,
    ]);
    assert_eq!(
        priv_key,
        [
            0x9f, 0xb1, 0xc3, 0xff, 0xf6, 0xd6, 0xfa, 0x09, 0x28, 0x3a, 0x5d, 0x6b, 0x78, 0xe5,
            0xcb, 0x31, 0x7e, 0x9c, 0xa1, 0xd1, 0x8a, 0x12, 0xbf, 0x90, 0x45, 0x76, 0x41, 0x9d,
            0x77, 0x2f, 0xed, 0x33, 0x51, 0x6c, 0x8a, 0x85, 0x6b, 0xdd, 0x84, 0xd6, 0x7a, 0x1f,
            0xf1, 0x19, 0xe2, 0x95, 0x15, 0x0f
        ]
    );
    assert_eq!(
        pub_x,
        [
            0x6a, 0x95, 0x60, 0x46, 0xea, 0x28, 0x3a, 0x03, 0x19, 0x10, 0x5d, 0xed, 0x52, 0x11,
            0x81, 0xea, 0x95, 0x7f, 0xdb, 0x40, 0xb1, 0x1f, 0x52, 0x17, 0xdf, 0x3f, 0x33, 0x92,
            0x17, 0xa6, 0x19, 0x01, 0xab, 0xe7, 0x4c, 0xf9, 0xbc, 0xad, 0xd5, 0xc1, 0x1f, 0x29,
            0xe4, 0xc2, 0xd7, 0x0f, 0xb5, 0x43,
        ],
    );
    assert_eq!(
        pub_y,
        [
            0x01, 0x5c, 0x00, 0x00, 0x34, 0x76, 0xc6, 0xb9, 0xc2, 0xa5, 0x7d, 0x79, 0x90, 0x14,
            0xe1, 0x56, 0xa1, 0x1c, 0x6b, 0x32, 0x88, 0x97, 0x3f, 0x90, 0xc2, 0xb5, 0x68, 0x5a,
            0xd4, 0x5a, 0x65, 0xc9, 0xe9, 0x17, 0x5b, 0xfd, 0x83, 0x6e, 0x93, 0xcf, 0xdb, 0xc0,
            0x54, 0x1a, 0x3b, 0xf6, 0x3d, 0xae,
        ],
    );
}

pub(crate) fn derive_ecdsa_key(priv_bytes: &[u8; 48]) -> PKey<Public> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut pub_point = EcPoint::new(&group).unwrap();

    let bn_ctx = BigNumContext::new().unwrap();
    let priv_key_bn = &BigNum::from_slice(priv_bytes).unwrap();
    pub_point
        .mul_generator(&group, priv_key_bn, &bn_ctx)
        .unwrap();
    let key = EcKey::from_private_components(&group, priv_key_bn, &pub_point).unwrap();
    let public_key = EcKey::from_public_key(&group, key.public_key()).unwrap();
    PKey::from_ec_key(public_key).unwrap()
}

#[test]
fn test_derive_ecdsa_key() {
    // test vector from https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/digital-signatures

    let expected_public_key = PKey::from_ec_key(
        EcKey::from_public_key_affine_coordinates(
            &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
            &BigNum::from_slice(&[
                0xfd, 0x3c, 0x84, 0xe5, 0x68, 0x9b, 0xed, 0x27, 0x0e, 0x60, 0x1b, 0x3d, 0x80, 0xf9,
                0x0d, 0x67, 0xa9, 0xae, 0x45, 0x1c, 0xce, 0x89, 0x0f, 0x53, 0xe5, 0x83, 0x22, 0x9a,
                0xd0, 0xe2, 0xee, 0x64, 0x56, 0x11, 0xfa, 0x99, 0x36, 0xdf, 0xa4, 0x53, 0x06, 0xec,
                0x18, 0x06, 0x67, 0x74, 0xaa, 0x24,
            ])
            .unwrap(),
            &BigNum::from_slice(&[
                0xb8, 0x3c, 0xa4, 0x12, 0x6c, 0xfc, 0x4c, 0x4d, 0x1d, 0x18, 0xa4, 0xb6, 0xc2, 0x1c,
                0x7f, 0x69, 0x9d, 0x51, 0x23, 0xdd, 0x9c, 0x24, 0xf6, 0x6f, 0x83, 0x38, 0x46, 0xee,
                0xb5, 0x82, 0x96, 0x19, 0x6b, 0x42, 0xec, 0x06, 0x42, 0x5d, 0xb5, 0xb7, 0x0a, 0x4b,
                0x81, 0xb7, 0xfc, 0xf7, 0x05, 0xa0,
            ])
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    let derived_public_key = derive_ecdsa_key(&[
        0x53, 0x94, 0xf7, 0x97, 0x3e, 0xa8, 0x68, 0xc5, 0x2b, 0xf3, 0xff, 0x8d, 0x8c, 0xee, 0xb4,
        0xdb, 0x90, 0xa6, 0x83, 0x65, 0x3b, 0x12, 0x48, 0x5d, 0x5f, 0x62, 0x7c, 0x3c, 0xe5, 0xab,
        0xd8, 0x97, 0x8f, 0xc9, 0x67, 0x3d, 0x14, 0xa7, 0x1d, 0x92, 0x57, 0x47, 0x93, 0x16, 0x62,
        0x49, 0x3c, 0x37,
    ]);

    assert!(expected_public_key.public_eq(&derived_public_key));
}

pub(crate) fn hmac384(key: &[u8], data: &[u8]) -> [u8; 48] {
    use openssl::hash::MessageDigest;
    use openssl::sign::Signer;

    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
    signer.update(data).unwrap();
    let mut result = [0u8; 48];
    signer.sign(&mut result).unwrap();
    result
}

pub(crate) fn hmac512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use openssl::hash::MessageDigest;
    use openssl::sign::Signer;

    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha512(), &pkey).unwrap();
    signer.update(data).unwrap();
    let mut result = [0u8; 64];
    signer.sign(&mut result).unwrap();
    result
}

#[test]
fn test_hmac384() {
    // test vector from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication

    assert_eq!(
        hmac384(
            &[
                0x5e, 0xab, 0x0d, 0xfa, 0x27, 0x31, 0x12, 0x60, 0xd7, 0xbd, 0xdc, 0xf7, 0x71, 0x12,
                0xb2, 0x3d, 0x8b, 0x42, 0xeb, 0x7a, 0x5d, 0x72, 0xa5, 0xa3, 0x18, 0xe1, 0xba, 0x7e,
                0x79, 0x27, 0xf0, 0x07, 0x9d, 0xbb, 0x70, 0x13, 0x17, 0xb8, 0x7a, 0x33, 0x40, 0xe1,
                0x56, 0xdb, 0xce, 0xe2, 0x8e, 0xc3, 0xa8, 0xd9,
            ],
            &[
                0xf4, 0x13, 0x80, 0x12, 0x3c, 0xcb, 0xec, 0x4c, 0x52, 0x7b, 0x42, 0x56, 0x52, 0x64,
                0x11, 0x91, 0xe9, 0x0a, 0x17, 0xd4, 0x5e, 0x2f, 0x62, 0x06, 0xcf, 0x01, 0xb5, 0xed,
                0xbe, 0x93, 0x2d, 0x41, 0xcc, 0x8a, 0x24, 0x05, 0xc3, 0x19, 0x56, 0x17, 0xda, 0x2f,
                0x42, 0x05, 0x35, 0xee, 0xd4, 0x22, 0xac, 0x60, 0x40, 0xd9, 0xcd, 0x65, 0x31, 0x42,
                0x24, 0xf0, 0x23, 0xf3, 0xba, 0x73, 0x0d, 0x19, 0xdb, 0x98, 0x44, 0xc7, 0x1c, 0x32,
                0x9c, 0x8d, 0x9d, 0x73, 0xd0, 0x4d, 0x8c, 0x5f, 0x24, 0x4a, 0xea, 0x80, 0x48, 0x82,
                0x92, 0xdc, 0x80, 0x3e, 0x77, 0x24, 0x02, 0xe7, 0x2d, 0x2e, 0x9f, 0x1b, 0xab, 0xa5,
                0xa6, 0x00, 0x4f, 0x00, 0x06, 0xd8, 0x22, 0xb0, 0xb2, 0xd6, 0x5e, 0x9e, 0x4a, 0x30,
                0x2d, 0xd4, 0xf7, 0x76, 0xb4, 0x7a, 0x97, 0x22, 0x50, 0x05, 0x1a, 0x70, 0x1f, 0xab,
                0x2b, 0x70,
            ]
        ),
        [
            0x7c, 0xf5, 0xa0, 0x61, 0x56, 0xad, 0x3d, 0xe5, 0x40, 0x5a, 0x5d, 0x26, 0x1d, 0xe9,
            0x02, 0x75, 0xf9, 0xbb, 0x36, 0xde, 0x45, 0x66, 0x7f, 0x84, 0xd0, 0x8f, 0xbc, 0xb3,
            0x08, 0xca, 0x8f, 0x53, 0xa4, 0x19, 0xb0, 0x7d, 0xea, 0xb3, 0xb5, 0xf8, 0xea, 0x23,
            0x1c, 0x5b, 0x03, 0x6f, 0x88, 0x75,
        ],
    );
}

pub(crate) fn hmac384_kdf(key: &[u8], label: &[u8], context: Option<&[u8]>) -> [u8; 48] {
    let ctr_be = 1_u32.to_be_bytes();

    let mut msg = Vec::<u8>::default();
    msg.extend_from_slice(&ctr_be);
    msg.extend_from_slice(label);

    if let Some(context) = context {
        msg.push(0x00);
        msg.extend_from_slice(context);
    }

    hmac384(key, &msg)
}

pub(crate) fn hmac512_kdf(key: &[u8], label: &[u8], context: Option<&[u8]>) -> [u8; 64] {
    let ctr_be = 1_u32.to_be_bytes();

    let mut msg = Vec::<u8>::default();
    msg.extend_from_slice(&ctr_be);
    msg.extend_from_slice(label);

    if let Some(context) = context {
        msg.push(0x00);
        msg.extend_from_slice(context);
    }

    hmac512(key, &msg)
}

#[test]
fn test_hmac384_kdf() {
    // test vector from https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/key-derivation

    assert_eq!(
        hmac384_kdf(
            &[
                0xb5, 0x7d, 0xc5, 0x23, 0x54, 0xaf, 0xee, 0x11, 0xed, 0xb4, 0xc9, 0x05, 0x2a, 0x52,
                0x83, 0x44, 0x34, 0x8b, 0x2c, 0x6b, 0x6c, 0x39, 0xf3, 0x21, 0x33, 0xed, 0x3b, 0xb7,
                0x20, 0x35, 0xa4, 0xab, 0x55, 0xd6, 0x64, 0x8c, 0x15, 0x29, 0xef, 0x7a, 0x91, 0x70,
                0xfe, 0xc9, 0xef, 0x26, 0xa8, 0x1e,
            ],
            &[
                0x17, 0xe6, 0x41, 0x90, 0x9d, 0xed, 0xfe, 0xe4, 0x96, 0x8b, 0xb9, 0x5d, 0x7f, 0x77,
                0x0e, 0x45, 0x57, 0xca, 0x34, 0x7a, 0x46, 0x61, 0x4c, 0xb3, 0x71, 0x42, 0x3f, 0x0d,
                0x91, 0xdf, 0x3b, 0x58, 0xb5, 0x36, 0xed, 0x54, 0x53, 0x1f, 0xd2, 0xa2, 0xeb, 0x0b,
                0x8b, 0x2a, 0x16, 0x34, 0xc2, 0x3c, 0x88, 0xfa, 0xd9, 0x70, 0x6c, 0x45, 0xdb, 0x44,
                0x11, 0xa2, 0x3b, 0x89,
            ],
            None
        )[..40],
        [
            0x59, 0x49, 0xac, 0xf9, 0x63, 0x5a, 0x77, 0x29, 0x79, 0x28, 0xc1, 0xe1, 0x55, 0xd4,
            0x3a, 0x4e, 0x4b, 0xca, 0x61, 0xb1, 0x36, 0x9a, 0x5e, 0xf5, 0x05, 0x30, 0x88, 0x85,
            0x50, 0xba, 0x27, 0x0e, 0x26, 0xbe, 0x4a, 0x42, 0x1c, 0xdf, 0x80, 0xb7,
        ],
    );
}

fn is_valid_privkey(buf: &[u8; 48]) -> bool {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut order = BigNum::new().unwrap();
    group.order(&mut order, &mut ctx).unwrap();

    let zero = BigNum::from_u32(0).unwrap();

    let bn = &BigNum::from_slice(buf).unwrap();
    bn > &zero && bn < &order
}
#[test]
fn test_is_valid_privkey() {
    assert!(!is_valid_privkey(&[0; 48]));
    assert!(is_valid_privkey(&[1; 48]));
    assert!(is_valid_privkey(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x72
    ]));
    assert!(!is_valid_privkey(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x73
    ]));
}

struct Hmac384Drbg {
    k: [u8; 48],
    v: [u8; 48],
}
impl Hmac384Drbg {
    pub fn new(entropy: &[u8], nonce: &[u8]) -> Self {
        let mut result = Self {
            k: [0x00; 48],
            v: [0x01; 48],
        };
        result.update(&[entropy, nonce].concat());
        result
    }
    pub fn generate(&mut self, len: usize) -> Vec<u8> {
        let mut result = vec![];
        while result.len() < len {
            self.v = hmac384(&self.k, &self.v);
            result.extend(self.v);
        }
        self.update(&[]);
        result.resize(len, 0x00);
        result
    }

    fn update(&mut self, data: &[u8]) {
        self.k = hmac384(&self.k, &[self.v.as_slice(), &[0x00], data].concat());
        self.v = hmac384(&self.k, &self.v);

        if !data.is_empty() {
            self.k = hmac384(&self.k, &[self.v.as_slice(), &[0x01], data].concat());
            self.v = hmac384(&self.k, &self.v);
        }
    }
}

#[test]
fn test_hmac384_drbg() {
    // Test vector from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators#DRBG
    let mut drbg = Hmac384Drbg::new(
        &[
            0xa1, 0xdc, 0x2d, 0xfe, 0xda, 0x4f, 0x3a, 0x11, 0x24, 0xe0, 0xe7, 0x5e, 0xbf, 0xbe,
            0x5f, 0x98, 0xca, 0xc1, 0x10, 0x18, 0x22, 0x1d, 0xda, 0x3f, 0xdc, 0xf8, 0xf9, 0x12,
            0x5d, 0x68, 0x44, 0x7a,
        ],
        &[
            0xba, 0xe5, 0xea, 0x27, 0x16, 0x65, 0x40, 0x51, 0x52, 0x68, 0xa4, 0x93, 0xa9, 0x6b,
            0x51, 0x87,
        ],
    );
    // The NIST test ignores the first call to generate
    drbg.generate(192);
    assert_eq!(
        drbg.generate(192),
        vec![
            0x22, 0x82, 0x93, 0xe5, 0x9b, 0x1e, 0x45, 0x45, 0xa4, 0xff, 0x9f, 0x23, 0x26, 0x16,
            0xfc, 0x51, 0x08, 0xa1, 0x12, 0x8d, 0xeb, 0xd0, 0xf7, 0xc2, 0x0a, 0xce, 0x83, 0x7c,
            0xa1, 0x05, 0xcb, 0xf2, 0x4c, 0x0d, 0xac, 0x1f, 0x98, 0x47, 0xda, 0xfd, 0x0d, 0x05,
            0x00, 0x72, 0x1f, 0xfa, 0xd3, 0xc6, 0x84, 0xa9, 0x92, 0xd1, 0x10, 0xa5, 0x49, 0xa2,
            0x64, 0xd1, 0x4a, 0x89, 0x11, 0xc5, 0x0b, 0xe8, 0xcd, 0x6a, 0x7e, 0x8f, 0xac, 0x78,
            0x3a, 0xd9, 0x5b, 0x24, 0xf6, 0x4f, 0xd8, 0xcc, 0x4c, 0x8b, 0x64, 0x9e, 0xac, 0x2b,
            0x15, 0xb3, 0x63, 0xe3, 0x0d, 0xf7, 0x95, 0x41, 0xa6, 0xb8, 0xa1, 0xca, 0xac, 0x23,
            0x89, 0x49, 0xb4, 0x66, 0x43, 0x69, 0x4c, 0x85, 0xe1, 0xd5, 0xfc, 0xbc, 0xd9, 0xaa,
            0xae, 0x62, 0x60, 0xac, 0xee, 0x66, 0x0b, 0x8a, 0x79, 0xbe, 0xa4, 0x8e, 0x07, 0x9c,
            0xeb, 0x6a, 0x5e, 0xaf, 0x49, 0x93, 0xa8, 0x2c, 0x3f, 0x1b, 0x75, 0x8d, 0x7c, 0x53,
            0xe3, 0x09, 0x4e, 0xea, 0xc6, 0x3d, 0xc2, 0x55, 0xbe, 0x6d, 0xcd, 0xcc, 0x2b, 0x51,
            0xe5, 0xca, 0x45, 0xd2, 0xb2, 0x06, 0x84, 0xa5, 0xa8, 0xfa, 0x58, 0x06, 0xb9, 0x6f,
            0x84, 0x61, 0xeb, 0xf5, 0x1b, 0xc5, 0x15, 0xa7, 0xdd, 0x8c, 0x54, 0x75, 0xc0, 0xe7,
            0x0f, 0x2f, 0xd0, 0xfa, 0xf7, 0x86, 0x9a, 0x99, 0xab, 0x6c
        ],
    );
}

/// Generates a SECP384R1 key from the provided entropy and nonce, using the
/// same mechanism as the Caliptra hardware (HMAC_DRBG).
pub(crate) fn hmac384_drbg_keygen(entropy: &[u8], nonce: &[u8]) -> [u8; 48] {
    let mut drbg = Hmac384Drbg::new(entropy, nonce);
    loop {
        let key = drbg.generate(48).try_into().unwrap();
        if is_valid_privkey(&key) {
            return key;
        }
    }
}

#[test]
fn test_hmac384_drbg_keygen() {
    assert_eq!(
        hmac384_drbg_keygen(
            &[
                0xae, 0x5e, 0x52, 0xd1, 0x4b, 0x0d, 0xef, 0x76, 0xda, 0xe5, 0x7c, 0x2b, 0x07, 0x6c,
                0x2b, 0xf3, 0x05, 0x20, 0xad, 0x5b, 0x85, 0xef, 0x9b, 0xce, 0xb3, 0x30, 0x98, 0x46,
                0x5f, 0xe7, 0xee, 0xb1, 0xa6, 0xf4, 0x5f, 0xcb, 0x19, 0x30, 0x89, 0xcf, 0xd7, 0x96,
                0x8d, 0xad, 0x91, 0xc8, 0x30, 0xbc,
            ],
            &[
                0x13, 0xf7, 0xee, 0x43, 0x52, 0xfd, 0xf9, 0xf9, 0x22, 0xdc, 0x9e, 0xa7, 0x89, 0x46,
                0x36, 0x28, 0x11, 0x20, 0xc9, 0x12, 0x51, 0x75, 0x1b, 0xe8, 0x99, 0xa8, 0xef, 0x7c,
                0x90, 0xbb, 0xca, 0xdf, 0x19, 0x14, 0x57, 0x85, 0x56, 0xf6, 0xe1, 0x1c, 0xaf, 0xce,
                0xd3, 0x38, 0xb9, 0x04, 0x84, 0x4f,
            ]
        ),
        [
            0xc7, 0xfa, 0x34, 0xe9, 0xa7, 0x2f, 0xb5, 0x7f, 0x61, 0x16, 0x94, 0xc3, 0xc8, 0x7f,
            0xe3, 0xf4, 0x2c, 0xe4, 0x1c, 0xac, 0x44, 0x6b, 0x63, 0x63, 0x28, 0xa7, 0xf9, 0x55,
            0x05, 0xd8, 0xf7, 0x42, 0x70, 0x33, 0xcf, 0x37, 0xa1, 0x69, 0x4c, 0x7c, 0x45, 0xfd,
            0x72, 0x48, 0xe0, 0x7c, 0x35, 0xad,
        ]
    );
}

pub(crate) fn pubkey_ecdsa_der(pub_key: &PKey<Public>) -> Vec<u8> {
    let ec_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = pub_key.ec_key().unwrap();
    let mut bn_ctx = BigNumContext::new().unwrap();
    ec_key
        .public_key()
        .to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)
        .unwrap()
}

#[test]
fn test_pubkey_ecdsa_der() {
    const KEY_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE/1JNLIcrWUHx2fSoUEiKohwyP3GTL3TN
k0MGr7vVgOM9kdPLeNtwgZUQ1up40UA+dgfFOoE/sqBWdwQLmO0LQIoHBpqfnQE+
DmQQPrr5e0u3qIopwfq1hXtOLI0nTm2F
-----END PUBLIC KEY-----";

    let key = PKey::public_key_from_pem(KEY_PEM.as_bytes()).unwrap();

    assert_eq!(
        pubkey_ecdsa_der(&key),
        &[
            0x04, 0xff, 0x52, 0x4d, 0x2c, 0x87, 0x2b, 0x59, 0x41, 0xf1, 0xd9, 0xf4, 0xa8, 0x50,
            0x48, 0x8a, 0xa2, 0x1c, 0x32, 0x3f, 0x71, 0x93, 0x2f, 0x74, 0xcd, 0x93, 0x43, 0x06,
            0xaf, 0xbb, 0xd5, 0x80, 0xe3, 0x3d, 0x91, 0xd3, 0xcb, 0x78, 0xdb, 0x70, 0x81, 0x95,
            0x10, 0xd6, 0xea, 0x78, 0xd1, 0x40, 0x3e, 0x76, 0x07, 0xc5, 0x3a, 0x81, 0x3f, 0xb2,
            0xa0, 0x56, 0x77, 0x04, 0x0b, 0x98, 0xed, 0x0b, 0x40, 0x8a, 0x07, 0x06, 0x9a, 0x9f,
            0x9d, 0x01, 0x3e, 0x0e, 0x64, 0x10, 0x3e, 0xba, 0xf9, 0x7b, 0x4b, 0xb7, 0xa8, 0x8a,
            0x29, 0xc1, 0xfa, 0xb5, 0x85, 0x7b, 0x4e, 0x2c, 0x8d, 0x27, 0x4e, 0x6d, 0x85
        ]
    )
}

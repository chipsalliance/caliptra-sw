/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256gcm.rs

Abstract:

    File contains implementation of AES-256 GCM algorithm.

--*/

use crate::{AES_256_BLOCK_SIZE, AES_256_KEY_SIZE};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use aes_gcm::{
    aead::{AeadCore, AeadMutInPlace, OsRng},
    Key,
};

const AES_256_GCM_IV_SIZE: usize = 12;
const AES_256_GCM_TAG_SIZE: usize = 16;

/// Streaming GHASH implementation for AES-256-GCM.
pub struct GHash {
    h: u128,
    state: u128,
}

impl Default for GHash {
    fn default() -> Self {
        Self { h: 0, state: 0 }
    }
}

impl GHash {
    pub fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        // h = encrypt(0)
        let cipher = Aes256::new(key.into());
        let ghash_key = &mut [0u8; AES_256_BLOCK_SIZE];
        cipher.encrypt_block(ghash_key.into());
        let h = u128::from_be_bytes(*ghash_key);
        Self { h, state: 0 }
    }

    pub fn restore(&mut self, state: [u8; AES_256_BLOCK_SIZE]) {
        self.state = u128::from_be_bytes(state);
    }

    pub fn update(&mut self, block: &[u8; AES_256_BLOCK_SIZE]) {
        let block = u128::from_be_bytes(*block);
        self.state ^= block;
        self.state = gf2_128_mul(self.state, self.h);
    }

    pub fn finalize(
        &self,
        key: &[u8; AES_256_KEY_SIZE],
        iv: &[u8; AES_256_GCM_IV_SIZE],
    ) -> [u8; AES_256_BLOCK_SIZE] {
        let mut iv_bytes = [0u8; AES_256_BLOCK_SIZE];
        iv_bytes[..12].copy_from_slice(iv);
        iv_bytes[15] = 1;
        let cipher = Aes256::new(key.into());
        cipher.encrypt_block((&mut iv_bytes).into());
        let e_j0 = u128::from_be_bytes(iv_bytes);
        let output = self.state ^ e_j0;
        output.to_be_bytes()
    }

    pub fn state(&self) -> [u8; AES_256_BLOCK_SIZE] {
        self.state.to_be_bytes()
    }
}

pub enum Aes256Gcm {}

impl Aes256Gcm {
    /// One-shot AES-256-GCM decryption.
    pub fn decrypt(
        key: &[u8; AES_256_KEY_SIZE],
        iv: &[u8; AES_256_GCM_IV_SIZE],
        aad: &[u8],
        tag: &[u8; AES_256_GCM_TAG_SIZE],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let key: &Key<aes_gcm::Aes256Gcm> = key.into();
        let mut cipher = aes_gcm::Aes256Gcm::new(key);
        let mut buffer = ciphertext.to_vec();
        match cipher.decrypt_in_place_detached(iv.into(), aad, &mut buffer, tag.into()) {
            Ok(_) => Some(buffer),
            Err(_) => None,
        }
    }

    /// One-shot AES-256-GCM encryption.
    pub fn encrypt(
        key: &[u8; AES_256_KEY_SIZE],
        iv: Option<&[u8; AES_256_GCM_IV_SIZE]>,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Option<(
        [u8; AES_256_GCM_IV_SIZE],
        Vec<u8>,
        [u8; AES_256_GCM_TAG_SIZE],
    )> {
        let random_iv = aes_gcm::Aes256Gcm::generate_nonce(&mut OsRng).into();
        let iv = iv.unwrap_or(&random_iv);
        let key: &Key<aes_gcm::Aes256Gcm> = key.into();
        let mut cipher = aes_gcm::Aes256Gcm::new(key);
        let mut buffer = plaintext.to_vec();
        match cipher.encrypt_in_place_detached(iv.into(), aad, &mut buffer) {
            Ok(tag) => Some((*iv, buffer, tag.into())),
            Err(_) => None,
        }
    }

    /// Encrypts/decrypts a single block of data at an arbitrary location using AES-256-GCM.
    pub fn crypt_block(
        key: &[u8; AES_256_KEY_SIZE],
        iv: &[u8; AES_256_GCM_IV_SIZE],
        block_num: usize,
        plaintext: &[u8; 16],
    ) -> [u8; 16] {
        let key: &Key<aes_gcm::Aes256Gcm> = key.into();
        let mut cipher = aes_gcm::Aes256Gcm::new(key);
        // TODO: remove this hack and use propert CTR mode for performance.
        let mut buffer = vec![0u8; AES_256_BLOCK_SIZE].repeat(block_num);
        buffer.extend_from_slice(plaintext);
        cipher
            .encrypt_in_place_detached(iv.into(), &[], &mut buffer)
            .unwrap();
        buffer[buffer.len() - AES_256_BLOCK_SIZE..]
            .try_into()
            .unwrap()
    }
}

/// The AES GCM polynomial for GF(2^128), bit-reversed as in the standard.
const GCM_POLY: u128 = 0xE1000000000000000000000000000000;

/// Computes a * b in GF(2^128).
/// See https://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication for some details.
///
/// This is implemented as constant time. It could be faster if we used carryless multiply instructions:
/// https://en.wikipedia.org/wiki/CLMUL_instruction_set
fn gf2_128_mul(mut a: u128, b: u128) -> u128 {
    let mut m = 0;
    for i in 0..128 {
        m ^= ((b >> (127 - i)) & 1) * a;
        let xor_poly = a & 1;
        a >>= 1;
        a ^= xor_poly * GCM_POLY;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::{gf2_128_mul, Aes256Gcm, GHash};

    #[test]
    fn test_gf2_128_mul_inverse() {
        let a = 0x66e94bd4ef8a2c3b884cfa59ca342b2eu128;
        let b = 0x5e2ec746917062882c85b0685353de37u128;
        assert_eq!(gf2_128_mul(a, b), 0xf38cbb1ad69223dcc3457ae5b6b0f885);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let expected_tag = [
            0x9a, 0x4a, 0x25, 0x79, 0x52, 0x93, 0x1, 0xbc, 0xfb, 0x71, 0xc7, 0x8d, 0x40, 0x60,
            0xf5, 0x2c,
        ];
        let expected_ciphertext = [0xe2, 0x7a, 0xbd, 0xd2, 0xd2, 0xa5, 0x3d, 0x2f, 0x13, 0x6b];
        let fixed_iv = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        ];
        let key = [
            0x92, 0xac, 0xe3, 0xe3, 0x48, 0xcd, 0x82, 0x10, 0x92, 0xcd, 0x92, 0x1a, 0xa3, 0x54,
            0x63, 0x74, 0x29, 0x9a, 0xb4, 0x62, 0x9, 0x69, 0x1b, 0xc2, 0x8b, 0x87, 0x52, 0xd1,
            0x7f, 0x12, 0x3c, 0x20,
        ];
        let aad = [0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff];
        let expected_plaintext = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        // from https://github.com/C2SP/wycheproof/blob/master/testvectors/aes_gcm_test.json
        let (iv, ciphertext, tag) =
            Aes256Gcm::encrypt(&key, Some(&fixed_iv), &aad, &expected_plaintext).unwrap();
        assert_eq!(&expected_ciphertext[..], &ciphertext);
        assert_eq!(expected_tag, tag);
        assert_eq!(fixed_iv, iv);

        let plaintext =
            Aes256Gcm::decrypt(&key, &fixed_iv, &aad, &expected_tag, &expected_ciphertext).unwrap();
        assert_eq!(&expected_plaintext[..], plaintext);
    }

    #[test]
    fn test_ghash() {
        let key: [u8; 32] = 0xfeffe9928665731c6d6a8f9467308308u128
            .to_be_bytes()
            .to_vec()
            .repeat(2)
            .try_into()
            .unwrap();
        let mut h = GHash::new(&key.try_into().unwrap());
        let ct: [u128; 4] = [
            0x522dc1f099567d07f47f37a32a84427d,
            0x643a8cdcbfe5c0c97598a2bd2555d1aa,
            0x8cb08e48590dbb3da7b08b1056828838,
            0xc5f61e6393ba7a0abcc9f662898015ad,
        ];
        for c in ct {
            h.update(&c.to_be_bytes());
        }
        h.update(&0x0000_0000_0000_0000_0000_0000_0000_0200u128.to_be_bytes());
        let iv = 0xcafebabefacedbaddecaf888u128.to_be_bytes()[4..16]
            .try_into()
            .unwrap();
        let tag = h.finalize(&key, &iv);
        assert_eq!(tag, 0xb094dac5d93471bdec1a502270e3cc6cu128.to_be_bytes());
    }

    #[test]
    fn test_ghash2() {
        // KEY = f0eaf7b41b42f4500635bc05d9cede11a5363d59a6288870f527bcffeb4d6e04
        // IV = 18f316781077a595c72d4c07
        // CT = 7a1b61009dce6b7cd4d1ea0203b179f1219dd5ce7407e12ea0a4c56c71bb791b
        // AAD = 42cade3a19204b7d4843628c425c2375
        // Tag = 4419180b0b963b7289a4fa3f45c535a3
        // PT = 400fb5ef32083b3abea957c4f068abad50c8d86bbf9351fa72e7da5171df38f9

        const KEY: [u8; 32] = [
            0xf0, 0xea, 0xf7, 0xb4, 0x1b, 0x42, 0xf4, 0x50, 0x6, 0x35, 0xbc, 0x5, 0xd9, 0xce, 0xde,
            0x11, 0xa5, 0x36, 0x3d, 0x59, 0xa6, 0x28, 0x88, 0x70, 0xf5, 0x27, 0xbc, 0xff, 0xeb,
            0x4d, 0x6e, 0x4,
        ];
        let mut h = GHash::new(&KEY.try_into().unwrap());
        let ct: [u128; 3] = [
            0x42cade3a19204b7d4843628c425c2375,
            0x7a1b61009dce6b7cd4d1ea0203b179f1,
            0x219dd5ce7407e12ea0a4c56c71bb791b,
        ];
        for c in ct {
            h.update(&c.to_be_bytes());
        }
        h.update(&0x0000_0000_0000_0080_0000_0000_0000_0100u128.to_be_bytes());
        let iv = 0x18f316781077a595c72d4c07u128.to_be_bytes()[4..16]
            .try_into()
            .unwrap();
        let tag = h.finalize(&KEY, &iv);
        assert_eq!(tag, 0x4419180b0b963b7289a4fa3f45c535a3u128.to_be_bytes());
    }
}

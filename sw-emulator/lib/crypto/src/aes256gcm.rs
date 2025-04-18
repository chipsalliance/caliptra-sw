/*++

Licensed under the Apache-2.0 license.

File Name:

    aes256gcm.rs

Abstract:

    File contains implementation of AES-256 GCM algorithm.

--*/

use crate::AES_256_KEY_SIZE;
use aes_gcm::{
    aead::{AeadCore, AeadMutInPlace, KeyInit, OsRng},
    Key,
};

const AES_256_GCM_IV_SIZE: usize = 12;
const AES_256_GCM_TAG_SIZE: usize = 16;

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
}

#[cfg(test)]
mod tests {
    use crate::Aes256Gcm;

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
}

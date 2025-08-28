/*++

Licensed under the Apache-2.0 license.

File Name:

    mdk.rs

Abstract:

    A vector generator for an MDK.

--*/

use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};

pub const PLAINTEXT: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

pub struct Mdk {
    pub input_key: [u8; 64],
    pub mdk: [u8; 64],
    pub encrypted_data: [u8; 64],
}

impl Default for Mdk {
    fn default() -> Self {
        let mut input_key = [0; 64];
        hmac(&[0; 64], &[0], &mut input_key);

        let mut mdk = [0; 64];
        kdf(&input_key, b"OCP_LOCK_MDK", None, &mut mdk);

        let aes_key = &mdk[0..32];
        let cipher = Cipher::aes_256_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, aes_key, None).unwrap();
        crypter.pad(false);

        // crypter update requires input size + block size.
        let mut encrypted_data_buf = [0u8; 64 + 16];
        let mut count = crypter.update(&PLAINTEXT, &mut encrypted_data_buf).unwrap();
        count += crypter.finalize(&mut encrypted_data_buf[count..]).unwrap();

        let mut encrypted_data = [0u8; 64];
        encrypted_data.copy_from_slice(&encrypted_data_buf[..count]);

        Self {
            input_key,
            mdk,
            encrypted_data,
        }
    }
}

fn hmac(key: &[u8], msg: &[u8], tag: &mut [u8]) {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha512(), &pkey).unwrap();
    signer.update(msg).unwrap();
    signer.sign(tag).unwrap();
}

fn kdf(key: &[u8], label: &[u8], context: Option<&[u8]>, output: &mut [u8; 64]) {
    let ctr_be = 1_u32.to_be_bytes();

    let mut msg = Vec::<u8>::default();
    msg.extend_from_slice(&ctr_be);
    msg.extend_from_slice(label);

    if let Some(context) = context {
        msg.push(0x00);
        msg.extend_from_slice(context);
    }

    hmac(key, &msg, output);
}

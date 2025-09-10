/*++

Licensed under the Apache-2.0 license.

File Name:

    preconditioned_key_extract_gen.rs

Abstract:

    A vector generator for the preconditioned_key_extract function.
    https://chipsalliance.github.io/Caliptra/ocp-lock/specification/HEAD/#fig:preconditioned-key-extract

--*/

use crate::utils::*;

use openssl::symm::{encrypt, Cipher};

pub struct PreconditionedKeyExtractVector {
    pub input_key: Vec<u8>,
    pub input_salt: Vec<u8>,
    pub input_kdf_label: Vec<u8>,
    pub checksum: [u8; 16],    // AES-ECB-Encrypt(input_salt[0..32], 0x0000...)
    pub kdf_output: [u8; 64],  // KDF(input_key, input_kdf_label, checksum)
    pub output_key: [u8; 64],  // HMAC(input_salt, kdf_output)
    pub fingerprint: [u8; 16], // AES-ECB-Encrypt(output_key[0..32], 0x0000...)
}

impl Default for PreconditionedKeyExtractVector {
    fn default() -> PreconditionedKeyExtractVector {
        PreconditionedKeyExtractVector {
            input_key: Vec::new(),
            input_salt: Vec::new(),
            input_kdf_label: Vec::new(),
            checksum: [0; 16],
            kdf_output: [0; 64],
            output_key: [0; 64],
            fingerprint: [0; 16],
        }
    }
}

pub fn gen_vector(
    input_key_length: usize,
    salt_length: usize,
    kdf_length: usize,
) -> PreconditionedKeyExtractVector {
    let cipher = Cipher::aes_256_ecb();
    let mut vec = PreconditionedKeyExtractVector::default();

    vec.input_key.resize(input_key_length, 0);
    vec.input_salt.resize(salt_length, 0);
    vec.input_kdf_label.resize(kdf_length, 0);

    rand_bytes(&mut vec.input_key);
    rand_bytes(&mut vec.input_salt);
    rand_bytes(&mut vec.input_kdf_label);

    let mut input_key = vec![0; 64];
    let mut salt = vec![0; 64];

    hmac(&vec.input_key, &[0], &mut input_key, Digest::SHA512);
    hmac(&vec.input_salt, &[0], &mut salt, Digest::SHA512);

    let aes_key = &salt[0..32];

    let checksum = encrypt(cipher, aes_key, None, &[0u8; 16]).unwrap();
    vec.checksum.copy_from_slice(&checksum[0..16]);

    kdf(
        &input_key,
        &vec.input_kdf_label,
        Some(&vec.checksum),
        &mut vec.kdf_output,
        Digest::SHA512,
    );

    hmac(&salt, &vec.kdf_output, &mut vec.output_key, Digest::SHA512);

    let aes_key = &vec.output_key[0..32];
    let fingerprint = encrypt(cipher, aes_key, None, &[0u8; 16]).unwrap();
    vec.fingerprint.copy_from_slice(&fingerprint[0..16]);

    vec
}

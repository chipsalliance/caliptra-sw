// Licensed under the Apache-2.0 license
use caliptra_image_gen::ImageGeneratorCrypto;
use caliptra_image_openssl::OsslCrypto;
use std::io::{self, ErrorKind};

pub fn sha256_word_reversed(bytes: &[u8]) -> io::Result<[u32; 8]> {
    let crypto = OsslCrypto::default();

    let mut reversed = Vec::<u8>::new();
    for i in 0..bytes.len() / 4 {
        let word = u32::from_le_bytes(bytes[i * 4..][..4].try_into().unwrap());
        reversed.extend_from_slice(&word.swap_bytes().to_le_bytes());
    }

    crypto
        .sha256_digest(&reversed)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))
}

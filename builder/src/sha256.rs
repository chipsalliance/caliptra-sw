// Licensed under the Apache-2.0 license
use caliptra_image_gen::ImageGeneratorCrypto;
use caliptra_image_gen::ImageGeneratorHasher;
use caliptra_image_openssl::OsslCrypto;

pub fn sha256_word_reversed(bytes: &[u8]) -> [u32; 8] {
    let mut sha = OsslCrypto::default().sha256_start();

    for i in 0..bytes.len() / 4 {
        let word = u32::from_le_bytes(bytes[i * 4..][..4].try_into().unwrap());
        sha.update(&word.swap_bytes().to_le_bytes());
    }
    sha.finish()
}

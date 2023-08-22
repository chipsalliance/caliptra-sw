// Licensed under the Apache-2.0 license

pub fn sha256_word_reversed(bytes: &[u8]) -> [u32; 8] {
    let mut sha = openssl::sha::Sha256::new();
    for i in 0..bytes.len() / 4 {
        let word = u32::from_le_bytes(bytes[i * 4..][..4].try_into().unwrap());
        sha.update(&word.swap_bytes().to_le_bytes());
    }
    let result_bytes = sha.finish();
    core::array::from_fn(|i| u32::from_be_bytes(result_bytes[i * 4..][..4].try_into().unwrap()))
}

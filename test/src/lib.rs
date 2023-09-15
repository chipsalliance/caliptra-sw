// Licensed under the Apache-2.0 license

pub mod crypto;
pub mod derive;
pub mod x509;

pub fn swap_word_bytes(words: &[u32]) -> Vec<u32> {
    words.iter().map(|word| word.swap_bytes()).collect()
}
pub fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

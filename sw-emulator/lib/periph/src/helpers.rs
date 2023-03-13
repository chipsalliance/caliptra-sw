/*++

Licensed under the Apache-2.0 license.

File Name:

    helpers.rs

Abstract:

    File contains helper functions

--*/
#![allow(unused)]

pub fn words_from_bytes_le(arr: &[u8; 48]) -> [u32; 12] {
    let mut result = [0u32; 12];
    for i in 0..result.len() {
        result[i] = u32::from_le_bytes(arr[i * 4..][..4].try_into().unwrap())
    }
    result
}

pub fn bytes_from_words_le(arr: &[u32; 12]) -> [u8; 48] {
    let mut result = [0u8; 48];
    for i in 0..arr.len() {
        result[i * 4..][..4].copy_from_slice(&arr[i].to_le_bytes());
    }
    result
}

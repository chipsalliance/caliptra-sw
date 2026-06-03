// Licensed under the Apache-2.0 license.

//! Lightweight LZSS compression and decompression implementation.
//!
//! # LZSS Algorithm Overview
//!
//! LZSS (Lempel-Ziv-Storer-Szymanski) is a lossless data compression algorithm.
//! It replaces repeated substrings with references to a sliding window of history.
//!
//! ## Format Specification
//!
//! The compressed stream consists of blocks. Each block starts with a 1-byte
//! `control` header, followed by up to 8 tokens (literals or references).
//!
//! The 8 bits of the `control` byte (from LSB to MSB) correspond to the 8 tokens:
//! - **Bit = 1 (Literal):** The token is a single raw byte.
//! - **Bit = 0 (Reference):** The token is a 2-byte reference to previously
//!   decompressed data.
//!
//! ### Reference Encoding
//! A reference is encoded as two bytes `(b1, b2)` representing an `offset` and `length`:
//! - **Offset (12 bits):** How far back in the decompressed buffer to start copying.
//!   Reconstructed as `(b1 << 4) | (b2 >> 4)`. Maximum offset is 4095.
//! - **Length (4 bits):** How many bytes to copy.
//!   Reconstructed as `(b2 & 0x0F) + 3`. Range is 3 to 18 bytes.

#[cfg(feature = "std")]
use std::vec::Vec;

/// Decompresses a single literal byte.
///
/// Reads the next byte from `src` and writes it to `dst` at `dst_idx`.
/// Advances both `src_idx` and `dst_idx` by 1.
#[inline(always)]
fn decompress_literal(
    src: &[u8],
    src_idx: &mut usize,
    dst: &mut [u8],
    dst_idx: &mut usize,
) -> bool {
    let val = match src.get(*src_idx) {
        Some(&v) => v,
        None => return false,
    };
    if let Some(d) = dst.get_mut(*dst_idx) {
        *d = val;
    } else {
        return false;
    }
    *dst_idx += 1;
    *src_idx += 1;
    true
}

/// Decompresses a reference to previous data.
///
/// Reads a 2-byte reference from `src`, decodes the offset and length,
/// and copies `length` bytes from `dst` history (at `dst_idx - offset`) to `dst_idx`.
/// Advances `src_idx` by 2 and `dst_idx` by `length`.
#[inline(always)]
fn decompress_reference(
    src: &[u8],
    src_idx: &mut usize,
    dst: &mut [u8],
    dst_idx: &mut usize,
) -> bool {
    let b1 = match src.get(*src_idx) {
        Some(&b) => b as usize,
        None => return false,
    };
    let b2 = match src.get(*src_idx + 1) {
        Some(&b) => b as usize,
        None => return false,
    };
    *src_idx += 2;

    let offset = (b1 << 4) | (b2 >> 4);
    let length = (b2 & 0x0F) + 3;

    if offset == 0 || *dst_idx < offset {
        return false;
    }

    for _ in 0..length {
        if *dst_idx >= dst.len() {
            return false;
        }
        let src_val = match dst.get(*dst_idx - offset) {
            Some(&val) => val,
            None => return false,
        };
        if let Some(d) = dst.get_mut(*dst_idx) {
            *d = src_val;
        } else {
            return false;
        }
        *dst_idx += 1;
    }
    true
}

/// Decompress LZSS compressed data.
///
/// Iterates through the compressed data, reading a control byte for every 8 tokens.
/// The control byte indicates whether each of the next 8 tokens is a literal (bit = 1)
/// or a reference (bit = 0).
///
/// Returns true on success, false if the data is corrupt or dst is too small.
pub fn decompress(src: &[u8], dst: &mut [u8]) -> bool {
    let mut src_idx = 0;
    let mut dst_idx = 0;
    while dst_idx < dst.len() {
        let control = match src.get(src_idx) {
            Some(&c) => c,
            None => return false,
        };
        src_idx += 1;
        for bit in 0..8 {
            if dst_idx >= dst.len() {
                break;
            }
            if (control & (1 << bit)) != 0 {
                if !decompress_literal(src, &mut src_idx, dst, &mut dst_idx) {
                    return false;
                }
            } else {
                if !decompress_reference(src, &mut src_idx, dst, &mut dst_idx) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(feature = "std")]
fn find_longest_match(src: &[u8], src_idx: usize) -> (usize, usize) {
    let mut best_offset = 0;
    let mut best_len = 0;

    let start = if src_idx > 4095 { src_idx - 4095 } else { 0 };

    for i in start..src_idx {
        let mut len = 0;
        while src_idx + len < src.len() && src[i + len] == src[src_idx + len] && len < 18 {
            len += 1;
        }
        if len > best_len {
            best_len = len;
            best_offset = src_idx - i;
        }
    }
    (best_offset, best_len)
}

/// Compress data using LZSS.
///
/// Iterates through the input data, searching for matches in the sliding window
/// (up to 4095 bytes back). If a match of length >= 3 is found, it writes a reference token.
/// Otherwise, it writes a literal token. Every 8 tokens are prefixed with a control byte.
#[cfg(feature = "std")]
pub fn compress(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::new();
    let mut src_idx = 0;

    while src_idx < src.len() {
        let mut control = 0u8;
        let mut token_bytes = Vec::new();

        for bit in 0..8 {
            if src_idx >= src.len() {
                break;
            }

            let (match_offset, match_len) = find_longest_match(src, src_idx);

            if match_len >= 3 {
                // Reference
                let offset = match_offset;
                let length = match_len;

                let b1 = (offset >> 4) as u8;
                let b2 = (((offset & 0x0F) << 4) | ((length - 3) & 0x0F)) as u8;
                token_bytes.push(b1);
                token_bytes.push(b2);

                src_idx += match_len;
            } else {
                // Literal
                control |= 1 << bit;
                token_bytes.push(src[src_idx]);
                src_idx += 1;
            }
        }

        dst.push(control);
        dst.extend(token_bytes);
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let data: &[u8] = &[];
        let compressed = compress(data);
        let mut decompressed = vec![0u8; 0];
        assert!(decompress(&compressed, &mut decompressed));
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_simple() {
        let data = b"Hello World! Hello World! Hello World!";
        let compressed = compress(data);
        let mut decompressed = vec![0u8; data.len()];
        assert!(decompress(&compressed, &mut decompressed));
        assert_eq!(data, &decompressed[..]);
    }

    #[test]
    fn test_repeating() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let compressed = compress(data);
        let mut decompressed = vec![0u8; data.len()];
        assert!(decompress(&compressed, &mut decompressed));
        assert_eq!(data, &decompressed[..]);
    }

    #[test]
    fn test_random() {
        let data = b"abcdefghijklmnopqrstuvwxyz1234567890";
        let compressed = compress(data);
        let mut decompressed = vec![0u8; data.len()];
        assert!(decompress(&compressed, &mut decompressed));
        assert_eq!(data, &decompressed[..]);
    }
}

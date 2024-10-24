/*++

Licensed under the Apache-2.0 license.

File Name:

    der_helper.rs

Abstract:

    Helpers for encoding DER unsigned integers

--*/

/// DER Integer Tag
const DER_INTEGER_TAG: u8 = 0x02;

#[inline(never)]
fn trim_leading_zeros(val: &[u8]) -> &[u8] {
    // Count the leading zeros
    for i in 0..val.len() {
        if val[i] != 0 {
            return &val[i..];
        }
    }
    // If everything is 0, then we need len 1, and 0 as value
    &val[0..1] // single 0
}

#[inline(never)]
fn encode_length(val: &[u8]) -> usize {
    for i in 0..val.len() {
        if val[i] != 0 {
            return val.len() - i + (val[i] >> 7) as usize;
        }
    }
    return 1;
}

/// Compute len of DER encoding of an unsinged integer
#[inline(never)]
pub fn der_uint_len(val: &[u8]) -> Option<usize> {
    let encode_length = encode_length(val);

    let len_field_size = match encode_length {
        0..=127 => 1,
        128.. => trim_leading_zeros(&encode_length.to_be_bytes()).len(),
        _ => None?,
    };

    // Tag + len + int
    Some(1 + len_field_size + encode_length)
}

/// Encode a DER length
#[inline(never)]
pub fn der_encode_len(len: usize, buf: &mut [u8]) -> Option<usize> {
    match len {
        1..=127 => {
            *buf.get_mut(0)? = len as u8;
            Some(1)
        }
        128.. => {
            let encode_len_be_bytes = len.to_be_bytes();
            let len_in_be_bytes = trim_leading_zeros(&encode_len_be_bytes);
            let len = len_in_be_bytes.len();
            *buf.get_mut(0)? = 0x80 | (len as u8);
            buf.get_mut(1..)?
                .get_mut(..len)?
                .copy_from_slice(len_in_be_bytes);
            Some(len + 1)
        }
        _ => None?,
    }
}

/// DER Encode unsigned integer
#[inline(never)]
pub fn der_encode_uint(val: &[u8], buf: &mut [u8]) -> Option<usize> {
    let mut pos = 0;

    *buf.get_mut(pos)? = DER_INTEGER_TAG;
    pos += 1;

    let sub_val = trim_leading_zeros(val);
    let encode_len = encode_length(val);

    pos += der_encode_len(encode_len, buf.get_mut(pos..)?)?;

    if *sub_val.first()? > 127 {
        *buf.get_mut(pos)? = 0;
        pos += 1;
    }

    buf.get_mut(pos..)?
        .get_mut(..sub_val.len())?
        .copy_from_slice(sub_val);
    pos += sub_val.len();

    Some(pos)
}

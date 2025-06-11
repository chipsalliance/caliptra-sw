/*++

Licensed under the Apache-2.0 license.

File Name:

    cmac_kdf.rs

Abstract:

    A KDF implementation that is compliant with SP 800-108 Section 4.1 (KDF in Counter Mode)
    using CMAC as the underlying PRF.


--*/

use crate::{Aes, AesKey, AES_BLOCK_SIZE_BYTES};
use arrayvec::ArrayVec;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_error::{CaliptraError, CaliptraResult};

const MAX_KMAC_INPUT_SIZE: usize = 4096;
const MAX_KMAC_OUTPUT_SIZE: usize = 64;

/// Calculate CMAC-KDF
///
/// # Arguments
///
/// * `aes` - AES driver
/// * `key`- AES key
/// * `label` - Label for the KDF. If `context` is omitted, this is considered
///   the fixed input data.
/// * `context` - Context for KDF. If present, a NULL byte is included between
///   the label and context.
/// * `rounds` - must be 1, 2, 3, or 4. This determines the output size.
///
/// # Returns
/// The output key as an array of bytes. The number of valid bytes is
/// `rounds` * 16.`
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn cmac_kdf(
    aes: &mut Aes,
    key: AesKey,
    label: &[u8],
    context: Option<&[u8]>,
    rounds: u32,
) -> CaliptraResult<[u8; MAX_KMAC_OUTPUT_SIZE]> {
    let input_len = label.len() + context.map(|c| c.len() + 1).unwrap_or(0) + 4;
    if input_len > MAX_KMAC_INPUT_SIZE {
        return Err(CaliptraError::DRIVER_CMAC_KDF_INVALID_SLICE);
    }
    if !(1..=4).contains(&rounds) {
        return Err(CaliptraError::DRIVER_CMAC_KDF_INVALID_ROUNDS);
    }

    let mut input = ArrayVec::<u8, MAX_KMAC_INPUT_SIZE>::new();
    let mut output = [0u8; MAX_KMAC_OUTPUT_SIZE];

    for round in 0..rounds {
        // reset the input for each round
        input.clear();
        // Each round is a 4-byte counter
        input
            .try_extend_from_slice(&(round + 1).to_be_bytes())
            .map_err(|_| CaliptraError::DRIVER_CMAC_KDF_INVALID_SLICE)?;
        input
            .try_extend_from_slice(label)
            .map_err(|_| CaliptraError::DRIVER_CMAC_KDF_INVALID_SLICE)?;
        if let Some(context) = context {
            // separator
            input
                .try_push(0x00)
                .map_err(|_| CaliptraError::DRIVER_CMAC_KDF_INVALID_SLICE)?;
            input
                .try_extend_from_slice(context)
                .map_err(|_| CaliptraError::DRIVER_CMAC_KDF_INVALID_SLICE)?;
        }

        let result = aes.cmac(key, &input)?;
        output[round as usize * AES_BLOCK_SIZE_BYTES..(round as usize + 1) * AES_BLOCK_SIZE_BYTES]
            .copy_from_slice(&result);
    }
    Ok(output)
}

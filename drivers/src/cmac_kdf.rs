/*++

Licensed under the Apache-2.0 license.

File Name:

    cmac_kdf.rs

Abstract:

    A KDF implementation that is compliant with SP 800-108 Section 4.1 (KDF in Counter Mode)
    using CMAC as the underlying PRF.


--*/

use crate::{AesCmacOp, AesKey, LEArray4x16, AES_BLOCK_SIZE_WORDS};
use arrayvec::ArrayVec;
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_error::{CaliptraError, CaliptraResult};

const MAX_KMAC_INPUT_SIZE: usize = 4096;

/// Calculate CMAC-KDF
///
/// # Arguments
///
/// * `aes` - AES driver (implements `AesCmacOp`)
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
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub fn cmac_kdf<A: AesCmacOp>(
    aes: &mut A,
    key: AesKey,
    label: &[u8],
    context: Option<&[u8]>,
    rounds: u32,
) -> CaliptraResult<LEArray4x16> {
    let input_len = label.len() + context.map(|c| c.len() + 1).unwrap_or(0) + 4;
    if input_len > MAX_KMAC_INPUT_SIZE {
        return Err(CaliptraError::DRIVER_CMAC_KDF_INVALID_SLICE);
    }
    if !(1..=4).contains(&rounds) {
        return Err(CaliptraError::DRIVER_CMAC_KDF_INVALID_ROUNDS);
    }

    let mut input = ArrayVec::<u8, MAX_KMAC_INPUT_SIZE>::new();
    let mut output = LEArray4x16::default();

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
        output.0
            [round as usize * AES_BLOCK_SIZE_WORDS..(round as usize + 1) * AES_BLOCK_SIZE_WORDS]
            .copy_from_slice(&result.0);
    }
    Ok(output)
}

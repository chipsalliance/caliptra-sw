/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_kdf.rs

Abstract:

    A KDF implementation that is compliant with SP 800-108.

--*/

use crate::{Hmac384, Hmac384Key, Hmac384Tag, Trng};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_error::CaliptraResult;

/// Calculate HMAC-384-KDF
///
/// If the output is a KV slot, the slot is marked as a valid HMAC key /
/// ECC keygen seed.
///
/// # Arguments
///
/// * `hmac` - HMAC384 context
/// * `key` - HMAC384 key
/// * `label` - Label for the KDF. If `context` is omitted, this is considered
///             the fixed input data.
/// * `context` - Context for KDF. If present, a NULL byte is included between
///               the label and context.
/// * `trng` - TRNG driver instance
/// * `output` - Location to store the output
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn hmac384_kdf(
    hmac: &mut Hmac384,
    key: Hmac384Key,
    label: &[u8],
    context: Option<&[u8]>,
    trng: &mut Trng,
    output: Hmac384Tag,
) -> CaliptraResult<()> {
    let mut hmac_op = hmac.hmac_init(&key, trng, output)?;

    hmac_op.update(&1_u32.to_be_bytes())?;
    hmac_op.update(label)?;

    if let Some(context) = context {
        hmac_op.update(&[0x00])?;
        hmac_op.update(context)?;
    }

    hmac_op.finalize()
}

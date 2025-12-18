/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_kdf.rs

Abstract:

    A KDF implementation that is compliant with SP 800-108 Section 4.1 (KDF in Counter Mode).

--*/

use crate::{Array4x12, Hmac, HmacData, HmacKey, HmacMode, HmacTag, Trng};
use arrayvec::ArrayVec;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_error::CaliptraResult;
use zerocopy::IntoBytes;
use zeroize::ZeroizeOnDrop;

/// OCP LOCK only needs a SHA-384 HKDF
const KDF_HASH_LEN: usize = 48;

#[derive(ZeroizeOnDrop)]
pub struct Okm<const LEN: usize> {
    data: ArrayVec<u8, LEN>,
}

impl<const LEN: usize> Okm<LEN> {
    fn new() -> Self {
        Self {
            data: ArrayVec::new(),
        }
    }

    fn add_slice(&mut self, data: &Array4x12) {
        // data is big endian, so swap it to little endian.
        for chunk in data.as_bytes().chunks(4) {
            for &item in chunk.iter().rev() {
                // It's okay to drop bytes if T exceeds `LEN`
                let _ = self.data.try_push(item);
            }
        }
    }
}

impl<const LEN: usize> AsRef<[u8]> for Okm<LEN> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_bytes()
    }
}

impl<const LEN: usize> From<Okm<LEN>> for [u8; LEN] {
    fn from(value: Okm<LEN>) -> Self {
        let mut out = [0; LEN];
        out.clone_from_slice(&value.data);
        out
    }
}

#[derive(ZeroizeOnDrop)]
struct T {
    data: Array4x12,
}

impl AsRef<[u8]> for T {
    fn as_ref(&self) -> &[u8] {
        self.data.as_bytes()
    }
}

impl AsMut<Array4x12> for T {
    fn as_mut(&mut self) -> &mut Array4x12 {
        &mut self.data
    }
}

impl AsRef<Array4x12> for T {
    fn as_ref(&self) -> &Array4x12 {
        &self.data
    }
}

impl T {
    fn new(data: Array4x12) -> Self {
        Self { data }
    }
}

/// Calculate HMAC-KDF
///
/// If the output is a KV slot, the slot is marked as a valid HMAC key /
/// ECC or MLDSA keygen seed.
///
/// # Arguments
///
/// * `hmac` - HMAC context
/// * `key` - HMAC key
/// * `label` - Label for the KDF. If `context` is omitted, this is considered
///             the fixed input data.
/// * `context` - Context for KDF. If present, a NULL byte is included between
///               the label and context.
/// * `trng` - TRNG driver instance
/// * `output` - Location to store the output
/// * `mode` - HMAC Mode
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn hmac_kdf(
    hmac: &mut Hmac,
    key: HmacKey,
    label: &[u8],
    context: Option<&[u8]>,
    trng: &mut Trng,
    output: HmacTag,
    mode: HmacMode,
) -> CaliptraResult<()> {
    #[cfg(feature = "fips-test-hooks")]
    unsafe {
        crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::HMAC384_FAILURE)?
    }

    let mut hmac_op = hmac.hmac_init(key, trng, output, mode)?;

    hmac_op.update(&1_u32.to_be_bytes())?;
    hmac_op.update(label)?;

    if let Some(context) = context {
        hmac_op.update(&[0x00])?;
        hmac_op.update(context)?;
    }

    hmac_op.finalize()
}

/// Implements `Extract` from https://www.rfc-editor.org/rfc/rfc5869.
/// # Arguments
///
/// * `hmac` - HMAC context
/// * `ikm` - Input keying material. Must be a firmware key.
/// * `salt` - optional salt value (a non-secret random value). If not provided, it is set to a
///            string of HashLen zero
/// * `trng` - TRNG driver instance
/// * `output` - Location to store the output
/// * `mode` - HMAC Mode
///
/// NOTE: Currently only supports a 384 bit hash.
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn hmac_kdf_extract(
    hmac: &mut Hmac,
    ikm: &[u8],
    salt: Option<&Array4x12>,
    trng: &mut Trng,
    prf: &mut Array4x12,
) -> CaliptraResult<()> {
    #[cfg(feature = "fips-test-hooks")]
    unsafe {
        crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::HMAC384_FAILURE)?
    }
    let mode = HmacMode::Hmac384;
    let default_salt = Array4x12::default();
    let salt = HmacKey::Array4x12(salt.unwrap_or(&default_salt));
    hmac.hmac(
        salt,
        HmacData::Slice(ikm),
        trng,
        HmacTag::Array4x12(prf),
        mode,
    )
}

/// Implements `Expand` from https://www.rfc-editor.org/rfc/rfc5869.
/// # Arguments
///
/// * `hmac` - HMAC context
/// * `prk` - a pseudorandom key
/// * `info` - optional context and application specific information
/// * `trng` - TRNG driver instance
/// * `mode` - HMAC Mode
///
/// # Constants
/// * `L` - Length of output keying material
///
/// NOTE: Currently only supports a 384 bit hash.
///
// TODO(clundin): Add CFI support for const generics in function params?
// #[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn hmac_kdf_expand<const L: usize>(
    hmac: &mut Hmac,
    prk: &Array4x12,
    info: Option<&[u8]>,
    trng: &mut Trng,
) -> CaliptraResult<Okm<L>> {
    #[cfg(feature = "fips-test-hooks")]
    unsafe {
        crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::HMAC384_FAILURE)?
    }
    const {
        assert!(
            L <= 255 * KDF_HASH_LEN,
            "You've constructed `hmac_kdf_expand` with an invalid `L` paramater"
        )
    };

    let mode = HmacMode::Hmac384;
    let info = info.unwrap_or(&[]);
    let n = L.div_ceil(KDF_HASH_LEN);

    let mut okm = Okm::new();
    let mut prev_t: Option<T> = None;
    for idx in 1..=n {
        let mut output = T::new(Array4x12::default());
        let mut hmac_op = hmac.hmac_init(
            HmacKey::Array4x12(prk),
            trng,
            HmacTag::Array4x12(output.as_mut()),
            mode,
        )?;

        if let Some(t) = prev_t {
            hmac_op.update(t.as_ref())?;
        } else {
            hmac_op.update(&[])?;
        }

        hmac_op.update(info)?;
        hmac_op.update((idx as u8).as_bytes())?;
        hmac_op.finalize()?;

        // Keep pushing T into OKM until it runs out of space.
        // OKM = first L octets of T
        okm.add_slice(output.as_ref());

        // Save T for next iteration.
        prev_t = Some(output);
    }

    Ok(okm)
}

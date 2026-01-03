/*++

Licensed under the Apache-2.0 license.

File Name:

    key_ladder.rs

Abstract:

    File contains function to manage the firmware's key ladder.

--*/

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_cfi_lib::cfi_assert_eq;
use caliptra_common::crypto::Crypto;
use caliptra_common::keyids::{KEY_ID_FW_KEY_LADDER, KEY_ID_ROM_FMC_CDI};
use caliptra_drivers::{Hmac, HmacMode, KeyId, KeyUsage, Trng};
use caliptra_error::CaliptraResult;

use crate::rom_env::RomEnvNonCrypto;

// This KeyId only holds the LDevID CDI during a specific phase of cold-boot: after
// the LDevID has been derived, but before firmware has been verified and executed.
const LDEVID_CDI: KeyId = KEY_ID_ROM_FMC_CDI;
const LADDER_KEY: KeyId = KEY_ID_FW_KEY_LADDER;

/// Initialize key ladder on cold reset, bound to the lifecycle and debug states.
///
/// # Arguments
///
/// * `env` - ROM Environment
/// * `ladder_len` - Length of ladder to initialize, based on firmware's SVN
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub(crate) fn initialize_key_ladder(
    env: &mut RomEnvNonCrypto,
    ladder_len: u32,
) -> CaliptraResult<()> {
    Crypto::hmac_kdf(
        &mut env.hmac,
        &mut env.trng,
        LDEVID_CDI,
        b"si_init",
        Some(&[
            env.soc_ifc.lifecycle() as u8,
            env.soc_ifc.debug_locked() as u8,
        ]),
        LADDER_KEY,
        HmacMode::Hmac512,
        KeyUsage::default().set_hmac_key_en(),
    )?;

    extend_key_ladder(&mut env.hmac, &mut env.trng, ladder_len)
}

/// Extend key ladder, on cold or update reset.
///
/// # Arguments
///
/// * `hmac` - HMAC helper
/// * `trng` - TRNG helper
/// * `num_iters` - Amount by which to extend the ladder
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub(crate) fn extend_key_ladder(
    hmac: &mut Hmac,
    trng: &mut Trng,
    num_iters: u32,
) -> CaliptraResult<()> {
    let mut i: u32 = 0;

    for _ in 0..num_iters {
        i += 1;
        Crypto::hmac_kdf(
            hmac,
            trng,
            LADDER_KEY,
            b"si_extend",
            None,
            LADDER_KEY,
            HmacMode::Hmac512,
            KeyUsage::default().set_hmac_key_en(),
        )?;
    }

    cfi_assert_eq(num_iters, i);

    Ok(())
}

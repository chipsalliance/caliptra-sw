/*++

Licensed under the Apache-2.0 license.

File Name:

    key_ladder.rs

Abstract:

    File contains key ladder utilities.

--*/

use crate::{handoff::RtHandoff, Drivers, Hmac};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::keyids::KEY_ID_TMP;
use caliptra_drivers::{CaliptraResult, HmacMode, KeyId};
use caliptra_error::CaliptraError;

pub struct KeyLadder;
impl KeyLadder {
    /// Calculates a secret from the key ladder.
    ///
    /// Extends the key ladder the requisite number of times, based on
    /// the given target SVN. Fails if the target SVN is too large. Runs
    /// a final KDF to derive the resulting secret in the destination KV
    /// slot.
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    /// * `target_svn` - SVN to which the derived secret should be bound. May not be larger than the current key ladder's SVN.
    /// * `context` - Diversification value
    /// * `dest` - Key Vault slot to whch the derived secret should be written.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub fn derive_secret(
        drivers: &mut Drivers,
        target_svn: u32,
        context: &[u8],
        dest: KeyId,
    ) -> CaliptraResult<()> {
        let handoff = RtHandoff {
            data_vault: &drivers.persistent_data.get().rom.data_vault,
            fht: &drivers.persistent_data.get().rom.fht,
        };

        let key_ladder_svn = handoff.fw_min_svn();
        let key_ladder_kv = handoff.fw_key_ladder()?;

        // Don't allow stomping over the key ladder secret.
        if dest == key_ladder_kv {
            // If this occurs it is an internal programming error within Caliptra firmware.
            Err(CaliptraError::RUNTIME_INTERNAL)?;
        }

        if target_svn > key_ladder_svn {
            Err(CaliptraError::RUNTIME_KEY_LADDER_TARGET_SVN_TOO_LARGE)?;
        }

        let num_iters = key_ladder_svn - target_svn;

        let secret_source = if num_iters == 0 {
            key_ladder_kv
        } else {
            let mut src_slot = key_ladder_kv;
            for _ in 0..num_iters {
                // First time through, KDF from key_ladder_kv into KEY_ID_TMP;
                // all other times through, stay in KEY_ID_TMP.
                Hmac::hmac_kdf(
                    drivers,
                    src_slot,
                    b"si_extend",
                    None,
                    HmacMode::Hmac512,
                    KEY_ID_TMP,
                )?;
                src_slot = KEY_ID_TMP;
            }
            KEY_ID_TMP
        };

        Hmac::hmac_kdf(
            drivers,
            secret_source,
            b"chain_output",
            Some(context),
            HmacMode::Hmac512,
            dest,
        )?;

        if secret_source == KEY_ID_TMP && dest != KEY_ID_TMP {
            drivers.key_vault.erase_key(KEY_ID_TMP).unwrap();
        }

        Ok(())
    }
}

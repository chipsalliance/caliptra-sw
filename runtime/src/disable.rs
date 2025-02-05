/*++

Licensed under the Apache-2.0 license.

File Name:

    disable.rs

Abstract:

    File contains DisableAttestation mailbox command.

--*/

use crate::Drivers;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::MailboxResp;
use caliptra_drivers::{
    hmac_kdf, Array4x12, CaliptraError, CaliptraResult, Ecc384Seed, HmacKey, HmacMode, KeyReadArgs,
    KeyUsage, KeyWriteArgs,
};
use dpe::U8Bool;

pub struct DisableAttestationCmd;
impl DisableAttestationCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        Self::erase_keys(drivers)?;
        Self::zero_rt_cdi(drivers)?;
        Self::generate_dice_key(drivers)?;
        drivers.persistent_data.get_mut().attestation_disabled = U8Bool::new(true);
        Ok(MailboxResp::default())
    }

    /// Erase the RT CDI and RT Private Key from the key vault
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn erase_keys(drivers: &mut Drivers) -> CaliptraResult<()> {
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        drivers.key_vault.erase_key(key_id_rt_cdi)?;
        drivers.key_vault.erase_key(key_id_rt_priv_key)
    }

    /// Set CDI key vault slot to a KDF of a buffer of 0s.
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn zero_rt_cdi(drivers: &mut Drivers) -> CaliptraResult<()> {
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        hmac_kdf(
            &mut drivers.hmac,
            HmacKey::Array4x12(&Array4x12::default()),
            b"zero_rt_cdi",
            None,
            &mut drivers.trng,
            KeyWriteArgs::new(
                key_id_rt_cdi,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en()
                    .set_mldsa_key_gen_seed_en(),
            )
            .into(),
            HmacMode::Hmac384,
        )?;

        Ok(())
    }

    /// Generate a new RT alias key from the zeroed-out RT CDI. Since this new
    /// key is derived from an empty CDI slot it will not match the key that was
    /// certified in the RT alias cert.
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn generate_dice_key(drivers: &mut Drivers) -> CaliptraResult<()> {
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        let pub_key = drivers.ecc384.key_pair(
            &Ecc384Seed::Key(KeyReadArgs::new(key_id_rt_cdi)),
            &Array4x12::default(),
            &mut drivers.trng,
            KeyWriteArgs::new(
                key_id_rt_priv_key,
                KeyUsage::default().set_ecc_private_key_en(),
            )
            .into(),
        )?;
        drivers.persistent_data.get_mut().fht.rt_dice_pub_key = pub_key;

        Ok(())
    }
}

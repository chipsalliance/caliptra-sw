/*++

Licensed under the Apache-2.0 license.

File Name:

    disable.rs

Abstract:

    File contains DisableAttestation mailbox command.

--*/

use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::keyids::KEY_ID_EXPORTED_DPE_CDI;
use caliptra_drivers::{
    hmac384_kdf, Array4x12, CaliptraResult, Ecc384Seed, Hmac384Key, Hmac384Tag, KeyId, KeyReadArgs,
    KeyUsage, KeyWriteArgs,
};
use dpe::U8Bool;

pub struct DisableAttestationCmd;
impl DisableAttestationCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        Self::erase_keys(drivers)?;
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(&drivers.persistent_data.get().fht)?;
        Self::zero_ecc384_cdi(drivers, key_id_rt_cdi)?;
        Self::zero_ecc384_cdi(drivers, KEY_ID_EXPORTED_DPE_CDI)?;
        Self::generate_dice_key(drivers)?;
        #[cfg(feature = "mldsa_attestation")]
        Self::zero_pq_devid_cdi(drivers)?;
        drivers.persistent_data.get_mut().attestation_disabled = U8Bool::new(true);
        Ok(())
    }

    /// Erase the RT CDI and RT Private Key from the key vault
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn erase_keys(drivers: &mut Drivers) -> CaliptraResult<()> {
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(&drivers.persistent_data.get().fht)?;
        let key_id_rt_priv_key =
            Drivers::get_key_id_rt_priv_key(&drivers.persistent_data.get().fht)?;
        drivers.key_vault.erase_key(key_id_rt_cdi)?;
        drivers.key_vault.erase_key(key_id_rt_priv_key)
    }

    /// Set CDI key vault slot to a KDF of a buffer of 0s.
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    /// * `key` - KeyId of the ECC384 CDI key vault slot to zero
    fn zero_ecc384_cdi(drivers: &mut Drivers, key: KeyId) -> CaliptraResult<()> {
        let key = KeyWriteArgs::new(
            key,
            KeyUsage::default()
                .set_hmac_key_en()
                .set_ecc_key_gen_seed_en(),
        );
        Self::zero_cdi(drivers, key.into())
    }

    /// Set CDI key vault slot or output buffer to a KDF of a buffer of 0s.
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    /// * `output` - The key vault slot or output buffer to write the zeroed CDI to
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn zero_cdi(drivers: &mut Drivers, output: Hmac384Tag) -> CaliptraResult<()> {
        hmac384_kdf(
            &mut drivers.hmac384,
            Hmac384Key::Array4x12(&Array4x12::default()),
            b"zero_cdi",
            None,
            &mut drivers.trng,
            output,
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn generate_dice_key(drivers: &mut Drivers) -> CaliptraResult<()> {
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(&drivers.persistent_data.get().fht)?;
        let key_id_rt_priv_key =
            Drivers::get_key_id_rt_priv_key(&drivers.persistent_data.get().fht)?;
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

    /// Set CDI bytes to a KDF of a buffer of 0s.
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    #[cfg(feature = "mldsa_attestation")]
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn zero_pq_devid_cdi(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut out = Array4x12::default();
        Self::zero_cdi(drivers, (&mut out).into())?;

        drivers
            .persistent_data
            .get_mut()
            .erase_pq_devid_cdi(out.into());
        Ok(())
    }
}

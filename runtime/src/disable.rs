// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::keyids::{KEY_ID_RT_CDI, KEY_ID_RT_PRIV_KEY};
use caliptra_common::mailbox_api::MailboxResp;
use caliptra_drivers::{
    hmac384_kdf, Array4x12, CaliptraError, CaliptraResult, Hmac384Key, KeyReadArgs, KeyUsage,
    KeyWriteArgs,
};

pub struct DisableAttestationCmd;
impl DisableAttestationCmd {
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        drivers.key_vault.erase_key(KEY_ID_RT_CDI)?;
        drivers.key_vault.erase_key(KEY_ID_RT_PRIV_KEY)?;

        Self::zero_rt_cdi(drivers)?;
        Self::generate_dice_key(drivers)?;
        drivers.attestation_disabled = true;
        Ok(MailboxResp::default())
    }

    // Set CDI key vault slot to an HMAC of a buffer of 0s.
    fn zero_rt_cdi(drivers: &mut Drivers) -> CaliptraResult<()> {
        hmac384_kdf(
            &mut drivers.hmac384,
            Hmac384Key::Array4x12(&Array4x12::default()),
            b"zero_rt_cdi",
            None,
            &mut drivers.trng,
            KeyWriteArgs::new(
                KEY_ID_RT_CDI,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )?;

        Ok(())
    }

    // Dice key is derived from an empty CDI slot so it will not match the key that was certified in the rt_alias cert.
    fn generate_dice_key(drivers: &mut Drivers) -> CaliptraResult<()> {
        hmac384_kdf(
            &mut drivers.hmac384,
            KeyReadArgs::new(KEY_ID_RT_CDI).into(),
            b"dice_keygen",
            None,
            &mut drivers.trng,
            KeyWriteArgs::new(
                KEY_ID_RT_PRIV_KEY,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )?;

        Ok(())
    }
}

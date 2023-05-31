/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias.rs

Abstract:

    Alias RT DICE Layer & PCR extension

--*/
use crate::flow::crypto::Crypto;
use crate::flow::dice::{DiceInput, DiceLayer, DiceOutput};
use crate::flow::pcr::{extend_current_pcr, extend_journey_pcr};
use crate::flow::tci::Tci;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::cprintln;
use caliptra_drivers::{
    okref, CaliptraError, CaliptraResult, Hmac384Data, Hmac384Key, KeyId, KeyReadArgs,
};
const SHA384_HASH_SIZE: usize = 48;

#[derive(Default)]
pub struct RtAliasLayer {}

impl DiceLayer for RtAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(
        _env: &mut FmcEnv,
        _hand_off: &HandOff,
        _input: &DiceInput,
    ) -> CaliptraResult<DiceOutput> {
        // Derive CDI
        let _cdi = Self::derive_cdi(_env, _hand_off, _input.cdi);
        // TODO : implement derivation.
        Err(CaliptraError::FMC_RT_ALIAS_UNIMPLEMENTED)
    }
}

impl RtAliasLayer {
    #[inline(never)]
    pub fn run(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        cprintln!("[art] Extend PCRs");
        Self::extend_pcrs(env, hand_off)?;
        Ok(())
    }

    /// Extend current and journey PCRs
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    pub fn extend_pcrs(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        extend_current_pcr(env, hand_off)?;
        extend_journey_pcr(env, hand_off)?;
        Ok(())
    }

    /// Permute Composite Device Identity (CDI) using Rt TCI and Image Manifest Digest
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `hand_off` - HandOff
    /// * `cdi` - Key Slot to store the generated CDI
    ///
    /// # Returns
    ///
    /// * `KeyId` - KeySlot containing the DICE CDI
    fn derive_cdi(env: &mut FmcEnv, hand_off: &HandOff, cdi: KeyId) -> CaliptraResult<KeyId> {
        // Get the HMAC Key from CDI
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));

        // Compose FMC TCI (1. RT TCI, 2. Image Manifest Digest)
        let mut tci = [0u8; 2 * SHA384_HASH_SIZE];
        let rt_tci = Tci::rt_tci(env, hand_off);
        let rt_tci: [u8; 48] = okref(&rt_tci)?.into();
        tci[0..SHA384_HASH_SIZE].copy_from_slice(&rt_tci);

        let image_manifest_digest: Result<_, CaliptraError> =
            Tci::image_manifest_digest(env, hand_off);
        let image_manifest_digest: [u8; 48] = okref(&image_manifest_digest)?.into();
        tci[SHA384_HASH_SIZE..2 * SHA384_HASH_SIZE].copy_from_slice(&image_manifest_digest);

        // Permute CDI from FMC TCI
        let data = Hmac384Data::Slice(&tci);
        let cdi = Crypto::hmac384_mac(env, key, data, cdi)?;
        Ok(cdi)
    }
}

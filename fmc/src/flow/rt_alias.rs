/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias.rs

Abstract:

    Alias RT DICE Layer & PCR extension

--*/
use crate::flow::dice::{DiceInput, DiceLayer, DiceOutput};
use crate::flow::pcr::{extend_current_pcr, extend_journey_pcr};
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::cprintln;
use caliptra_drivers::CaliptraResult;

#[derive(Default)]
pub struct RtAliasLayer {}

impl DiceLayer for RtAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(_env: &FmcEnv, _input: &DiceInput) -> CaliptraResult<DiceOutput> {
        // TODO : implement derivation.
        Err(0xdead)
    }
}

impl RtAliasLayer {
    #[inline(never)]
    pub fn run(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        cprintln!("[art] Extend PCRs");
        Self::extend_pcrs(env, hand_off)?;
        Ok(())
    }

    /// Extend current and journey PCRs
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    pub fn extend_pcrs(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        extend_current_pcr(env, hand_off)?;
        extend_journey_pcr(env, hand_off)?;
        Ok(())
    }
}

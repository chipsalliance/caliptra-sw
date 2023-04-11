/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias.rs

Abstract:

    Crypto helper routines

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
    fn derive(env: &FmcEnv, _input: &DiceInput) -> CaliptraResult<DiceOutput> {
        // At this point PCR0 & PCR1 must have the same value. We use the value
        // of PCR1 as the data for deriving the CDI
        let _measurement = env
            .pcr_bank()
            .map(|p| p.read_pcr(caliptra_drivers::PcrId::PcrId1));

        // TODO : implement derivation.
        // Derive the Rt layer CDI.
        //let cdi = Self::derive_cdi(env, _measurement, input.cdi)?;
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

    // Derive Composite Device Identity (CDI) from accumulated measurements.
    //
    // # Arguments
    //
    // * `env` - FMC Environment
    // * `pcr_meas` - Array containing the measurements read from the PCR.
    // * `cdi` - Key Slot to store the generated CDI
    //
    // # Returns
    //
    // * `KeyId` - KeySlot containing the DICE CDI
    //fn derive_cdi(env: &FmcEnv, pcr_measurement: Array4x12, cdi: KeyId) -> CaliptraResult<KeyId> {
    //    Err(0xdead)
    //}
}

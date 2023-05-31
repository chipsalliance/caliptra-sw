/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains execution routines for extending current and journey PCRs.

Environment:

    FMC

Note:

    PCR2 - Journey PCR unlocked and cleared on cold reset
    PCR3 - Current PCR unlocked and cleared on any reset

--*/
use crate::flow::tci::Tci;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_drivers::{okref, CaliptraResult, PcrId};

const CURRENT_PCR: PcrId = PcrId::PcrId3;
const JOURNEY_PCR: PcrId = PcrId::PcrId2;

/// Extend current PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn extend_current_pcr(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
    extend_pcr_common(env, hand_off, CURRENT_PCR)
}

/// Extend journey PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn extend_journey_pcr(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
    extend_pcr_common(env, hand_off, JOURNEY_PCR)
}

/// Extend common data into PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
/// * `pcr_id` - PCR slot to extend the data into
fn extend_pcr_common(env: &mut FmcEnv, hand_off: &HandOff, pcr_id: PcrId) -> CaliptraResult<()> {
    // Extend RT TCI (Hash over runtime code)
    let rt_tci = Tci::rt_tci(env, hand_off);
    let rt_tci: [u8; 48] = okref(&rt_tci)?.into();
    env.pcr_bank.extend_pcr(pcr_id, &mut env.sha384, &rt_tci)?;

    // Extend FW Image Manifest
    let manifest_digest = Tci::image_manifest_digest(env, hand_off);
    let manifest_digest: [u8; 48] = okref(&manifest_digest)?.into();
    env.pcr_bank
        .extend_pcr(pcr_id, &mut env.sha384, &manifest_digest)?;

    Ok(())
}

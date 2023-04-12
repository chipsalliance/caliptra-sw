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

use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_drivers::{CaliptraResult, PcrId};

const CURRENT_PCR: PcrId = PcrId::PcrId3;
const JOURNEY_PCR: PcrId = PcrId::PcrId2;

/// Extend current PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn extend_current_pcr(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
    extend_pcr_common(env, hand_off, CURRENT_PCR)
}

/// Extend journey PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn extend_journey_pcr(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
    extend_pcr_common(env, hand_off, JOURNEY_PCR)
}

/// Extend common data into PCR
///
/// # Arguments
///
/// * `env` - FMC Environment
/// * `pcr_id` - PCR slot to extend the data into
fn extend_pcr_common(env: &FmcEnv, hand_off: &HandOff, pcr_id: PcrId) -> CaliptraResult<()> {
    let pcr_bank = env.pcr_bank();
    let sha = env.sha384();

    // Extend RT TCI (Hash over runtime code)
    let data = hand_off.rt_tci(env);
    let bytes: &[u8; 48] = &data.into();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    // Extend RT SVN
    let data = hand_off.rt_svn(env);
    let bytes = &data.to_le_bytes();
    sha.map(|s| pcr_bank.map(|p| p.extend_pcr(pcr_id, s, bytes)))?;

    Ok(())
}

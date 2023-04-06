/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains execution routines for extending PCR0 & PCR1

Environment:

    ROM

Note:

    PCR0 - Journey PCR unlocked and cleared on cold reset
    PCR1 - Current PCR unlocked and cleared on any reset

--*/

use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_drivers::{CaliptraResult, PcrId};

/// Extend PCR0
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn extend_pcr0(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
    extend_pcr_common(env, hand_off, PcrId::PcrId0)
}

/// Extend PCR1
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn extend_pcr1(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
    extend_pcr_common(env, hand_off, PcrId::PcrId1)
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

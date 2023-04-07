/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains execution routines for extending PCR0

Environment:

    ROM

Note:

    PCR0 - Journey PCR unlocked and cleared on cold reset

--*/

use crate::rom_env::RomEnv;
use caliptra_drivers::{Array4x12, CaliptraResult};

/// Extend PCR0
///
/// # Arguments
///
/// * `env` - ROM Environment
/// * `digest` - Digest to extend
pub fn extend_pcr0(env: &RomEnv, digest: Array4x12) -> CaliptraResult<()> {
    let pcr_bank = env.pcr_bank();
    let pcr0_id = caliptra_drivers::PcrId::PcrId0;

    // Clear the PCR
    pcr_bank.map(|p| p.erase_pcr(pcr0_id))?;

    // Lock the PCR from clear
    pcr_bank.map(|p| p.set_pcr_lock(pcr0_id));

    // Extend the PCR
    let digest: &[u8; 48] = &digest.into();
    env.sha384()
        .map(|s| pcr_bank.map(|p| p.extend_pcr(pcr0_id, s, digest)))?;

    Ok(())
}

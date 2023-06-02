/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various RT Flows.

--*/

mod cold_reset;
mod unknown_reset;
mod update_reset;
mod warm_reset;

mod crypto;
pub mod dice;
mod pcr;
mod rt_alias;
mod tci;
mod x509;

use crate::flow::rt_alias::RtAliasLayer;

use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::KeyId;
use caliptra_drivers::ResetReason;

pub const KEY_ID_FMC_PRIV_KEY: KeyId = KeyId::KeyId5;

/// Execute FMC Flows based on reset resason
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn run(env: &mut FmcEnv, hand_off: &mut HandOff) -> CaliptraResult<()> {
    let _ = RtAliasLayer::run(env, hand_off);
    // Retrieve reset reason.
    let reset_reason = env.soc_ifc.reset_reason();
    match reset_reason {
        // Cold Reset Flow
        ResetReason::ColdReset => cold_reset::ColdResetFlow::run(env, hand_off),

        // Warm Reset Flow
        ResetReason::WarmReset => warm_reset::WarmResetFlow::run(env, hand_off),

        // Update Reset Flow
        ResetReason::UpdateReset => update_reset::UpdateResetFlow::run(env, hand_off),

        // Unknown/Spurious Reset Flow
        _ => unknown_reset::UnknownResetFlow::run(env, hand_off),
    }
}

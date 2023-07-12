/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various RT Flows.

--*/

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

pub const KEY_ID_TMP: KeyId = KeyId::KeyId3;
pub const KEY_ID_RT_CDI: KeyId = KeyId::KeyId4;
pub const KEY_ID_RT_PRIV_KEY: KeyId = KeyId::KeyId5;

/// Execute FMC Flows based on reset resason
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn run(env: &mut FmcEnv, hand_off: &mut HandOff) -> CaliptraResult<()> {
    RtAliasLayer::run(env, hand_off)
}

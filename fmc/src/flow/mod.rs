/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various RT Flows.

--*/

mod crypto;
pub mod dice;
mod hash_chain;
mod pcr;
mod rt_alias;
mod tci;
mod x509;

use crate::flow::hash_chain::HashChain;
use crate::flow::rt_alias::RtAliasLayer;

use crate::fmc_env::FmcEnv;
use crate::hand_off::HandOff;
use caliptra_drivers::CaliptraResult;

/// Execute FMC Flows based on reset resason
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn run(env: &mut FmcEnv) -> CaliptraResult<()> {
    RtAliasLayer::run(env)?;
    HashChain::derive(env)?;

    env.key_vault.set_key_use_lock(HandOff::fmc_cdi(env));

    Ok(())
}

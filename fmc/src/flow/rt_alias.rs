/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias.rs

Abstract:

    Crypto helper routines

--*/

use crate::flow::dice::{DiceInput, DiceLayer, DiceOutput};
use crate::fmc_env::FmcEnv;
use caliptra_drivers::CaliptraResult;

#[derive(Default)]
pub struct RtAliasLayer {}

impl DiceLayer for RtAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(env: &FmcEnv, _: &DiceInput) -> CaliptraResult<DiceOutput> {
        Self::extend_pcrs(env)?;
        Err(0)
    }
}

impl RtAliasLayer {
    /// Extend PCR0
    ///
    /// PCR0 is a journey PCR and is locked for clear on cold boot.
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    pub fn extend_pcrs(_env: &FmcEnv) -> CaliptraResult<()> {
        // TODO
        Ok(())
    }
}

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
    fn derive(_: &FmcEnv, _: &DiceInput) -> CaliptraResult<DiceOutput> {
        Err(0)
    }
}

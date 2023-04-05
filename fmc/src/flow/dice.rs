/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    File contains interface and definitions for common Device Identity
    Composition Engine (DICE) functionality.

--*/

use crate::fmc_env::FmcEnv;
use caliptra_drivers::{CaliptraResult, KeyId};

use caliptra_common::crypto::Ecc384KeyPair;

/// DICE Layer Input
#[derive(Debug)]
pub struct DiceInput {
    /// Composite Device Identity (CDI)
    ///
    /// This field will act as an input and output for the CDI.
    /// * On input, this field will be used as a key for CDI derivation function.
    /// * On output, this field will hold the CDI of the current layer.
    pub cdi: KeyId,

    /// Authority Key Pair
    pub auth_key_pair: Ecc384KeyPair,

    /// Authority Serial Number
    pub auth_sn: [u8; 64],

    /// Authority Key Identifier
    pub auth_key_id: [u8; 20],

    /// Subject Private Key
    ///
    /// Layer Private Key will be generated in the Key Vault slot specified
    /// by this slot
    pub subj_priv_key: KeyId,

    /// Temporary KeyId used during DICE derivations
    pub uds_key: KeyId,

    /// Field entropy key.
    pub fe_key: KeyId,
}

/// DICE Layer Output
#[derive(Debug)]
pub struct DiceOutput {
    /// CDI generated for this layer
    ///
    /// This field points to the Key Vault slot that holds the CDI for the
    /// current layer
    pub cdi: KeyId,

    /// Subject key pair for this layer
    pub subj_key_pair: Ecc384KeyPair,

    /// Subject Serial Number
    pub subj_sn: [u8; 64],

    /// Subject Key Identifier
    pub subj_key_id: [u8; 20],
}

/// DICE Layer Interface
pub trait DiceLayer {
    /// Perform derivations for the DICE layer
    ///
    /// # Arguments
    ///
    /// * `env`   - FMC Environment
    /// * `input` - DICE layer input
    ///
    /// # Returns
    ///
    /// * `DiceOutput` - DICE layer output
    fn derive(env: &FmcEnv, input: &DiceInput) -> CaliptraResult<DiceOutput>;
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    File contains interface and definitions for common Device Identity
    Composition Engine (DICE) functionality.

--*/

use crate::rom_env::RomEnv;
use caliptra_drivers::{CaliptraResult, Ecc384PubKey, KeyId};

use super::crypto::Ecc384KeyPair;

/// DICE Layer Input
#[derive(Debug)]
pub struct DiceInput {
    /// Authority Key Pair
    pub auth_key_pair: Ecc384KeyPair,

    /// Authority Serial Number
    pub auth_sn: [u8; 64],

    /// Authority Key Identifier
    pub auth_key_id: [u8; 20],
}

impl DiceInput {
    pub fn default() -> Self {
        DiceInput {
            auth_key_pair: Ecc384KeyPair {
                priv_key: KeyId::KeyId0,
                pub_key: Ecc384PubKey::default(),
            },
            auth_sn: [0u8; 64],
            auth_key_id: [0u8; 20],
        }
    }
}

/// DICE Layer Output
#[derive(Debug)]
pub struct DiceOutput {
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
    /// * `env`   - ROM Environment
    /// * `input` - DICE layer input
    ///
    /// # Returns
    ///
    /// * `DiceOutput` - DICE layer output
    fn derive(env: &RomEnv, input: &DiceInput) -> CaliptraResult<DiceOutput>;
}

/// Compose two dice layers into one
///
/// # Arguments
///
/// * `f` - Dice Layer 1
/// * `g` - Dice Layer 2
pub fn compose_layers<F, G>(
    f: F,
    g: G,
) -> impl Fn(&RomEnv, &DiceInput) -> CaliptraResult<DiceOutput>
where
    F: Fn(&RomEnv, &DiceInput) -> CaliptraResult<DiceOutput>,
    G: Fn(&RomEnv, &DiceInput) -> CaliptraResult<DiceOutput>,
{
    move |env, i| {
        let output = f(env, i)?;
        let input = DiceInput {
            auth_key_pair: output.subj_key_pair,
            auth_sn: output.subj_sn,
            auth_key_id: output.subj_key_id,
        };
        g(env, &input)
    }
}

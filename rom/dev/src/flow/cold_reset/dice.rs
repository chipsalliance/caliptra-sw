/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    File contains interface and definitions for common Device Identity
    Composition Engine (DICE) functionality.

--*/

use super::crypto::Ecc384KeyPair;

/// DICE Layer Input
#[derive(Debug)]
pub struct DiceInput<'a> {
    /// Authority Key Pair
    pub auth_key_pair: &'a Ecc384KeyPair,

    /// Authority Serial Number
    pub auth_sn: &'a [u8; 64],

    /// Authority Key Identifier
    pub auth_key_id: &'a [u8; 20],
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

impl DiceOutput {
    pub fn zeroize(&mut self) {
        self.subj_key_pair.zeroize();
        self.subj_sn.fill(0);
        self.subj_key_id.fill(0);
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    File contains interface and definitions for common Device Identity
    Composition Engine (DICE) functionality.

--*/

use caliptra_drivers::KeyId;

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
}

/// DICE Layer Output
#[derive(Debug)]
pub struct DiceOutput {
    /// CDI
    pub cdi: KeyId,
    /// Subject key pair for this layer
    pub subj_key_pair: Ecc384KeyPair,

    /// Subject Serial Number
    pub subj_sn: [u8; 64],

    /// Subject Key Identifier
    pub subj_key_id: [u8; 20],
}

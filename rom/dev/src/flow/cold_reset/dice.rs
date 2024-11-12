/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    File contains interface and definitions for common Device Identity
    Composition Engine (DICE) functionality.

--*/

use super::crypto::{Ecc384KeyPair, MlDsaKeyPair};
use zeroize::Zeroize;

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
#[derive(Debug, Zeroize)]
pub struct DiceOutput {
    /// ECC Subject key pair for this layer
    pub ecc_subj_key_pair: Ecc384KeyPair,

    /// ECC Subject Serial Number
    pub ecc_subj_sn: [u8; 64],

    /// ECC Subject Key Identifier
    pub ecc_subj_key_id: [u8; 20],

    /// MLDSA Subject key pair for this layer
    pub mldsa_subj_key_pair: MlDsaKeyPair,

    /// MLDSA Subject Serial Number
    pub mldsa_subj_sn: [u8; 64],

    /// MLDSA Subject Key Identifier
    pub mldsa_subj_key_id: [u8; 20],
}

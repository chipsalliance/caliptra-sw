/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/
use caliptra_drivers::{Ecc384PubKey, KeyId};
/// DICE  Layer Key Pair
#[derive(Debug)]
pub struct Ecc384KeyPair {
    /// Private Key
    pub priv_key: KeyId,

    /// Public Key
    pub pub_key: Ecc384PubKey,
}

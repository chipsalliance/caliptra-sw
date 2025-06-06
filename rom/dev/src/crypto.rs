/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/

use caliptra_drivers::Ecc384Signature;
use caliptra_x509::Ecdsa384Signature;

/// ECDSA-384 Signature Adapter
///
pub trait Ecdsa384SignatureAdapter {
    /// Convert to ECDSA Signature
    fn to_ecdsa(&self) -> Ecdsa384Signature;
}

impl Ecdsa384SignatureAdapter for Ecc384Signature {
    /// Convert to ECDSA Signatuure
    fn to_ecdsa(&self) -> Ecdsa384Signature {
        Ecdsa384Signature {
            r: (&self.r).into(),
            s: (&self.s).into(),
        }
    }
}

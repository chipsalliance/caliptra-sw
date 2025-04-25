/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for ECC-384 cryptography operations.

--*/

use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Ecc384, Ecc384PrivKeyIn, Ecc384PrivKeyOut,
    Ecc384PubKey, Trng,
};

// From NIST
// CAVS 14.1
// ECC CDH Primitive (SP800-56A Section 5.7.1.2) Test Information for "testecccdh"
// Curves tested: Curves tested: P-192 P-224 P-256 P-384 P-521 K-163 K-233 K-283 K-409 K-571 B-163 B-233 B-283 B-409 B-571
// Generated on Mon Nov 19 10:52:17 2012
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhvs.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip

// [P-384]

// COUNT = 0
// QCAVSx = a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066
// QCAVSy = ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a
// dIUT = 3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1
// QIUTx = 9803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f
// QIUTy = ba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99
// ZIUT = 5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1

const A_PRIV_KEY: Array4x12 = Array4x12::new([
    0x3cc3122a, 0x68f0d950, 0x27ad38c0, 0x67916ba0, 0xeb8c3889, 0x4d22e1b1, 0x5618b681, 0x8a661774,
    0xad463b20, 0x5da88cf6, 0x99ab4d43, 0xc9cf98a1,
]);
const B_PUB_KEY: Ecc384PubKey = Ecc384PubKey {
    x: Array4x12::new([
        0xa7c76b97, 0x0c3b5fe8, 0xb05d2838, 0xae04ab47, 0x697b9eaf, 0x52e76459, 0x2efda27f,
        0xe7513272, 0x734466b4, 0x00091adb, 0xf2d68c58, 0xe0c50066,
    ]),
    y: Array4x12::new([
        0xac68f19f, 0x2e1cb879, 0xaed43a99, 0x69b91a08, 0x39c4c38a, 0x49749b66, 0x1efedf24,
        0x3451915e, 0xd0905a32, 0xb060992b, 0x468c6476, 0x6fc8437a,
    ]),
};
const SHARED_SECRET: Array4x12 = Array4x12::new([
    0x5f9d29dc, 0x5e31a163, 0x06035621, 0x3669c8ce, 0x132e22f5, 0x7c9a04f4, 0x0ba7fcea, 0xd493b457,
    0xe5621e76, 0x6c40a2e3, 0xd4d6a04b, 0x25e533f1,
]);

#[derive(Default, Debug)]
pub struct EcdhKat {}

impl EcdhKat {
    /// This function executes the Known Answer Tests (aka KAT) for ECDH.
    ///
    /// Test vector source:
    /// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip
    ///
    /// # Arguments
    ///
    /// * `ecc` - ECC-384 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, ecc: &mut Ecc384, trng: &mut Trng) -> CaliptraResult<()> {
        self.ecdh(ecc, trng)
    }

    fn ecdh(&self, ecc: &mut Ecc384, trng: &mut Trng) -> CaliptraResult<()> {
        let mut shared_secret = Array4x12::new([0u32; 12]);
        ecc.ecdh(
            Ecc384PrivKeyIn::Array4x12(&A_PRIV_KEY),
            &B_PUB_KEY,
            trng,
            Ecc384PrivKeyOut::Array4x12(&mut shared_secret),
        )?;

        if shared_secret != SHARED_SECRET {
            Err(CaliptraError::KAT_ECDH_VERIFY_FAILURE)?;
        }

        Ok(())
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for ECC-384 cryptography operations.

--*/

use caliptra_drivers::{
    Array4x12, Array4xN, CaliptraError, CaliptraResult, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey,
    Ecc384Signature, Trng,
};

const PRIV_KEY: Array4x12 = Array4x12::new([
    0xc908585a, 0x486c3b3d, 0x8bbe50eb, 0x7d2eb8a0, 0x3aa04e3d, 0x8bde2c31, 0xa8a2a1e3, 0x349dc21c,
    0xbbe6c90a, 0xe2f74912, 0x8884b622, 0xbb72b4c5,
]);

const PUB_KEY: Ecc384PubKey = Ecc384PubKey {
    x: Array4xN([
        0x98233ca, 0x567a3f14, 0xbe784904, 0xc6921d43, 0x3b4f853a, 0x523742e4, 0xbc98767e,
        0x23ca3da6, 0x656bec46, 0xa7b1119e, 0x63d266ca, 0x6254977f,
    ]),
    y: Array4xN([
        0x75d0b401, 0xc8bac39a, 0xc5fb0f2b, 0x3b95372c, 0x41d9de40, 0x55fddb06, 0xf7484974,
        0x8d0aed85, 0x9b6550ca, 0x750c3cd1, 0x1851e050, 0xbb7d20b2,
    ]),
};

const SIGNATURE: Ecc384Signature = Ecc384Signature {
    r: Array4xN([
        0x36f85014, 0x6f400443, 0x848cae03, 0x57591032, 0xe6a395de, 0x66e7261a, 0x38049fb,
        0xee15db19, 0x5dbd9786, 0x9439292a, 0x4f5792e4, 0x3a1231b7,
    ]),
    s: Array4xN([
        0xeeea4294, 0x82fd8fa9, 0xd4d5f960, 0xa09edfa6, 0xc765efe5, 0xff4c17a5, 0x12e694fa,
        0xcc45d3f6, 0xfc3d3b5c, 0x62739c1f, 0xb9fcae3, 0x26f54b43,
    ]),
};

#[derive(Default, Debug)]
pub struct Ecc384Kat {}

impl Ecc384Kat {
    /// This function executes the Known Answer Tests (aka KAT) for ECC384.
    ///
    /// Test vector source:
    /// Generated using MbedTLS library.
    ///
    /// # Arguments
    ///
    /// * `ecc` - ECC-384 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, ecc: &mut Ecc384, trng: &mut Trng) -> CaliptraResult<()> {
        self.kat_signature_generate(ecc, trng)?;
        self.kat_signature_verify(ecc)
    }

    fn kat_signature_generate(&self, ecc: &mut Ecc384, trng: &mut Trng) -> CaliptraResult<()> {
        let digest = Array4x12::new([0u32; 12]);
        let signature = ecc
            .sign(Ecc384PrivKeyIn::from(&PRIV_KEY), &digest, trng)
            .map_err(|_| CaliptraError::ROM_KAT_ECC384_SIGNATURE_GENERATE_FAILURE)?;

        if signature != SIGNATURE {
            Err(CaliptraError::ROM_KAT_ECC384_SIGNATURE_GENERATE_FAILURE)?;
        }

        Ok(())
    }

    fn kat_signature_verify(&self, ecc: &mut Ecc384) -> CaliptraResult<()> {
        let digest = [0u32; 12];
        if !ecc
            .verify(&PUB_KEY, &digest.into(), &SIGNATURE)
            .map_err(|_| CaliptraError::ROM_KAT_ECC384_SIGNATURE_VERIFY_FAILURE)?
        {
            Err(CaliptraError::ROM_KAT_ECC384_SIGNATURE_MISMATCH)?;
        }

        Ok(())
    }
}

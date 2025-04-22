/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for MLDSA cryptography operations.

--*/

use caliptra_drivers::{
    Array4x16, Array4x8, CaliptraError, CaliptraResult, Mldsa87, Mldsa87PrivKey, Mldsa87Seed,
    Mldsa87SignRnd, Sha2_512_384, Trng,
};
use caliptra_registers::sha512::Sha512Reg;

use zerocopy::IntoBytes;

const SEED: Array4x8 = Array4x8::new([
    0x0a004093, 0x27d15f67, 0x121d0737, 0xd5e4ce3f, 0x28fe43a2, 0xd4f06807, 0x858a7646, 0x9cf85c2d,
]);

const KAT_MESSAGE: [u32; 16] = [
    0x78fb03e7, 0x22ed1fc4, 0xf2a5e244, 0x9600e616, 0x0d298750, 0x179a0dd9, 0xb503d306, 0xbc2ac6d4,
    0x735f11ee, 0x23f6c548, 0x358498db, 0x04f50a80, 0xfb169e3c, 0x1c6cd56e, 0xd41baaf3, 0xd418f5c8,
];

const KAT_PUB_KEY_DIGEST: Array4x16 = Array4x16::new([
    0xf4c35e85, 0xf95f18da, 0xac71ce53, 0x98e13e88, 0xe947da, 0x6db08ae3, 0xd428d16d, 0x9d8f33e,
    0x41e57657, 0xbff27bf, 0x6a3be1de, 0x59007b25, 0x56b9350, 0x9b866a1c, 0xa0ab1181, 0x7b60a1ad,
]);

const KAT_PRIV_KEY_DIGEST: Array4x16 = Array4x16::new([
    0xad320570, 0x304d29a5, 0x27838020, 0xf1e4140b, 0x48c19676, 0x5a455fc5, 0x873204dc, 0x57134df7,
    0x21a93bd7, 0xe7b754d5, 0x498ce1bf, 0xca83035f, 0xd6092af, 0x933a895a, 0x80cdffad, 0xa3ac8621,
]);

const KAT_SIGNATURE_DIGEST: Array4x16 = Array4x16::new([
    0x4258ad8a, 0xec8b5351, 0x2a89f13b, 0x8e3e593, 0x12bcf768, 0xe7e9a377, 0x555c663b, 0x528e4fb4,
    0xa2b34dff, 0xc2f68d3a, 0x51eb38ae, 0xd2634a75, 0x2c991d48, 0xceec1726, 0xa6aed8a1, 0xeccf481c,
]);

#[derive(Default, Debug)]
pub struct Mldsa87Kat {}

impl Mldsa87Kat {
    /// This function executes the Known Answer Tests (aka KAT) for MLDSA87.
    ///
    /// # Arguments
    ///
    /// * `mldsa87` - MLDSA87 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, mldsa87: &mut Mldsa87, trng: &mut Trng) -> CaliptraResult<()> {
        self.kat_key_pair_gen_sign_and_verify(mldsa87, trng)
    }

    fn kat_key_pair_gen_sign_and_verify(
        &self,
        mldsa87: &mut Mldsa87,
        trng: &mut Trng,
    ) -> CaliptraResult<()> {
        // Compare SHA-512 hashes of the keys and signature to save on ROM space.
        let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };

        let mut priv_key = Mldsa87PrivKey::default();
        let pub_key = mldsa87
            .key_pair(&Mldsa87Seed::Array4x8(&SEED), trng, Some(&mut priv_key))
            .map_err(|_| CaliptraError::KAT_MLDSA87_KEY_PAIR_GENERATE_FAILURE)?;

        let pub_key_digest = sha2
            .sha512_digest(pub_key.as_bytes())
            .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;
        let priv_key_digest = sha2
            .sha512_digest(priv_key.as_bytes())
            .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;

        if pub_key_digest != KAT_PUB_KEY_DIGEST || priv_key_digest != KAT_PRIV_KEY_DIGEST {
            Err(CaliptraError::KAT_MLDSA87_KEY_PAIR_VERIFY_FAILURE)?;
        }

        let signature = mldsa87
            .sign(
                &Mldsa87Seed::PrivKey(&priv_key),
                &pub_key,
                &KAT_MESSAGE.into(),
                &Mldsa87SignRnd::default(),
                trng,
            )
            .map_err(|_| CaliptraError::KAT_MLDSA87_SIGNATURE_FAILURE)?;

        let signature_digest = sha2
            .sha512_digest(signature.as_bytes())
            .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;

        if signature_digest != KAT_SIGNATURE_DIGEST {
            Err(CaliptraError::KAT_MLDSA87_SIGNATURE_MISMATCH)?;
        }

        Ok(())
    }
}

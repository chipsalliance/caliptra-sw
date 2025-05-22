/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for MLDSA cryptography operations.

--*/

use caliptra_drivers::{
    Array4x16, CaliptraError, CaliptraResult, LEArray4x8, Mldsa87, Mldsa87PrivKey, Mldsa87Seed,
    Mldsa87SignRnd, Sha2_512_384, Trng,
};
use caliptra_registers::sha512::Sha512Reg;

use zerocopy::IntoBytes;

const SEED: LEArray4x8 = LEArray4x8::new([
    0x0a004093, 0x27d15f67, 0x121d0737, 0xd5e4ce3f, 0x28fe43a2, 0xd4f06807, 0x858a7646, 0x9cf85c2d,
]);

const KAT_MESSAGE: [u32; 16] = [
    0x78fb03e7, 0x22ed1fc4, 0xf2a5e244, 0x9600e616, 0x0d298750, 0x179a0dd9, 0xb503d306, 0xbc2ac6d4,
    0x735f11ee, 0x23f6c548, 0x358498db, 0x04f50a80, 0xfb169e3c, 0x1c6cd56e, 0xd41baaf3, 0xd418f5c8,
];

const KAT_PUB_KEY_DIGEST: Array4x16 = Array4x16::new([
    0x156d7184, 0xed6113a4, 0x1944255a, 0x3ffd5aa1, 0x3273e7a7, 0x3d8b5feb, 0xf695df65, 0x351a7476,
    0xb74d6d96, 0xe8927960, 0x0d188fda, 0xb7adaa9a, 0x431308ed, 0xf9544ec3, 0x5fe96fa4, 0xd012c3a8,
]);

const KAT_PRIV_KEY_DIGEST: Array4x16 = Array4x16::new([
    0x535af06c, 0x07e85226, 0x21991715, 0xb1db1b31, 0x3bffe2d3, 0x6ac688bf, 0x960fe7df, 0xda987e1a,
    0x779b9471, 0x80983ac8, 0x45a293ec, 0x70269c4a, 0xeb947158, 0xbe85be08, 0x40730835, 0x3b4700ef,
]);

const KAT_SIGNATURE_DIGEST: Array4x16 = Array4x16::new([
    0x2cc91683, 0xf3f36770, 0x20082e60, 0x06351dbe, 0x459019bb, 0xf99c95f4, 0xf34a6562, 0xf712686d,
    0xe85df11e, 0x324c7954, 0x6e4ff08c, 0x5a028589, 0x1c5ee701, 0x8d490941, 0xb805a337, 0x51746789,
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
            .key_pair(Mldsa87Seed::Array4x8(&SEED), trng, Some(&mut priv_key))
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
                Mldsa87Seed::PrivKey(&priv_key),
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

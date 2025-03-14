/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for MLDSA cryptography operations.

--*/

use caliptra_drivers::{
    Array4x8, Array4x16, CaliptraError, CaliptraResult, Mldsa87, Mldsa87PrivKey, Mldsa87Seed,
    Mldsa87SignRnd, Sha2_512_384, Trng,
};
use caliptra_registers::sha512::Sha512Reg;

use zerocopy::IntoBytes;

const SEED: Array4x8 = Array4x8::new([
    0x2d5cf89c, 0x46768a85, 0x0768f0d4, 0xa243fe28, 0x3fcee4d5, 0x37071d12, 0x675fd127, 0x9340000a,
]);

const KAT_MESSAGE: [u32; 16] = [
    0xc8f518d4, 0xf3aa1bd4, 0x6ed56c1c, 0x3c9e16fb, 0x800af504, 0xdb988435, 0x48c5f623, 0xee115f73,
    0xd4c62abc, 0x06d303b5, 0xd90d9a17, 0x5087290d, 0x16e60096, 0x44e2a5f2, 0xc41fed22, 0xe703fb78,
];

const KAT_PUB_KEY_DIGEST: Array4x16 = Array4x16::new([
    0x05fc4f4f, 0xee96bf2d, 0x270e4f47, 0x21f71527, 0xfc1ea6a6, 0xd9ad68d7, 0x0a34848a, 0x50fbd0d8,
    0x6088e2ec, 0x77c6a548, 0x15b5a42f, 0x4f162521, 0x91f168bf, 0xaa395968, 0x7ec6795a, 0x66917be5,
]);

const KAT_PRIV_KEY_DIGEST: Array4x16 = Array4x16::new([
    0xa3eae8e3, 0x8ac986e1, 0x0c4ccaee, 0x3e6b4782, 0xf8fe3932, 0x91e0b7a7, 0x75408072, 0x0bb85b44,
    0xa174b457, 0x1d259780, 0xf826de94, 0x1d75fbca, 0x7f1741ed, 0x4b741f69, 0xd4d96eaa, 0x1a6645aa,
]);

const KAT_SIGNATURE_DIGEST: Array4x16 = Array4x16::new([
    0x58bad4e0, 0x6e57218f, 0x53248540, 0x27f1fe3d, 0x1da1ead8, 0x282ed21c, 0xedfa3c8f, 0x11be4e13,
    0x9bc9e4af, 0xaf19baa4, 0xfe7fe6c5, 0x87ad51ce, 0x125126b6, 0xab490691, 0xa588551a, 0xb3942cd6,
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

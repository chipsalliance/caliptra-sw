/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for ECC-384 cryptography operations.

--*/

use caliptra_drivers::{
    Array4x12, Array4xN, CaliptraError, CaliptraResult, Ecc384, Ecc384PrivKeyOut, Ecc384PubKey,
    Ecc384Signature, Sha2_512_384, Trng,
};

const KEY_GEN_PRIV_KEY: Array4x12 = Array4x12::new([
    0xfeeef554, 0x4a765649, 0x90128ad1, 0x89e873f2, 0x1f0dfd5a, 0xd7e2fa86, 0x1127ee6e, 0x394ca784,
    0x871c1aec, 0x032c7a8b, 0x10b93e0e, 0xab8946d6,
]);

const KEY_GEN_PUB_KEY: Ecc384PubKey = Ecc384PubKey {
    x: Array4xN([
        0xd7dd94e0, 0xbffc4cad, 0xe9902b7f, 0xdb154260, 0xd5ec5dfd, 0x57950e83, 0x59015a30,
        0x2c8bf7bb, 0xa7e5f6df, 0xfc168516, 0x2bdd35f9, 0xf5c1b0ff,
    ]),
    y: Array4xN([
        0xbb9c3a2f, 0x061e8d70, 0x14278dd5, 0x1e66a918, 0xa6b6f9f1, 0xc1937312, 0xd4e7a921,
        0xb18ef0f4, 0x1fdd401d, 0x9e771850, 0x9f8731e9, 0xeec9c31d,
    ]),
};

const SIGNATURE: Ecc384Signature = Ecc384Signature {
    r: Array4xN([
        0x78c52a07, 0xa1fcdcae, 0x52fb32e1, 0x4734bf3f, 0x014aa242, 0x778df0f2, 0xbfc09ca1,
        0x45cceab6, 0x25a7fd5f, 0x6634c02c, 0x80f98919, 0xce53ed47,
    ]),
    s: Array4xN([
        0x47226c6b, 0x29719f52, 0xd11bb477, 0x9994b15b, 0xdf594ef8, 0xa686ccfd, 0x78659ffa,
        0x96787f80, 0x2a63300d, 0xc3f78cb8, 0xa55f13b1, 0xb48aa603,
    ]),
};

#[derive(Default, Debug)]
pub struct Ecc384Kat {}

impl Ecc384Kat {
    /// This function executes the Known Answer Tests (aka KAT) for ECC384.
    ///
    /// Test vector source:
    /// Zeroed seed/nonce; key pair derived via test\src\crypto.rs
    /// Signature verified using python cryptography lib (built on OpenSSL)
    ///
    /// # Arguments
    ///
    /// * `ecc` - ECC-384 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(
        &self,
        ecc: &mut Ecc384,
        sha: &mut Sha2_512_384,
        trng: &mut Trng,
    ) -> CaliptraResult<()> {
        self.kat_key_pair_gen_sign_and_verify(ecc, sha, trng)
    }

    fn kat_key_pair_gen_sign_and_verify(
        &self,
        ecc: &mut Ecc384,
        sha: &mut Sha2_512_384,
        trng: &mut Trng,
    ) -> CaliptraResult<()> {
        let mut priv_key = Array4x12::new([0u32; 12]);
        let mut pct_sig = Ecc384Signature {
            r: Array4x12::new([0u32; 12]),
            s: Array4x12::new([0u32; 12]),
        };

        let msg_digest = sha
            .sha384_digest(&[])
            .map_err(|_| CaliptraError::KAT_ECC384_KEY_PAIR_GENERATE_FAILURE)?;

        let pub_key = ecc
            .key_pair_for_fips_kat(
                trng,
                Ecc384PrivKeyOut::from(&mut priv_key),
                &mut pct_sig,
                &msg_digest,
            )
            .map_err(|_| CaliptraError::KAT_ECC384_KEY_PAIR_GENERATE_FAILURE)?;

        // NOTE: Signature verify step is performed in ECC driver sign function
        if priv_key != KEY_GEN_PRIV_KEY {
            Err(CaliptraError::KAT_ECC384_KEY_PAIR_VERIFY_FAILURE)?;
        }
        if pub_key != KEY_GEN_PUB_KEY {
            Err(CaliptraError::KAT_ECC384_KEY_PAIR_VERIFY_FAILURE)?;
        }
        if pct_sig != SIGNATURE {
            Err(CaliptraError::KAT_ECC384_SIGNATURE_MISMATCH)?;
        }

        Ok(())
    }
}

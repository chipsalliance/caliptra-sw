/*++
Licensed under the Apache-2.0 license.
File Name:
    crypto.rs
Abstract:
    Crypto helper routines
--*/
use crate::fmc_env::FmcEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::crypto::{self, Ecc384KeyPair, MlDsaKeyPair};
use caliptra_drivers::{
    CaliptraResult, Ecc384PubKey, Ecc384Result, Ecc384Signature, HmacMode, KeyId, Mldsa87PubKey,
    Mldsa87Result, Mldsa87Signature,
};
use caliptra_x509::Ecdsa384Signature;

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

pub enum Crypto {}

impl Crypto {
    /// Version of hmac_kdf() that takes a FmcEnv.
    #[inline(always)]
    pub fn env_hmac_kdf(
        env: &mut FmcEnv,
        key: KeyId,
        label: &[u8],
        context: Option<&[u8]>,
        output: KeyId,
        mode: HmacMode,
    ) -> CaliptraResult<()> {
        crypto::hmac_kdf(
            &mut env.hmac,
            &mut env.trng,
            key,
            label,
            context,
            output,
            mode,
        )
    }

    /// Generate ECC Key Pair
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Diversification label
    /// * `priv_key` - Key slot to store the private key
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Private Key slot id and public key pairs
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn env_ecc384_key_gen(
        env: &mut FmcEnv,
        cdi: KeyId,
        label: &[u8],
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        crypto::ecc384_key_gen(
            &mut env.ecc384,
            &mut env.hmac,
            &mut env.trng,
            &mut env.key_vault,
            cdi,
            label,
            priv_key,
        )
    }

    /// Sign data using ECC Private Key
    ///
    /// This routine calculates the digest of the `data` and signs the hash
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `priv_key` - Key slot to retrieve the private key
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Ecc384Signature` - Signature
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn env_ecdsa384_sign(
        env: &mut FmcEnv,
        priv_key: KeyId,
        pub_key: &Ecc384PubKey,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        crypto::ecdsa384_sign(
            &mut env.sha2_512_384,
            &mut env.ecc384,
            &mut env.trng,
            priv_key,
            pub_key,
            data,
        )
    }

    /// Verify the ECC Signature
    ///
    /// This routine calculates the digest and verifies the signature
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `pub_key` - Public key to verify the signature
    /// * `data` - Input data to hash
    /// * `sig` - Signature to verify
    ///
    /// # Returns
    ///
    /// * `bool` - True on success, false otherwise
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn env_ecdsa384_verify(
        env: &mut FmcEnv,
        pub_key: &Ecc384PubKey,
        data: &[u8],
        sig: &Ecc384Signature,
    ) -> CaliptraResult<Ecc384Result> {
        crypto::ecdsa384_verify(&mut env.sha2_512_384, &mut env.ecc384, pub_key, data, sig)
    }

    /// Sign the data using ECC Private Key.
    /// Verify the signature using the ECC Public Key.
    ///
    /// This routine calculates the digest of the `data`, signs the hash and returns the signature.
    /// This routine also verifies the signature using the public key.
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `priv_key` - Key slot to retrieve the private key
    /// * `pub_key` - Public key to verify with
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Ecc384Signature` - Signature
    #[inline(always)]
    pub fn env_ecdsa384_sign_and_verify(
        env: &mut FmcEnv,
        priv_key: KeyId,
        pub_key: &Ecc384PubKey,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        crypto::ecdsa384_sign_and_verify(
            &mut env.sha2_512_384,
            &mut env.ecc384,
            &mut env.trng,
            priv_key,
            pub_key,
            data,
        )
    }

    /// Generate MLDSA Key Pair
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Diversification label
    /// * `key_pair_seed` - Key slot to store the keypair generation seed.
    ///
    /// # Returns
    ///
    /// * `MlDsaKeyPair` - Public Key and keypair generation seed
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(always)]
    pub fn env_mldsa_key_gen(
        env: &mut FmcEnv,
        cdi: KeyId,
        label: &[u8],
        key_pair_seed: KeyId,
    ) -> CaliptraResult<MlDsaKeyPair> {
        crypto::mldsa_key_gen(
            &mut env.mldsa,
            &mut env.hmac,
            &mut env.trng,
            cdi,
            label,
            key_pair_seed,
        )
    }

    /// Sign data using MLDSA Private Key
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `key_pair_seed` - Key slot to retrieve the keypair generation seed
    /// * `pub_key` - Public key to verify the signature
    /// * `data` - Input data to sign
    ///
    /// # Returns
    ///
    /// * `Mldsa87Signature` - Signature
    pub fn env_mldsa_sign(
        env: &mut FmcEnv,
        key_pair_seed: KeyId,
        pub_key: &Mldsa87PubKey,
        data: &[u8],
    ) -> CaliptraResult<Mldsa87Signature> {
        crypto::mldsa_sign(&mut env.mldsa, &mut env.trng, key_pair_seed, pub_key, data)
    }

    /// Version of mldsa_verify() that takes a FmcEnv.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn env_mldsa_verify(
        env: &mut FmcEnv,
        pub_key: &Mldsa87PubKey,
        data: &[u8],
        sig: &Mldsa87Signature,
    ) -> CaliptraResult<Mldsa87Result> {
        crypto::mldsa_verify(&mut env.mldsa, pub_key, data, sig)
    }

    /// Version of mldsa_sign_and_verify() that takes a FmcEnv.
    #[inline(always)]
    pub fn env_mldsa_sign_and_verify(
        env: &mut FmcEnv,
        key_pair_seed: KeyId,
        pub_key: &Mldsa87PubKey,
        data: &[u8],
    ) -> CaliptraResult<Mldsa87Signature> {
        crypto::mldsa_sign_and_verify(&mut env.mldsa, &mut env.trng, key_pair_seed, pub_key, data)
    }
}

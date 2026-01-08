/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains crypto utilities needed to generate images.

--*/

use core::{ops::Deref, str::from_utf8};
use std::path::Path;

use anyhow::{anyhow, bail, Context};

use caliptra_image_gen::{
    from_hw_format, to_hw_format, ImageGeneratorCrypto, ImageGeneratorHasher,
};
use caliptra_image_types::*;
use caliptra_lms_types::{LmotsAlgorithmType, LmsAlgorithmType};

use fips204::ml_dsa_87::{PrivateKey, PublicKey, SIG_LEN};
use fips204::traits::{SerDes, Signer, Verifier};
use zerocopy::IntoBytes;
use {
    ecdsa::{elliptic_curve::sec1::ToEncodedPoint, signature::hazmat::PrehashSigner},
    p384::pkcs8::DecodePublicKey,
    rand::{rngs::OsRng, RngCore},
    sec1::DecodeEcPrivateKey,
    sha2::{Digest, Sha256, Sha384, Sha512},
};

use crate::{sign_with_lms_key, LmsKeyGen, Sha256Hasher, SUPPORTED_LMS_Q_VALUE};

#[derive(Default)]
pub struct RustCrypto {}

pub struct RustCryptoSha256Hasher(Sha256);

impl ImageGeneratorHasher for RustCryptoSha256Hasher {
    type Output = [u32; SHA256_DIGEST_WORD_SIZE];

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn finish(self) -> Self::Output {
        to_hw_format(&self.0.finalize())
    }
}

impl ImageGeneratorCrypto for RustCrypto {
    type Sha256Hasher = RustCryptoSha256Hasher;

    fn sha256_start(&self) -> Self::Sha256Hasher {
        RustCryptoSha256Hasher(Sha256::default())
    }

    fn sha384_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest384> {
        let mut engine = Sha384::new();
        engine.update(data);
        Ok(to_hw_format(&engine.finalize()))
    }

    fn ecdsa384_sign(
        &self,
        digest: &ImageDigest384,
        priv_key: &ImageEccPrivKey,
        _pub_key: &ImageEccPubKey,
    ) -> anyhow::Result<ImageEccSignature> {
        let priv_key: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(priv_key);
        let digest: [u8; SHA384_DIGEST_BYTE_SIZE] = from_hw_format(digest);

        let sig: p384::ecdsa::Signature =
            p384::ecdsa::SigningKey::from_slice(&priv_key)?.sign_prehash(&digest)?;

        let r = &sig.r().deref().to_bytes();
        let s = &sig.s().deref().to_bytes();

        let image_sig = ImageEccSignature {
            r: to_hw_format(&r),
            s: to_hw_format(&s),
        };
        Ok(image_sig)
    }

    fn lms_sign(
        &self,
        digest: &ImageDigest384,
        priv_key: &ImageLmsPrivKey,
    ) -> anyhow::Result<ImageLmsSignature> {
        let message: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(digest);
        let mut nonce = [0u8; SHA192_DIGEST_BYTE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        sign_with_lms_key::<RustCryptoHasher>(priv_key, &message, &nonce, SUPPORTED_LMS_Q_VALUE)
    }

    // [TODO][CAP2]: Update to use RustCrypto API when available.
    fn mldsa_sign(
        &self,
        msg: &[u8],
        priv_key: &ImageMldsaPrivKey,
        pub_key: &ImageMldsaPubKey,
    ) -> anyhow::Result<ImageMldsaSignature> {
        // Private key is received in hw format which is also the library format.
        // Unlike ECC, no reversal of the DWORD endianess needed.
        let priv_key_bytes: [u8; MLDSA87_PRIV_KEY_BYTE_SIZE] = priv_key
            .0
            .as_bytes()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid private key size"))?;
        let priv_key = { PrivateKey::try_from_bytes(priv_key_bytes).unwrap() };

        let signature = priv_key.try_sign_with_seed(&[0u8; 32], msg, &[]).unwrap();
        let signature_extended = {
            let mut sig = [0u8; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&signature);
            sig
        };

        let pub_key = {
            let pub_key_bytes: [u8; MLDSA87_PUB_KEY_BYTE_SIZE] = pub_key
                .0
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid public key size"))?;
            PublicKey::try_from_bytes(pub_key_bytes).unwrap()
        };
        if !pub_key.verify(msg, &signature, &[]) {
            bail!("MLDSA public key verification failed");
        }

        // Return the signature in hw format (which is also the library format)
        // Unlike ECC, no reversal of the DWORD endianess needed.
        let mut sig: ImageMldsaSignature = ImageMldsaSignature::default();
        for (i, chunk) in signature_extended.chunks(4).enumerate() {
            sig.0[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        Ok(sig)
    }

    fn ecc_pub_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPubKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read public key PEM file {}", path.display()))?;

        let pub_key =
            p384::PublicKey::from_public_key_pem(from_utf8(&key_bytes)?)?.to_encoded_point(false);

        let x = pub_key.x().ok_or(anyhow!("Error parsing x coordinate"))?;
        let y = pub_key.y().ok_or(anyhow!("Error parsing y coordinate"))?;

        let image_key = ImageEccPubKey {
            x: to_hw_format(&x),
            y: to_hw_format(&y),
        };
        Ok(image_key)
    }

    fn ecc_priv_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPrivKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read private key PEM file {}", path.display()))?;

        let priv_key = p384::ecdsa::SigningKey::from_sec1_pem(from_utf8(&key_bytes)?)?.to_bytes();

        Ok(to_hw_format(&priv_key))
    }

    fn sha512_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest512> {
        let mut engine = Sha512::new();
        engine.update(data);
        Ok(to_hw_format(&engine.finalize()))
    }
}

impl LmsKeyGen for RustCrypto {
    /// Generate a new random LMS private key with the specified tree type and OTS type
    fn generate_lms_private_key(
        tree_type: LmsAlgorithmType,
        otstype: LmotsAlgorithmType,
    ) -> anyhow::Result<ImageLmsPrivKey> {
        let mut priv_key = ImageLmsPrivKey {
            tree_type,
            otstype,
            ..Default::default()
        };

        OsRng.fill_bytes(&mut priv_key.id);
        OsRng.fill_bytes(priv_key.seed.as_mut_bytes());

        Ok(priv_key)
    }
}

pub struct RustCryptoHasher(Sha256);

impl Sha256Hasher for RustCryptoHasher {
    fn new() -> Self {
        Self(Sha256::new())
    }
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }
    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generate_lms_pubkey, sign_with_lms_key, RustCryptoHasher, IMAGE_LMS_OTS_TYPE,
        IMAGE_LMS_OTS_TYPE_8, IMAGE_LMS_TREE_TYPE, IMAGE_LMS_TREE_TYPE_HT_5,
    };

    #[test]
    fn test_lms_keygen_trait() {
        // Test the LmsKeyGen trait implementation for RustCrypto
        let priv_key =
            RustCrypto::generate_lms_private_key(IMAGE_LMS_TREE_TYPE_HT_5, IMAGE_LMS_OTS_TYPE_8)
                .unwrap();

        // Verify the key has correct algorithm types
        assert_eq!(priv_key.tree_type, IMAGE_LMS_TREE_TYPE_HT_5);
        assert_eq!(priv_key.otstype, IMAGE_LMS_OTS_TYPE_8);

        // Verify randomness - ID and seed should be non-zero
        assert_ne!(priv_key.id, [0u8; 16]);
        assert_ne!(priv_key.seed.as_bytes(), &[0u8; 24]);

        // Test with standard IMAGE types
        let std_priv_key =
            RustCrypto::generate_lms_private_key(IMAGE_LMS_TREE_TYPE, IMAGE_LMS_OTS_TYPE).unwrap();
        assert_eq!(std_priv_key.tree_type, IMAGE_LMS_TREE_TYPE);
        assert_eq!(std_priv_key.otstype, IMAGE_LMS_OTS_TYPE);

        // Different invocations should generate different keys
        let priv_key2 =
            RustCrypto::generate_lms_private_key(IMAGE_LMS_TREE_TYPE_HT_5, IMAGE_LMS_OTS_TYPE_8)
                .unwrap();
        assert_ne!(priv_key.id, priv_key2.id);
        assert_ne!(priv_key.seed.as_bytes(), priv_key2.seed.as_bytes());
    }

    #[test]
    fn test_lms_keygen_with_pubkey_generation() {
        // Test full workflow: generate private key using trait, then generate public key
        let priv_key =
            RustCrypto::generate_lms_private_key(IMAGE_LMS_TREE_TYPE_HT_5, IMAGE_LMS_OTS_TYPE_8)
                .unwrap();
        let pub_key = generate_lms_pubkey::<RustCryptoHasher>(&priv_key).unwrap();

        // Public key should match private key metadata
        assert_eq!(pub_key.tree_type, priv_key.tree_type);
        assert_eq!(pub_key.otstype, priv_key.otstype);
        assert_eq!(pub_key.id, priv_key.id);

        // Digest should be non-zero (derived from seed)
        assert_ne!(pub_key.digest.as_bytes(), &[0u8; 24]);
    }

    #[test]
    fn test_lms_keygen_with_signing() {
        // Test complete workflow: generate key using trait, generate public key, sign message
        let priv_key =
            RustCrypto::generate_lms_private_key(IMAGE_LMS_TREE_TYPE_HT_5, IMAGE_LMS_OTS_TYPE_8)
                .unwrap();
        let _pub_key = generate_lms_pubkey::<RustCryptoHasher>(&priv_key).unwrap();

        // Test signing with generated key
        let message = b"test message for LmsKeyGen trait";
        let nonce = [0x42u8; 24];
        let sig = sign_with_lms_key::<RustCryptoHasher>(&priv_key, message, &nonce, 1).unwrap();

        // Signature should have correct metadata
        assert_eq!(sig.tree_type, priv_key.tree_type);
        assert_eq!(sig.ots.ots_type, priv_key.otstype);
        assert_eq!(sig.q.get(), 1);
    }

    /// Generic test function that works with any crypto backend implementing LmsKeyGen
    fn test_lms_keygen_generic<T: LmsKeyGen>() {
        let priv_key =
            T::generate_lms_private_key(IMAGE_LMS_TREE_TYPE_HT_5, IMAGE_LMS_OTS_TYPE_8).unwrap();

        assert_eq!(priv_key.tree_type, IMAGE_LMS_TREE_TYPE_HT_5);
        assert_eq!(priv_key.otstype, IMAGE_LMS_OTS_TYPE_8);
        assert_ne!(priv_key.id, [0u8; 16]);
        assert_ne!(priv_key.seed.as_bytes(), &[0u8; 24]);
    }

    #[test]
    fn test_lms_keygen_generic_rustcrypto() {
        test_lms_keygen_generic::<RustCrypto>();
    }
}

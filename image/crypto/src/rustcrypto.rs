/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains crypto utilities needed to generate images.

--*/

use core::{ops::Deref, str::from_utf8};
use std::path::Path;

use anyhow::{anyhow, Context};

use caliptra_image_gen::{ImageGeneratorCrypto, ImageGeneratorHasher};
use caliptra_image_types::*;

use {
    ecdsa::{elliptic_curve::sec1::ToEncodedPoint, signature::hazmat::PrehashSigner},
    p384::pkcs8::DecodePublicKey,
    rand::{rngs::OsRng, RngCore},
    sec1::DecodeEcPrivateKey,
    sha2::{Digest, Sha256, Sha384},
};

use crate::{from_hw_format, sign_with_lms_key, to_hw_format, Sha256Hasher, SUPPORTED_LMS_Q_VALUE};

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

    fn sha384_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest> {
        let mut engine = Sha384::new();
        engine.update(data);
        Ok(to_hw_format(&engine.finalize()))
    }

    fn ecdsa384_sign(
        &self,
        digest: &ImageDigest,
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
        digest: &ImageDigest,
        priv_key: &ImageLmsPrivKey,
    ) -> anyhow::Result<ImageLmsSignature> {
        let message: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(digest);
        let mut nonce = [0u8; SHA192_DIGEST_BYTE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        sign_with_lms_key::<RustCryptoHasher>(priv_key, &message, &nonce, SUPPORTED_LMS_Q_VALUE)
    }

    fn ecc_pub_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPubKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read public key PEM file {}", path.display()))?;

        let pub_key =
            p384::PublicKey::from_public_key_pem(from_utf8(&key_bytes)?)?.to_encoded_point(true);

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

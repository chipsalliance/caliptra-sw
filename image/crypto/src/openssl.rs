/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains crypto utilities needed to generate images.

--*/

use std::path::Path;

use anyhow::Context;

use caliptra_image_gen::{ImageGeneratorCrypto, ImageGeneratorHasher};
use caliptra_image_types::*;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    rand::rand_bytes,
    sha::{Sha256, Sha384},
};

use crate::{from_hw_format, sign_with_lms_key, to_hw_format, Sha256Hasher, SUPPORTED_LMS_Q_VALUE};

#[derive(Default)]
pub struct OsslCrypto {}

pub struct OsslSha256Hasher(Sha256);

impl ImageGeneratorHasher for OsslSha256Hasher {
    type Output = [u32; SHA256_DIGEST_WORD_SIZE];

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn finish(self) -> Self::Output {
        to_hw_format(&self.0.finish())
    }
}

impl ImageGeneratorCrypto for OsslCrypto {
    type Sha256Hasher = OsslSha256Hasher;

    fn sha256_start(&self) -> Self::Sha256Hasher {
        OsslSha256Hasher(Sha256::default())
    }

    fn sha384_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest> {
        let mut engine = Sha384::new();
        engine.update(data);
        Ok(ImageDigest(to_hw_format(&engine.finish())))
    }

    fn ecdsa384_sign(
        &self,
        digest: &ImageDigest,
        priv_key: &ImageEccPrivKey,
        pub_key: &ImageEccPubKey,
    ) -> anyhow::Result<ImageEccSignature> {
        let priv_key: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(&priv_key.0);
        let pub_key_x: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(&pub_key.x.0);
        let pub_key_y: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(&pub_key.y.0);
        let digest: [u8; SHA384_DIGEST_BYTE_SIZE] = from_hw_format(&digest.0);

        let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let mut ctx = BigNumContext::new()?;

        let priv_key = BigNum::from_slice(&priv_key)?;
        let pub_key_x = BigNum::from_slice(&pub_key_x)?;
        let pub_key_y = BigNum::from_slice(&pub_key_y)?;

        let mut pub_key = EcPoint::new(&group)?;
        pub_key.set_affine_coordinates_gfp(&group, &pub_key_x, &pub_key_y, &mut ctx)?;

        let ec_key = EcKey::from_private_components(&group, &priv_key, &pub_key)?;
        let sig = EcdsaSig::sign(&digest, &ec_key)?;

        let r = sig.r().to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;
        let s = sig.s().to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;

        let image_sig = ImageEccSignature {
            r: ImageScalar(to_hw_format(&r)),
            s: ImageScalar(to_hw_format(&s)),
        };
        Ok(image_sig)
    }

    fn lms_sign(
        &self,
        digest: &ImageDigest,
        priv_key: &ImageLmsPrivKey,
    ) -> anyhow::Result<ImageLmsSignature> {
        let message: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(&digest.0);
        let mut nonce = [0u8; SHA192_DIGEST_BYTE_SIZE];
        rand_bytes(&mut nonce)?;
        sign_with_lms_key::<OpensslHasher>(priv_key, &message, &nonce, SUPPORTED_LMS_Q_VALUE)
    }

    fn ecc_pub_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPubKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read public key PEM file {}", path.display()))?;
        let key = EcKey::public_key_from_pem(&key_bytes)?;
        let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;

        key.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;

        let x = x.to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;
        let y = y.to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;

        let image_key = ImageEccPubKey {
            x: ImageScalar(to_hw_format(&x)),
            y: ImageScalar(to_hw_format(&y)),
        };
        Ok(image_key)
    }

    fn ecc_priv_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPrivKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read private key PEM file {}", path.display()))?;

        let key = EcKey::private_key_from_pem(&key_bytes)?;

        let priv_key = key
            .private_key()
            .to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;

        Ok(ImageScalar(to_hw_format(&priv_key)))
    }
}

pub struct OpensslHasher(Sha256);

impl Sha256Hasher for OpensslHasher {
    fn new() -> Self {
        Self(Sha256::new())
    }
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }
    fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

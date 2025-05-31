/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains crypto utilities needed to generate images.

--*/

use std::path::Path;

use anyhow::{bail, Context};

use caliptra_image_gen::{
    from_hw_format, to_hw_format, u8_to_u32_le, ImageGeneratorCrypto, ImageGeneratorHasher,
};
use caliptra_image_types::*;
use zerocopy::IntoBytes;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::Private,
    pkey_ctx::PkeyCtx,
    pkey_ml_dsa::{PKeyMlDsaBuilder, Variant},
    rand::rand_bytes,
    sha::{Sha256, Sha384, Sha512},
    signature::Signature,
};

use crate::{sign_with_lms_key, Sha256Hasher, SUPPORTED_LMS_Q_VALUE};

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

    fn sha384_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest384> {
        let mut engine = Sha384::new();
        engine.update(data);
        Ok(to_hw_format(&engine.finish()))
    }

    fn sha512_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest512> {
        let mut engine = Sha512::new();
        engine.update(data);
        Ok(to_hw_format(&engine.finish()))
    }

    fn ecdsa384_sign(
        &self,
        digest: &ImageDigest384,
        priv_key: &ImageEccPrivKey,
        pub_key: &ImageEccPubKey,
    ) -> anyhow::Result<ImageEccSignature> {
        let priv_key: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(priv_key);
        let pub_key_x: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(&pub_key.x);
        let pub_key_y: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(&pub_key.y);
        let digest: [u8; SHA384_DIGEST_BYTE_SIZE] = from_hw_format(digest);

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
        rand_bytes(&mut nonce)?;
        sign_with_lms_key::<OpensslHasher>(priv_key, &message, &nonce, SUPPORTED_LMS_Q_VALUE)
    }

    fn mldsa_sign(
        &self,
        msg: &[u8],
        priv_key: &ImageMldsaPrivKey,
        pub_key: &ImageMldsaPubKey,
    ) -> anyhow::Result<ImageMldsaSignature> {
        // Private key is received in hw format which is also the OSSL library format.
        // Unlike ECC, no reversal of the DWORD endianess needed.
        let private_key = {
            let pub_key = pub_key.0.as_bytes();
            let priv_key = priv_key.0.as_bytes();
            let builder =
                PKeyMlDsaBuilder::<Private>::new(Variant::MlDsa87, pub_key, Some(priv_key))?;
            builder.build()?
        };

        let mut algo = Signature::for_ml_dsa(Variant::MlDsa87)?;
        let mut ctx = PkeyCtx::new(&private_key)?;
        ctx.sign_message_init(&mut algo)?;
        const SIG_LEN: usize = 4627;
        let mut signature = [0u8; SIG_LEN + 1];
        ctx.sign(msg, Some(&mut signature))?;

        ctx.verify_message_init(&mut algo)?;
        match ctx.verify(msg, &signature[..SIG_LEN]) {
            Ok(true) => (),
            _ => bail!("MLDSA signature verification failed"),
        }

        // Return the signature in hw format (which is also the library format)
        // Unlike ECC, no reversal of the DWORD endianess needed.
        let mut sig = ImageMldsaSignature::default();
        for (i, chunk) in signature.chunks(4).enumerate() {
            sig.0[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        Ok(sig)
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
            x: to_hw_format(&x),
            y: to_hw_format(&y),
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

        Ok(to_hw_format(&priv_key))
    }

    /// Read MLDSA Public Key from file. Library format is same as hardware format.
    fn mldsa_pub_key_from_file(path: &Path) -> anyhow::Result<ImageMldsaPubKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read public key file {}", path.display()))?;
        Ok(ImageMldsaPubKey(
            u8_to_u32_le(&key_bytes).try_into().unwrap(),
        ))
    }

    /// Read MLDSA Private Key from file. Library format is same as hardware format.
    fn mldsa_priv_key_from_file(path: &Path) -> anyhow::Result<ImageMldsaPrivKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read private key file {}", path.display()))?;
        Ok(ImageMldsaPrivKey(
            u8_to_u32_le(&key_bytes).try_into().unwrap(),
        ))
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

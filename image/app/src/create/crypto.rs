/*++

Licensed under the Apache-2.0 license.

File Name:

   crypto.rs

Abstract:

    File contains crypto utilities used by the application.

--*/

use std::path::PathBuf;

use anyhow::Context;
use caliptra_image_gen::ImageGeneratorCrypto;
use caliptra_image_types::*;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::sha::Sha384;

#[derive(Default)]
pub(crate) struct OsslCrypto {}

impl ImageGeneratorCrypto for OsslCrypto {
    /// Calculate SHA-384 Digest
    fn sha384_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest> {
        let mut engine = Sha384::new();
        engine.update(data);
        Ok(to_hw_format(&engine.finish()))
    }

    /// Calculate ECDSA-384 Signature
    fn ecdsa384_sign(
        &self,
        digest: &ImageDigest,
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
}

/// Read ECC-384 Public Key from PEM file
pub fn ecc_pub_key_from_pem(path: &PathBuf) -> anyhow::Result<ImageEccPubKey> {
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

/// Read ECC-384 Private Key from PEM file
pub fn ecc_priv_key_from_pem(path: &PathBuf) -> anyhow::Result<ImageEccPrivKey> {
    let key_bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read public key PEM file {}", path.display()))?;

    let key = EcKey::private_key_from_pem(&key_bytes)?;

    let priv_key = key
        .private_key()
        .to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;

    Ok(to_hw_format(&priv_key))
}

/// Convert the slice to hardware format
fn to_hw_format(value: &[u8]) -> [u32; ECC384_SCALAR_WORD_SIZE] {
    let arr = TryInto::<[u8; ECC384_SCALAR_BYTE_SIZE]>::try_into(value).unwrap();
    let mut result = [0u32; ECC384_SCALAR_WORD_SIZE];
    for i in 0..result.len() {
        result[i] = u32::from_be_bytes(arr[i * 4..][..4].try_into().unwrap())
    }
    result
}

/// Convert the hardware format to byte array
fn from_hw_format(value: &[u32; ECC384_SCALAR_WORD_SIZE]) -> [u8; ECC384_SCALAR_BYTE_SIZE] {
    let mut result = [0u8; ECC384_SCALAR_BYTE_SIZE];
    for i in 0..value.len() {
        *<&mut [u8; 4]>::try_from(&mut result[i * 4..][..4]).unwrap() = value[i].to_be_bytes();
    }
    result
}

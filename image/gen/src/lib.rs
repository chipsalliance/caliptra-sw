/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains data strucutres for the Caliptra Image Generator.

--*/

mod generator;

pub use generator::ImageGenerator;

use anyhow::Context;
use caliptra_image_types::*;
use std::path::Path;

/// Image Generator Executable
pub trait ImageGeneratorExecutable {
    /// Executable Version Number
    fn version(&self) -> u32;

    /// Executable Revision
    fn rev(&self) -> &ImageRevision;

    /// Executable Load Address
    fn load_addr(&self) -> u32;

    /// Executable Entry Point
    fn entry_point(&self) -> u32;

    /// Executable Content
    fn content(&self) -> &Vec<u8>;

    /// Executable Size
    fn size(&self) -> u32;
}

pub trait ImageGeneratorHasher {
    type Output: Copy;

    fn update(&mut self, data: &[u8]);

    fn finish(self) -> Self::Output;
}

/// Image Generator Crypto Trait
pub trait ImageGeneratorCrypto {
    type Sha256Hasher: ImageGeneratorHasher<Output = [u32; SHA256_DIGEST_WORD_SIZE]>;

    fn sha256_start(&self) -> Self::Sha256Hasher;

    /// Calculate SHA-256 digest
    fn sha256_digest(&self, data: &[u8]) -> anyhow::Result<[u32; SHA256_DIGEST_WORD_SIZE]> {
        let mut hasher = self.sha256_start();
        hasher.update(data);
        Ok(hasher.finish())
    }

    /// Calculate SHA2-384 digest
    fn sha384_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest384>;

    /// Calculate SHA2-512 digest
    fn sha512_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest512>;

    /// Calculate ECDSA Signature
    fn ecdsa384_sign(
        &self,
        digest: &ImageDigest384,
        priv_key: &ImageEccPrivKey,
        pub_key: &ImageEccPubKey,
    ) -> anyhow::Result<ImageEccSignature>;

    /// Calculate LMS Signature
    fn lms_sign(
        &self,
        digest: &ImageDigest384,
        priv_key: &ImageLmsPrivKey,
    ) -> anyhow::Result<ImageLmsSignature>;

    /// Read ECC-384 Public Key from PEM file
    fn ecc_pub_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPubKey>;

    /// Read ECC-384 Private Key from PEM file
    fn ecc_priv_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPrivKey>;

    /// Read MLDSA Public Key from file
    fn mldsa_pub_key_from_file(path: &Path) -> anyhow::Result<ImageMldsaPubKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read public key file {}", path.display()))?;
        Ok(ImageMldsaPubKey(to_hw_format(&key_bytes)))
    }

    /// Read MLDSA Private Key from file
    fn mldsa_priv_key_from_file(path: &Path) -> anyhow::Result<ImageMldsaPrivKey> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read private key file {}", path.display()))?;
        Ok(ImageMldsaPrivKey(to_hw_format(&key_bytes)))
    }
}

/// Convert the slice to hardware format
pub fn to_hw_format<const NUM_WORDS: usize>(value: &[u8]) -> [u32; NUM_WORDS] {
    let mut result = [0u32; NUM_WORDS];
    for i in 0..result.len() {
        result[i] = u32::from_be_bytes(value[i * 4..][..4].try_into().unwrap())
    }
    result
}

/// Convert the hardware format to byte array
pub fn from_hw_format(value: &[u32; ECC384_SCALAR_WORD_SIZE]) -> [u8; ECC384_SCALAR_BYTE_SIZE] {
    let mut result = [0u8; ECC384_SCALAR_BYTE_SIZE];
    for i in 0..value.len() {
        *<&mut [u8; 4]>::try_from(&mut result[i * 4..][..4]).unwrap() = value[i].to_be_bytes();
    }
    result
}

/// Image Generator Vendor Configuration
#[derive(Default, Clone)]
pub struct ImageGeneratorVendorConfig {
    pub ecc_key_count: u32,

    pub lms_key_count: u32,

    pub mldsa_key_count: u32,

    pub pub_keys: ImageVendorPubKeys,

    pub ecc_key_idx: u32,

    pub pqc_key_idx: u32,

    pub priv_keys: Option<ImageVendorPrivKeys>,

    pub not_before: [u8; 15],

    pub not_after: [u8; 15],

    pub pl0_pauser: Option<u32>,
}

/// Image Generator Owner Configuration
#[derive(Default, Clone)]
pub struct ImageGeneratorOwnerConfig {
    pub pub_keys: OwnerPubKeyConfig,

    pub priv_keys: Option<ImageOwnerPrivKeys>,

    pub not_before: [u8; 15],

    pub not_after: [u8; 15],
}

/// Image Generator Configuration
#[derive(Default)]
pub struct ImageGeneratorConfig<T>
where
    T: ImageGeneratorExecutable,
{
    pub pqc_key_type: FwVerificationPqcKeyType,

    pub vendor_config: ImageGeneratorVendorConfig,

    pub owner_config: Option<ImageGeneratorOwnerConfig>,

    pub fmc: T,

    pub runtime: T,

    pub fw_svn: u32,
}

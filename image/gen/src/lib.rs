/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains data strucutres for the Caliptra Image Generator.

--*/

mod generator;

pub use generator::ImageGenerator;

use caliptra_image_types::*;
use std::path::Path;

/// Image Generator Executable
pub trait ImageGeneratorExecutable {
    /// Executable Version Number
    fn version(&self) -> u32;

    /// Executable Security Version Number
    fn svn(&self) -> u32;

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

    /// Calculate SHA-384 digest
    fn sha384_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest>;

    /// Calculate ECDSA Signature
    fn ecdsa384_sign(
        &self,
        digest: &ImageDigest,
        priv_key: &ImageEccPrivKey,
        pub_key: &ImageEccPubKey,
    ) -> anyhow::Result<ImageEccSignature>;

    /// Calculate LMS Signature
    fn lms_sign(
        &self,
        digest: &ImageDigest,
        priv_key: &ImageLmsPrivKey,
    ) -> anyhow::Result<ImageLmsSignature>;

    /// Read ECC-384 Public Key from PEM file
    fn ecc_pub_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPubKey>;

    /// Read ECC-384 Private Key from PEM file
    fn ecc_priv_key_from_pem(path: &Path) -> anyhow::Result<ImageEccPrivKey>;

    /// Read MLDSA Public Key from file
    fn mldsa_pub_key_from_file(path: &Path) -> anyhow::Result<ImageMldsaPubKey>;

    /// Read MLDSA Private Key from file
    fn mldsa_priv_key_from_file(path: &Path) -> anyhow::Result<ImageMldsaPrivKey>;
}

/// Image Generator Vendor Configuration
#[derive(Default, Clone)]
pub struct ImageGeneratorVendorConfig {
    pub fw_image_type: FwImageType,

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

    pub epoch: [u8; 2],
}

/// Image Generator Configuration
#[derive(Default)]
pub struct ImageGeneratorConfig<T>
where
    T: ImageGeneratorExecutable,
{
    pub fw_image_type: FwImageType,

    pub vendor_config: ImageGeneratorVendorConfig,

    pub owner_config: Option<ImageGeneratorOwnerConfig>,

    pub fmc: T,

    pub runtime: T,
}

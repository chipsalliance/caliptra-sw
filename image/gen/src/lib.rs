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

/// Image Generator Executable
pub trait ImageGenratorExecutable {
    /// Executable Security Version Number
    fn svn(&self) -> u32;

    /// Executable Minimum Security Version Number
    fn min_svn(&self) -> u32;

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

/// Image Generator Crypto Trait
pub trait ImageGeneratorCrypto {
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
}

/// Image Generator Vendor Configuration
#[derive(Default)]
pub struct ImageGeneratorVendorConfig {
    pub pub_keys: ImageVendorPubKeys,

    pub ecc_key_idx: u32,

    pub lms_key_idx: u32,

    pub priv_keys: Option<ImageVendorPrivKeys>,

    pub not_before: [u8; 15],

    pub not_after: [u8; 15],
}

/// Image Generator Owner Configuration
#[derive(Default)]
pub struct ImageGeneratorOwnerConfig {
    pub lms_key_idx: u32,
    pub pub_keys: ImageOwnerPubKeys,

    pub priv_keys: Option<ImageOwnerPrivKeys>,

    pub not_before: [u8; 15],

    pub not_after: [u8; 15],
}

/// Image Generator Configuration
#[derive(Default)]
pub struct ImageGeneratorConfig<T>
where
    T: ImageGenratorExecutable,
{
    pub vendor_config: ImageGeneratorVendorConfig,

    pub owner_config: Option<ImageGeneratorOwnerConfig>,

    pub fmc: T,

    pub runtime: T,
}

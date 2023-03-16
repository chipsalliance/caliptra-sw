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
use getset::{CopyGetters, Getters, MutGetters, Setters};

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

/// Image Gnerator Crypto Trait
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
}

/// Image Generator Vendor Configuration
#[derive(Default, Getters, Setters, MutGetters, CopyGetters)]
pub struct ImageGeneratorVendorConfig {
    #[getset(get = "pub", set = "pub", get_mut = "pub")]
    pub_keys: ImageVendorPubKeys,

    #[getset(get_copy = "pub", set = "pub")]
    ecc_key_idx: u32,

    #[getset(get = "pub", set = "pub", get_mut = "pub")]
    priv_keys: Option<ImageVendorPrivKeys>,
}

/// Image Generator Owner Configuration
#[derive(Default, Getters, Setters, MutGetters)]
pub struct ImageGeneratorOwnerConfig {
    #[getset(get = "pub", set = "pub", get_mut = "pub")]
    pub_keys: ImageOwnerPubKeys,

    #[getset(get = "pub", set = "pub", get_mut = "pub")]
    priv_keys: Option<ImageOwnerPrivKeys>,
}

/// Image Generator Configuration
#[derive(Default, Getters, Setters, CopyGetters)]
pub struct ImageGeneratorConfig<T>
where
    T: ImageGenratorExecutable,
{
    #[getset(get = "pub", set = "pub")]
    vendor_config: ImageGeneratorVendorConfig,

    #[getset(get = "pub", set = "pub")]
    owner_config: Option<ImageGeneratorOwnerConfig>,

    #[getset(get = "pub", set = "pub")]
    fmc: T,

    #[getset(get = "pub", set = "pub")]
    runtime: T,
}

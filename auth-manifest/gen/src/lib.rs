/*++

Licensed under the Apache-2.0 license.

File Name:

   generator.rs

Abstract:

    Caliptra Image generator

--*/
mod generator;

pub mod default_test_manifest;

use caliptra_image_types::FwVerificationPqcKeyType;
pub use generator::AuthManifestGenerator;

use caliptra_auth_man_types::*;

/// Image Generator Vendor Configuration
#[derive(Default, Clone)]
pub struct AuthManifestGeneratorKeyConfig {
    pub pub_keys: AuthManifestPubKeysConfig,

    pub priv_keys: Option<AuthManifestPrivKeysConfig>,
}

/// Authorization Manifest Generator Configuration
#[derive(Default, Clone)]
pub struct AuthManifestGeneratorConfig {
    pub version: u32,

    pub svn: u32,

    pub flags: AuthManifestFlags,

    pub pqc_key_type: FwVerificationPqcKeyType,

    pub vendor_fw_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub vendor_man_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub owner_man_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub image_metadata_list: Vec<AuthManifestImageMetadata>,
}

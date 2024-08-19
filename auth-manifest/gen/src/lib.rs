/*++

Licensed under the Apache-2.0 license.

File Name:

   generator.rs

Abstract:

    Caliptra Image generator

--*/
mod generator;

pub use generator::AuthManifestGenerator;

//use auth_man_generator::{AuthManPrivKeys, AuthManPubKeys};
use caliptra_auth_man_types::*;

/// Image Generator Vendor Configuration
#[derive(Default, Clone)]
pub struct AuthManifestGeneratorKeyConfig {
    pub pub_keys: AuthManifestPubKeys,

    pub priv_keys: Option<AuthManifestPrivKeys>,
}

/// Authorization Manifest Generator Configuration
#[derive(Default, Clone)]
pub struct AuthManifestGeneratorConfig {
    pub version: u32,

    pub flags: u32,

    pub vendor_fw_key_info: AuthManifestGeneratorKeyConfig,

    pub vendor_man_key_info: AuthManifestGeneratorKeyConfig,

    pub owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub owner_man_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub image_metadata_list: Vec<AuthManifestImageMetadata>,
}

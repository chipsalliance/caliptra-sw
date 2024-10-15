/*++

Licensed under the Apache-2.0 license.

File Name:

   generator.rs

Abstract:

    Caliptra Image generator

--*/
mod authman_generator;
mod imc_generator;

pub use authman_generator::AuthManifestGenerator;
pub use imc_generator::ImcGenerator;

use caliptra_auth_man_types::*;

/// Authorization Manifest Image Generator Key Configuration
#[derive(Default, Clone)]
pub struct AuthManifestGeneratorKeyConfig {
    pub pub_keys: AuthManifestPubKeys,

    pub priv_keys: Option<AuthManifestPrivKeys>,
}

/// Authorization Manifest Generator Configuration
#[derive(Default, Clone)]
pub struct AuthManifestGeneratorConfig {
    pub version: u32,

    pub flags: AuthManifestFlags,

    pub vendor_fw_key_info: AuthManifestGeneratorKeyConfig,

    pub vendor_man_key_info: AuthManifestGeneratorKeyConfig,

    pub owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub owner_man_key_info: Option<AuthManifestGeneratorKeyConfig>,
}

// /// Image Metadata Collection Image Generator Key Configuration
// #[derive(Default, Clone)]
// pub struct ImcGeneratorKeyConfig {
//     pub priv_keys: Option<AuthManifestPrivKeys>,
// }

/// Image Metadata Collection Generator Configuration
#[derive(Default, Clone)]
pub struct ImcGeneratorConfig {
    pub revision: u32,

    pub flags: AuthManifestFlags,

    pub vendor_man_key_info: AuthManifestGeneratorKeyConfig,

    pub owner_man_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub image_metadata_list: Vec<AuthManifestImageMetadata>,
}

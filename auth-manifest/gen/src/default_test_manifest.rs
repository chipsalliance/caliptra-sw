// Licensed under the Apache-2.0 license

use crate::{AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestPrivKeysConfig,
    AuthManifestPubKeysConfig, AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_image_fake_keys::*;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::FwVerificationPqcKeyType;

// Default test MCU firmware used for subsystem mode uploads
pub static DEFAULT_MCU_FW: [u8; 4] = [0x00, 0x00, 0x00, 0x6f];

/// Get default test vendor firmware key configuration
pub fn default_test_vendor_fw_key_info() -> AuthManifestGeneratorKeyConfig {
    AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
            mldsa_pub_key: VENDOR_MLDSA_KEY_0_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
            mldsa_priv_key: VENDOR_MLDSA_KEY_0_PRIVATE,
        }),
    }
}

/// Get default test vendor manifest key configuration
pub fn default_test_vendor_man_key_info() -> AuthManifestGeneratorKeyConfig {
    AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
            mldsa_pub_key: VENDOR_MLDSA_KEY_1_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
            mldsa_priv_key: VENDOR_MLDSA_KEY_1_PRIVATE,
        }),
    }
}

/// Get default test owner firmware key configuration
pub fn default_test_owner_fw_key_info() -> AuthManifestGeneratorKeyConfig {
    AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
            lms_pub_key: OWNER_LMS_KEY_PUBLIC,
            mldsa_pub_key: OWNER_MLDSA_KEY_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
            lms_priv_key: OWNER_LMS_KEY_PRIVATE,
            mldsa_priv_key: OWNER_MLDSA_KEY_PRIVATE,
        }),
    }
}

/// Get default test owner manifest key configuration
pub fn default_test_owner_man_key_info() -> AuthManifestGeneratorKeyConfig {
    AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
            lms_pub_key: OWNER_LMS_KEY_PUBLIC,
            mldsa_pub_key: OWNER_MLDSA_KEY_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
            lms_priv_key: OWNER_LMS_KEY_PRIVATE,
            mldsa_priv_key: OWNER_MLDSA_KEY_PRIVATE,
        }),
    }
}

/// Generate a default SoC authorization manifest for testing purposes.
/// This is used in subsystem mode when no specific manifest is provided.
///
/// # Arguments
///
/// * `mcu_fw` - The MCU firmware bytes to hash
/// * `pqc_key_type` - The PQC key type to use (LMS or MLDSA)
/// * `svn` - Security version number for the manifest
/// * `crypto` - Crypto implementation to use for hashing
///
/// # Returns
///
/// An `AuthorizationManifest` signed with test keys
pub fn default_test_soc_manifest<C: ImageGeneratorCrypto>(
    mcu_fw: &[u8],
    pqc_key_type: FwVerificationPqcKeyType,
    svn: u32,
    crypto: C,
) -> AuthorizationManifest {
    // generate a default SoC manifest if one is not provided in subsystem mode
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);

    let digest = from_hw_format(&crypto.sha384_digest(mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];

    create_test_auth_manifest_with_config(
        metadata,
        AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        svn,
        crypto,
    )
}

/// Create a test authorization manifest with custom metadata and configuration.
/// Uses default test keys for signing.
///
/// # Arguments
///
/// * `image_metadata_list` - List of image metadata entries
/// * `flags` - Authorization manifest flags
/// * `pqc_key_type` - The PQC key type to use (LMS or MLDSA)
/// * `svn` - Security version number for the manifest
/// * `crypto` - Crypto implementation to use for hashing
///
/// # Returns
///
/// An `AuthorizationManifest` signed with test keys
pub fn create_test_auth_manifest_with_config<C: ImageGeneratorCrypto>(
    image_metadata_list: Vec<AuthManifestImageMetadata>,
    flags: AuthManifestFlags,
    pqc_key_type: FwVerificationPqcKeyType,
    svn: u32,
    crypto: C,
) -> AuthorizationManifest {
    let gen_config: AuthManifestGeneratorConfig = AuthManifestGeneratorConfig {
        vendor_fw_key_info: Some(default_test_vendor_fw_key_info()),
        vendor_man_key_info: Some(default_test_vendor_man_key_info()),
        owner_fw_key_info: Some(default_test_owner_fw_key_info()),
        owner_man_key_info: Some(default_test_owner_man_key_info()),
        image_metadata_list,
        version: 1,
        flags,
        pqc_key_type,
        svn,
    };

    let gen = AuthManifestGenerator::new(crypto);
    gen.generate(&gen_config).unwrap()
}

/// Create a test authorization manifest with custom metadata.
/// Uses default test keys and VENDOR_SIGNATURE_REQUIRED flag.
///
/// # Arguments
///
/// * `image_metadata_list` - List of image metadata entries
/// * `pqc_key_type` - The PQC key type to use (LMS or MLDSA)
/// * `svn` - Security version number for the manifest
/// * `crypto` - Crypto implementation to use for hashing
///
/// # Returns
///
/// An `AuthorizationManifest` signed with test keys
pub fn create_test_auth_manifest_with_metadata<C: ImageGeneratorCrypto>(
    image_metadata_list: Vec<AuthManifestImageMetadata>,
    pqc_key_type: FwVerificationPqcKeyType,
    svn: u32,
    crypto: C,
) -> AuthorizationManifest {
    create_test_auth_manifest_with_config(
        image_metadata_list,
        AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        svn,
        crypto,
    )
}

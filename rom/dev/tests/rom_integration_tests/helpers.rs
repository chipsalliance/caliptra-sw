// Licensed under the Apache-2.0 license

use std::mem;
use std::sync::LazyLock;

use caliptra_api::SocManager;
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig,
};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestPrivKeysConfig,
    AuthManifestPubKeysConfig, AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_builder::{firmware, FwId, ImageOptions};
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::{
    memory_layout::{ROM_ORG, ROM_SIZE, ROM_STACK_ORG, ROM_STACK_SIZE, STACK_ORG, STACK_SIZE},
    FMC_ORG, FMC_SIZE, RUNTIME_ORG, RUNTIME_SIZE,
};
use caliptra_drivers::InitDevIdCsrEnvelope;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, CodeRange, Fuses, HwModel, ImageInfo, InitParams, SecurityState, StackInfo,
    StackRange, SubsystemInitParams,
};
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, ModelError};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::*;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageBundle};
use zerocopy::{IntoBytes, TryFromBytes};

pub const PQC_KEY_TYPE: [FwVerificationPqcKeyType; 2] = [
    FwVerificationPqcKeyType::LMS,
    FwVerificationPqcKeyType::MLDSA,
];

pub const LIFECYCLES_PROVISIONED: [DeviceLifecycle; 2] =
    [DeviceLifecycle::Manufacturing, DeviceLifecycle::Production];

pub const LIFECYCLES_ALL: [DeviceLifecycle; 3] = [
    DeviceLifecycle::Unprovisioned,
    DeviceLifecycle::Manufacturing,
    DeviceLifecycle::Production,
];

// Default test MCU firmware used for subsystem mode uploads
pub static DEFAULT_MCU_FW: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut mcu_fw_image = vec![0x00, 0x00, 0x00, 0x6f];
    mcu_fw_image.resize(256, 0);
    mcu_fw_image
});

fn default_soc_manifest(pqc_key_type: FwVerificationPqcKeyType, svn: u32) -> AuthorizationManifest {
    // generate a default SoC manifest if one is not provided in subsystem mode
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);

    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&DEFAULT_MCU_FW).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];

    // Build a signed authorization manifest using the test fake keys
    let vendor_fw_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
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
    };

    let vendor_man_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
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
    };

    let owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig> =
        Some(AuthManifestGeneratorKeyConfig {
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
        });

    let owner_man_key_info: Option<AuthManifestGeneratorKeyConfig> =
        Some(AuthManifestGeneratorKeyConfig {
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
        });

    let gen_config: AuthManifestGeneratorConfig = AuthManifestGeneratorConfig {
        vendor_fw_key_info,
        vendor_man_key_info,
        owner_fw_key_info,
        owner_man_key_info,
        image_metadata_list: metadata,
        version: 1,
        flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        svn,
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate(&gen_config).unwrap()
}

pub fn default_soc_manifest_bytes(pqc_key_type: FwVerificationPqcKeyType, svn: u32) -> Vec<u8> {
    let manifest = default_soc_manifest(pqc_key_type, svn);
    let manifest_bytes = manifest.as_bytes();
    let len = manifest_bytes.len();
    // Pad to a multiple of 256 bytes
    let padded_len = ((len + 255) / 256) * 256;
    let mut padded = vec![0u8; padded_len];
    padded[..len].copy_from_slice(manifest_bytes);
    padded
}

// Matches runtime test helper: uploads via RRI in subsystem mode
pub fn test_upload_firmware(
    model: &mut DefaultHwModel,
    fw_image: &[u8],
    pqc_key_type: FwVerificationPqcKeyType,
) {
    if model.subsystem_mode() {
        model
            .upload_firmware_rri(
                fw_image,
                Some(&default_soc_manifest_bytes(pqc_key_type, 1)),
                Some(&DEFAULT_MCU_FW),
            )
            .unwrap();
    } else {
        model.upload_firmware(fw_image).unwrap();
    }
}

pub fn wait_until_runtime(model: &mut DefaultHwModel) {
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
}

pub fn assert_fatal_fw_load(
    hw: &mut DefaultHwModel,
    pqc_key_type: FwVerificationPqcKeyType,
    data: &[u8],
    err: CaliptraError,
) {
    if hw.subsystem_mode() {
        test_upload_firmware(hw, data, pqc_key_type);
        hw.step_until_fatal_error(err.into(), 1000000)
    } else {
        assert_eq!(
            ModelError::MailboxCmdFailed(err.into()),
            hw.upload_firmware(data).unwrap_err()
        );
    }
}

pub fn rom_from_env() -> &'static FwId<'static> {
    firmware::rom_from_env_fpga(cfg!(any(
        feature = "fpga_subsystem",
        feature = "fpga_realtime"
    )))
}

// Start a firmware load via mailbox (non-blocking), used in tests that
// need to observe intermediate boot statuses during FIRMWARE_LOAD.
pub fn test_start_firmware_load(model: &mut DefaultHwModel, fw_image: &[u8]) {
    model
        .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), fw_image)
        .unwrap();
}

pub fn build_hw_model_and_image_bundle(
    fuses: Fuses,
    image_options: ImageOptions,
) -> (DefaultHwModel, ImageBundle) {
    let image = build_image_bundle(image_options);
    (build_hw_model(fuses), image)
}

pub fn build_hw_model(fuses: Fuses) -> DefaultHwModel {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let image_info = vec![
        ImageInfo::new(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
        ),
    ];
    let mut security_state = SecurityState::from(fuses.life_cycle as u32);
    security_state.set_debug_locked(fuses.debug_locked);
    caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            stack_info: Some(StackInfo::new(image_info)),
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                ..Default::default()
            },
            ..Default::default()
        },
        BootParams {
            fuses,
            ..Default::default()
        },
    )
    .unwrap()
}

pub fn build_image_bundle(image_options: ImageOptions) -> ImageBundle {
    caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        if cfg!(feature = "fpga_subsystem") {
            &firmware::APP_WITH_UART_FPGA
        } else {
            &firmware::APP_WITH_UART
        },
        image_options,
    )
    .unwrap()
}

/// This function matches the to_match string in the haystack string and returns the data
/// after the match until the next newline character.
///
/// # Arguments
///
/// * `to_match` - String to search for
/// * `haystack` - String to search in
pub fn get_data<'a>(to_match: &str, haystack: &'a str) -> &'a str {
    let index = haystack
        .find(to_match)
        .unwrap_or_else(|| panic!("unable to find substr {to_match:?}"));
    haystack[index + to_match.len()..]
        .split('\n')
        .next()
        .unwrap_or("")
}

pub fn get_csr_envelop(hw: &mut DefaultHwModel) -> Result<InitDevIdCsrEnvelope, ModelError> {
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().idevid_csr_ready());
    let mut txn = hw.wait_for_mailbox_receive()?;
    let result = mem::take(&mut txn.req.data);
    txn.respond_success();
    hw.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
    let (csr_envelop, _) = InitDevIdCsrEnvelope::try_read_from_prefix(&result).unwrap();
    Ok(csr_envelop)
}

pub fn change_dword_endianess(data: &mut [u8]) {
    for idx in (0..data.len()).step_by(4) {
        data.swap(idx, idx + 3);
        data.swap(idx + 1, idx + 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "Foo bar baz \n\
                       [idev] ECC CSR = foo bar\n\
                       [idev] ECC CSR = wrong";

    #[test]
    fn test_get_data() {
        assert_eq!("foo bar", get_data("[idev] ECC CSR = ", LOG));

        assert_eq!("", get_data("CSR = wrong", LOG));
    }

    #[test]
    #[should_panic(expected = "unable to find substr \"[idev] FOO = \"")]
    fn test_get_data_not_found() {
        assert_eq!("", get_data("[idev] FOO = ", LOG));
    }
}

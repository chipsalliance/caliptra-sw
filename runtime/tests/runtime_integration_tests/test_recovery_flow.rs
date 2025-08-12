// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use caliptra_auth_man_types::{AuthManifestImageMetadata, ImageMetadataFlags};
use caliptra_emu_bus::{Device, EventData};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, InitParams};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::from_hw_format;
use caliptra_image_gen::ImageGeneratorCrypto;
use zerocopy::IntoBytes;

const RT_READY_FOR_COMMANDS: u32 = 0x600;

#[cfg_attr(
    any(
        feature = "verilator",
        feature = "fpga_realtime",
        feature = "fpga_subsystem"
    ),
    ignore
)]
#[test]
fn test_loads_mcu_fw() {
    // Test that the recovery flow runs and loads MCU's firmware

    let mcu_fw = vec![1, 2, 3, 4];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();
    let mut args = RuntimeTestArgs::default();
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    args.init_params = Some(InitParams {
        rom: &rom,
        subsystem_mode: true,
        ..Default::default()
    });
    args.soc_manifest = Some(soc_manifest);
    args.mcu_fw_image = Some(&mcu_fw);
    let mut model = run_rt_test(args);
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);
    // check that we got an MCU write
    let events = model.events_from_caliptra();
    let mut found = false;
    for event in events {
        if event.dest == Device::MCU && matches!(event.event, EventData::MemoryWrite { .. }) {
            found = true;
            break;
        }
    }
    assert!(found);
}

#[cfg_attr(
    any(
        feature = "verilator",
        feature = "fpga_realtime",
        feature = "fpga_subsystem"
    ),
    ignore
)]
#[test]
fn test_mcu_fw_bad_signature() {
    // Test that the recovery flow runs and loads MCU's firmware

    let mcu_fw = vec![1, 2, 3, 4];
    let bad_mcu_fw = vec![5, 6, 7, 8];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    // add a different digest to the to the SoC manifest
    let digest = from_hw_format(&crypto.sha384_digest(&bad_mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();
    let mut args = RuntimeTestArgs::default();
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    args.init_params = Some(InitParams {
        rom: &rom,
        subsystem_mode: true,
        ..Default::default()
    });
    args.soc_manifest = Some(soc_manifest);
    args.mcu_fw_image = Some(&mcu_fw);
    let mut model = run_rt_test(args);
    model.step_until_fatal_error(
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH.into(),
        30_000_000,
    );
}

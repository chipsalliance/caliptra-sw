// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs};
use caliptra_emu_types::RvSize;
use caliptra_hw_model::{BootParams, CaliptraHwVersion, HwModel, InitParams};

#[test]
fn test_version_2_0_peripheral_slots() {
    let mut bus = CaliptraRootBus::new(CaliptraRootBusArgs {
        hw_version: CaliptraHwVersion::V2_0,
        ..Default::default()
    });

    // In 2.0 mode, 0x1003_0000 should be Mldsa87 ("secp" = 0x73656370)
    let mldsa_name0 = bus.read(RvSize::Word, 0x1003_0000).unwrap();
    assert_eq!(mldsa_name0, 0x73656370);

    // In 2.0 mode, 0x1004_0000 (SHA-3) is unmapped and should return LoadAccessFault
    let sha3_read_res = bus.read(RvSize::Word, 0x1004_0000);
    assert!(matches!(sha3_read_res, Err(BusError::LoadAccessFault)));

    let sha3_write_res = bus.write(RvSize::Word, 0x1004_0000, 0x12345678);
    assert!(matches!(sha3_write_res, Err(BusError::StoreAccessFault)));
}

#[test]
fn test_version_2_1_peripheral_slots() {
    let mut bus = CaliptraRootBus::new(CaliptraRootBusArgs {
        hw_version: CaliptraHwVersion::V2_1,
        ..Default::default()
    });

    // In 2.1 mode, 0x1003_0000 should be Abr ("DSML" = 0x44534D4C)
    let abr_name0 = bus.read(RvSize::Word, 0x1003_0000).unwrap();
    assert_eq!(abr_name0, 0x44534D4C);

    // In 2.1 mode, 0x1004_0000 (SHA-3) is active
    let sha3_read_res = bus.read(RvSize::Word, 0x1004_0000);
    assert!(sha3_read_res.is_ok());
}

#[test]
fn test_hw_model_boot_v2_0_runtime_firmware() {
    let mut model = caliptra_hw_model::new(
        InitParams {
            hw_version: CaliptraHwVersion::V2_0,
            rom: (&caliptra_builder::firmware::ROM_2_0_1_RELEASE).into(),
            random_sram_puf: false,
            ..Default::default()
        },
        BootParams {
            fw_image: Some((&caliptra_builder::firmware::FW_2_0_1_RELEASE).into()),
            ..Default::default()
        },
    )
    .unwrap();

    // Step CPU until 2.0 firmware reaches ready_for_runtime flow state
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    // Assert that the 2.0 runtime is active and ready
    assert!(model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .ready_for_mb_processing());
}

#[test]
fn test_hw_model_boot_v2_1() {
    let mut model = caliptra_hw_model::new(
        InitParams {
            hw_version: CaliptraHwVersion::V2_1,
            rom: (&caliptra_builder::firmware::ROM_WITH_UART).into(),
            random_sram_puf: false,
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();

    model.step_until(|m| m.ready_for_fw());

    assert!(model.ready_for_fw());
}

// Licensed under the Apache-2.0 license

use caliptra_builder::{FwId, APP_WITH_UART, ROM_WITH_UART};
use caliptra_common::RomBootStatus;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};
use zerocopy::FromBytes;

fn run_exported_func(hw: &mut DefaultHwModel, command_id: u32) -> u32 {
    u32::read_from(
        hw.mailbox_execute(command_id, &[])
            .unwrap()
            .unwrap()
            .as_slice(),
    )
    .unwrap()
}

#[test]
fn test_exports() {
    const TEST_FMC: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu", "interactive_test_fmc"],
        workspace_dir: None,
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    let image_bundle =
        caliptra_builder::build_and_sign_image(&TEST_FMC, &APP_WITH_UART, Default::default())
            .unwrap();

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_boot_status(RomBootStatus::ColdResetComplete.into(), true);

    //caliptra_rom_unimplemented_export_2
    assert_eq!(
        run_exported_func(&mut hw, 0x1001_0002),
        u32::from(CaliptraError::ROM_GLOBAL_UNIMPLEMENTED_EXPORT)
    );
    //caliptra_rom_unimplemented_export_3
    assert_eq!(
        run_exported_func(&mut hw, 0x1001_0003),
        u32::from(CaliptraError::ROM_GLOBAL_UNIMPLEMENTED_EXPORT)
    );
    //caliptra_rom_unimplemented_export_4
    assert_eq!(
        run_exported_func(&mut hw, 0x1001_0004),
        u32::from(CaliptraError::ROM_GLOBAL_UNIMPLEMENTED_EXPORT)
    );
    //caliptra_rom_unimplemented_export_5
    assert_eq!(
        run_exported_func(&mut hw, 0x1001_0005),
        u32::from(CaliptraError::ROM_GLOBAL_UNIMPLEMENTED_EXPORT)
    );
    //caliptra_rom_unimplemented_export_6
    assert_eq!(
        run_exported_func(&mut hw, 0x1001_0006),
        u32::from(CaliptraError::ROM_GLOBAL_UNIMPLEMENTED_EXPORT)
    );
    //caliptra_rom_unimplemented_export_7
    assert_eq!(
        run_exported_func(&mut hw, 0x1001_0007),
        u32::from(CaliptraError::ROM_GLOBAL_UNIMPLEMENTED_EXPORT)
    );
}

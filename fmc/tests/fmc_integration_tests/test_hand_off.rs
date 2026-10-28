// Licensed under the Apache-2.0 license
use crate::helpers;
use caliptra_builder::{firmware, ImageOptions};
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams};

#[test]
#[cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
fn test_invalid_fht_is_fatal() {
    use caliptra_api::SocManager;
    use caliptra_drivers::{
        hand_off::FHT_MARKER,
        memory_layout::{DCCM_ORG, DCCM_SIZE, PERSISTENT_DATA_ORG},
        CaliptraError, FirmwareHandoffTable, PersistentData, RomPersistentData,
    };
    use caliptra_hw_model::ModelError;
    use std::mem::offset_of;
    use zerocopy::IntoBytes;

    let rom = caliptra_builder::build_firmware_rom(&firmware::hw_model_tests::TEST_FMC_INVALID_FHT)
        .unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::runtime_tests::BOOT,
        ImageOptions::default(),
    )
    .unwrap();
    for marker in [0, FHT_MARKER] {
        let fht = FirmwareHandoffTable {
            fht_marker: marker,
            ..Default::default()
        };
        let offset = (PERSISTENT_DATA_ORG - DCCM_ORG) as usize
            + offset_of!(PersistentData, rom)
            + offset_of!(RomPersistentData, fht);
        let mut dccm = vec![0u8; DCCM_SIZE as usize];
        dccm[offset..offset + fht.as_bytes().len()].copy_from_slice(fht.as_bytes());

        let mut hw = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                iccm: &image.fmc,
                dccm: &dccm,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        hw.step_until_boot_status(0xf000_0000, true);
        assert!(hw.soc_ifc().cptra_wdt_timer1_en().read().timer1_en());
        assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
        assert_eq!(
            hw.soc_ifc().cptra_fw_error_non_fatal().read(),
            u32::from(CaliptraError::FMC_HANDOFF_NOT_READY_FOR_RT)
        );
        hw.start_mailbox_execute(0x1000_0000, &[]).unwrap();
        let expected_error = u32::from(CaliptraError::FMC_HANDOFF_INVALID_FHT);
        hw.step_until_fatal_error(expected_error, 2_000_000);
        hw.step_until_or_timeout("FMC nonfatal error report", 1_000, |model| {
            model.soc_ifc().cptra_fw_error_non_fatal().read() == expected_error
        });

        for _ in 0..1_000 {
            hw.step();
        }
        assert!(hw.soc_mbox().status().read().status().cmd_failure());
        assert_eq!(
            hw.finish_mailbox_execute(),
            Err(ModelError::MailboxCmdFailed(expected_error))
        );
        assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), expected_error);
        assert_eq!(
            hw.soc_ifc().cptra_fw_error_non_fatal().read(),
            expected_error
        );
        assert!(!hw.soc_ifc().cptra_wdt_timer1_en().read().timer1_en());
        assert!(!hw.soc_ifc().cptra_flow_status().read().ready_for_runtime());
        assert_eq!(hw.soc_ifc().cptra_boot_status().read(), 0xf000_0000);
    }
}

#[test]
fn test_hand_off() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let fuses = Fuses {
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };

        let rom =
            caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
                .unwrap();

        let image = caliptra_builder::build_and_sign_image(
            &firmware::FMC_WITH_UART,
            &firmware::runtime_tests::BOOT,
            image_options,
        )
        .unwrap();

        let mut hw = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                fuses,
                ..Default::default()
            },
            BootParams {
                fw_image: Some(&image.to_bytes().unwrap()),
                ..Default::default()
            },
        )
        .unwrap();

        let mut output = vec![];
        hw.copy_output_until_exit_success(&mut output).unwrap();
    }
}

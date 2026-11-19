// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{FipsVersionResp, MailboxReqHeader, MailboxRespHeader},
    SocManager,
};
#[allow(unused_imports)]
use caliptra_builder::{
    firmware::{self, APP_WITH_UART, APP_WITH_UART_FPGA, FMC_WITH_UART},
    version, ImageOptions,
};
use caliptra_common::{fips::FipsVersionCmd, mailbox_api::CommandId, RomBootStatus::*};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState,
    SubsystemInitParams,
};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_test::image_pk_desc_hash;
use zerocopy::{FromBytes, IntoBytes};

use crate::helpers;

#[test]
fn test_warm_reset_success() {
    check_warm_reset_success(false);
}

#[cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
#[test]
fn test_dual_itrng_cold_and_warm_reset() {
    check_warm_reset_success(true);
}

/// ROM must fail closed, not fall back to ES0, when ES1 never delivers.
#[cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
#[test]
fn test_dual_itrng_missing_es1_is_fatal_in_rom() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new_unbooted(InitParams {
        rom: &rom,
        subsystem_mode: true,
        trng_mode: Some(caliptra_hw_model::TrngMode::Internal),
        itrng1_nibbles: Some(Box::new(core::iter::empty())),
        ss_init_params: SubsystemInitParams {
            enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();
    assert!(hw.soc_ifc().cptra_hw_config().read().dual_i_trng_en());
    hw.boot(BootParams::default()).unwrap();
    let start = std::time::Instant::now();
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(300),
            "ROM did not report a fatal error with ES1 withheld"
        );
        assert!(!hw.soc_ifc().cptra_flow_status().read().ready_for_runtime());
        hw.step();
    }
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::DRIVER_CSRNG_ENTROPY_TIMEOUT)
    );
    // ready_for_fw() is unconditionally true on the FPGA subsystem model.
    let flow = hw.soc_ifc().cptra_flow_status().read();
    assert!(!flow.ready_for_mb_processing() && !flow.ready_for_runtime());
}

#[cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
#[test]
fn test_dual_itrng_sticky_fault_is_fatal_in_rom() {
    let rom = caliptra_builder::build_firmware_rom(helpers::rom_from_env()).unwrap();
    let mut hw = caliptra_hw_model::new_unbooted(InitParams {
        rom: &rom,
        subsystem_mode: true,
        trng_mode: Some(caliptra_hw_model::TrngMode::Internal),
        itrng1_nibbles: Some(InitParams::default().itrng_nibbles),
        ..Default::default()
    })
    .unwrap();
    hw.inject_entropy_combiner_error(1);
    hw.boot(BootParams::default()).unwrap();
    hw.step_until_fatal_error(
        CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT.into(),
        20_000_000,
    );
    assert_eq!(hw.entropy_combiner_kat_starts(), 0);
    assert!(!hw.ready_for_fw());
}

fn check_warm_reset_success(dual_itrng: bool) {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let fw_svn = 9;
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        if cfg!(feature = "fpga_subsystem") {
            &firmware::APP_WITH_UART_FPGA
        } else {
            &firmware::APP_WITH_UART
        },
        ImageOptions {
            fw_svn,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let soc_manifest = &crate::helpers::default_soc_manifest_bytes(Default::default(), fw_svn);
    let boot_params = BootParams {
        fw_image: Some(&binding),
        soc_manifest: Some(soc_manifest),
        mcu_fw_image: Some(&crate::helpers::DEFAULT_MCU_FW),
        ..Default::default()
    };

    let mut hw = caliptra_hw_model::new_unbooted(InitParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            fw_svn: [0x7F, 0, 0, 0], // Equals 7
            ..Default::default()
        },
        rom: &rom,
        subsystem_mode: true,
        security_state,
        trng_mode: if dual_itrng {
            Some(caliptra_hw_model::TrngMode::Internal)
        } else {
            InitParams::default().trng_mode
        },
        itrng1_nibbles: dual_itrng.then(|| InitParams::default().itrng_nibbles),
        ss_init_params: SubsystemInitParams {
            enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();
    if dual_itrng {
        let regs = hw.soc_ifc();
        regs.cptra_i_trng_entropy_config_0()
            .write(|w| w.low_threshold(251).high_threshold(771));
        regs.cptra_i_trng_entropy_config_1()
            .write(|w| w.repetition_count(56).alert_threshold(3));
        regs.cptra_i_trng_entropy_config_2().write(|w| {
            w.fips_window_size(1024)
                .single_bit_mode(true)
                .rng_bit_sel(2)
        });
        regs.cptra_i_trng1_entropy_config_0()
            .write(|w| w.high_threshold(325));
        regs.cptra_i_trng1_entropy_config_1()
            .write(|w| w.repetition_count(59).alert_threshold(4));
        regs.cptra_i_trng1_entropy_config_2()
            .write(|w| w.fips_window_size(512));
    }
    if dual_itrng {
        assert!(hw.soc_ifc().cptra_hw_config().read().dual_i_trng_en());
    }
    hw.boot(boot_params).unwrap();

    let wait_for_runtime = |hw: &mut DefaultHwModel| {
        hw.step_until_or_timeout("Runtime ready", 20_000_000, |m| {
            assert_eq!(m.soc_ifc().cptra_fw_error_fatal().read(), 0);
            m.boot_complete()
        });
    };
    wait_for_runtime(&mut hw);
    #[cfg(not(any(
        feature = "verilator",
        feature = "fpga_realtime",
        feature = "fpga_subsystem"
    )))]
    if dual_itrng {
        assert_eq!(hw.entropy_combiner_kat_starts(), 1);
    }
    hw.warm_reset_flow().unwrap();
    wait_for_runtime(&mut hw);
    #[cfg(not(any(
        feature = "verilator",
        feature = "fpga_realtime",
        feature = "fpga_subsystem"
    )))]
    if dual_itrng {
        assert_eq!(hw.entropy_combiner_kat_starts(), 2);
    }
    if dual_itrng {
        hw.output().take(usize::MAX);
        helpers::test_start_firmware_load(&mut hw, &binding);
        assert_eq!(hw.finish_mailbox_execute(), Ok(None));
        // On FPGA, log output from before the update can still arrive late, so
        // only accept a Runtime banner printed after the update-reset success.
        hw.step_until_or_timeout("updated Runtime listening", 20_000_000, |m| {
            assert_eq!(m.soc_ifc().cptra_fw_error_fatal().read(), 0);
            let out = m.output().peek();
            out.find("[update-reset Success]")
                .is_some_and(|i| out[i..].contains("[rt] RT listening for mailbox commands"))
        });
        #[cfg(not(any(
            feature = "verilator",
            feature = "fpga_realtime",
            feature = "fpga_subsystem"
        )))]
        assert_eq!(hw.entropy_combiner_kat_starts(), 2);
        wait_for_runtime(&mut hw);
    }
}

#[test]
fn test_warm_reset_during_cold_boot_before_image_validation() {
    let fuses = Fuses {
        life_cycle: DeviceLifecycle::Production,
        ..Default::default()
    };

    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Step till Cold boot starts
    hw.step_until(|m| m.ready_for_fw());

    // Perform a warm reset
    hw.warm_reset_flow().unwrap();

    // Wait for error
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        hw.step();
    }
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET)
    );
}

#[test]
#[cfg(not(feature = "fpga_subsystem"))]
fn test_warm_reset_during_cold_boot_during_image_validation() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            life_cycle: DeviceLifecycle::Unprovisioned,
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };

        let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);

        helpers::test_start_firmware_load(&mut hw, &image_bundle.to_bytes().unwrap());

        hw.step_until_boot_status(FwProcessorManifestLoadComplete.into(), true);

        // Step for few times to land in image validation
        for _ in 0..1000 {
            hw.step();
        }

        // Perform a warm reset
        hw.warm_reset_flow().unwrap();

        // Wait for error
        while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
            hw.step();
        }
        assert_eq!(
            hw.soc_ifc().cptra_fw_error_fatal().read(),
            u32::from(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET)
        );
    }
}

#[test]
#[cfg(not(feature = "fpga_subsystem"))]
fn test_warm_reset_during_cold_boot_after_image_validation() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            life_cycle: DeviceLifecycle::Unprovisioned,
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };

        let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);

        helpers::test_upload_firmware(&mut hw, &image_bundle.to_bytes().unwrap(), *pqc_key_type);

        // Step till after last step in cold boot is complete
        hw.step_until_boot_status(FmcAliasDerivationComplete.into(), true);

        // Perform a warm reset
        hw.warm_reset_flow().unwrap();

        // Wait for error
        while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
            hw.step();
        }
        assert_eq!(
            hw.soc_ifc().cptra_fw_error_fatal().read(),
            u32::from(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET)
        );
    }
}

#[test]
fn test_warm_reset_during_update_reset() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            life_cycle: DeviceLifecycle::Unprovisioned,
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };

        let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);

        helpers::test_upload_firmware(&mut hw, &image_bundle.to_bytes().unwrap(), *pqc_key_type);
        helpers::wait_until_runtime(&mut hw);

        // Trigger an update reset with "new" firmware
        helpers::test_start_firmware_load(&mut hw, &image_bundle.to_bytes().unwrap());

        if cfg!(not(feature = "fpga_realtime")) {
            hw.step_until_boot_status(KatStarted.into(), true);
            hw.step_until_boot_status(KatComplete.into(), true);
            hw.step_until_boot_status(UpdateResetStarted.into(), false);
        }

        assert_eq!(hw.finish_mailbox_execute(), Ok(None));

        // Step till after last step in update reset is complete
        hw.step_until(|model| {
            model.soc_ifc().cptra_boot_status().read() >= UpdateResetLoadImageComplete.into()
        });

        // Perform a warm reset
        hw.warm_reset_flow().unwrap();

        // Wait for error
        while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
            hw.step();
        }
        assert_eq!(
            hw.soc_ifc().cptra_fw_error_fatal().read(),
            u32::from(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_UPDATE_RESET)
        );
    }
}

const HW_REV_ID: u32 = 0x0022;

fn test_version(
    hw: &mut DefaultHwModel,
    hw_rev: u32,
    rom_version: u32,
    fmc_version: u32,
    app_version: u32,
) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };

    let response = hw
        .mailbox_execute(CommandId::VERSION.into(), payload.as_bytes())
        .unwrap()
        .unwrap();

    let version_resp = FipsVersionResp::ref_from_bytes(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        version_resp.hdr.chksum,
        0x0,
        &version_resp.as_bytes()[core::mem::size_of_val(&version_resp.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(
        version_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Verify Version Info
    assert_eq!(version_resp.mode, FipsVersionCmd::MODE);

    // fips_rev[0] is hw_rev_id
    // fips_rev[1] is FMC version at 31:16 and ROM version at 15:0
    // fips_rev[2] is app (fw) version
    let received_hw_rev = version_resp.fips_rev[0];
    let received_rom_version = version_resp.fips_rev[1] & 0x0000FFFF;
    let received_fmc_version = (version_resp.fips_rev[1] & 0xFFFF0000) >> 16;
    let received_app_version = version_resp.fips_rev[2];

    assert_eq!(received_hw_rev, hw_rev);
    assert_eq!(received_rom_version, rom_version);
    assert_eq!(received_fmc_version, fmc_version);
    assert_eq!(received_app_version, app_version);
    let name = &version_resp.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());
}

#[test]
fn test_warm_reset_version() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let fmc_version = 3;
    let app_version = 5;

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        if cfg!(feature = "fpga_subsystem") {
            &firmware::APP_WITH_UART_FPGA
        } else {
            &firmware::APP_WITH_UART
        },
        ImageOptions {
            fmc_version,
            app_version,
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let (soc_manifest, mcu_fw_image) = if cfg!(feature = "fpga_subsystem") {
        (
            Some(crate::helpers::default_soc_manifest_bytes(
                FwVerificationPqcKeyType::MLDSA,
                1,
            )),
            Some(&crate::helpers::DEFAULT_MCU_FW),
        )
    } else {
        (None, None)
    };

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fw_image: Some(&binding),
        soc_manifest: soc_manifest.as_deref(),
        mcu_fw_image: mcu_fw_image.map(|v| v.as_ref()),
        ..Default::default()
    };

    let mut hw = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0x7F, 0, 0, 0], // Equals 7
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                ..Default::default()
            },
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    while !hw.boot_complete() {
        hw.step();
    }

    test_version(
        &mut hw,
        HW_REV_ID,
        version::get_rom_version().into(),
        fmc_version.into(),
        app_version,
    );

    // Perform warm reset
    hw.warm_reset_flow().unwrap();

    // Wait for boot
    while !hw.boot_complete() {
        hw.step();
    }

    test_version(
        &mut hw,
        HW_REV_ID,
        version::get_rom_version().into(),
        fmc_version.into(),
        app_version,
    );
}

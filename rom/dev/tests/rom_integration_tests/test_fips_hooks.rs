// Licensed under the Apache-2.0 license

use crate::helpers;
use caliptra_api::SocManager;
use caliptra_builder::firmware::{
    APP_WITH_UART, APP_WITH_UART_FPGA, FMC_WITH_UART, ROM_WITH_FIPS_TEST_HOOKS,
    ROM_WITH_FIPS_TEST_HOOKS_FPGA,
};
use caliptra_builder::ImageOptions;
use caliptra_common::{
    mailbox_api::{CommandId, MailboxReqHeader},
    RomBootStatus,
};
use caliptra_drivers::{CaliptraError, FipsTestHook};
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState,
    TrngMode,
};
use zerocopy::IntoBytes;

fn boot_with_fips_hook(hook: u8, init_params: InitParams) -> DefaultHwModel {
    let rom = caliptra_builder::build_firmware_rom(
        if cfg!(any(feature = "fpga_realtime", feature = "fpga_subsystem")) {
            &ROM_WITH_FIPS_TEST_HOOKS_FPGA
        } else {
            &ROM_WITH_FIPS_TEST_HOOKS
        },
    )
    .unwrap();

    caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..init_params
        },
        BootParams {
            initial_dbg_manuf_service_reg: u32::from(hook) << 16,
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
#[cfg_attr(
    feature = "fpga_subsystem",
    ignore = "boot-time FIPS hook injection is unsupported"
)]
fn test_boot_kat_failures_non_fatal_unprovisioned() {
    for subsystem_mode in [false, true] {
        for (hook, error, trng_mode) in [
            (
                FipsTestHook::SHA1_DIGEST_FAILURE,
                CaliptraError::KAT_SHA1_DIGEST_FAILURE,
                None,
            ),
            (
                FipsTestHook::SHA1_CORRUPT_DIGEST,
                CaliptraError::KAT_SHA1_DIGEST_MISMATCH,
                None,
            ),
            (
                FipsTestHook::SHA256_DIGEST_FAILURE,
                CaliptraError::KAT_SHA256_DIGEST_FAILURE,
                None,
            ),
            (
                FipsTestHook::SHA256_CORRUPT_DIGEST,
                CaliptraError::KAT_SHA256_DIGEST_MISMATCH,
                None,
            ),
            (
                FipsTestHook::SHA2_512_384_ACC_DIGEST_512_FAILURE,
                CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_FAILURE,
                None,
            ),
            (
                FipsTestHook::SHA2_512_384_ACC_CORRUPT_DIGEST_512,
                CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_MISMATCH,
                None,
            ),
            (
                FipsTestHook::CSRNG_GENERATE_FAILURE,
                CaliptraError::KAT_CSRNG_GENERATE_FAILURE,
                Some(TrngMode::Internal),
            ),
            (
                FipsTestHook::CSRNG_CORRUPT_OUTPUT,
                CaliptraError::KAT_CSRNG_DIGEST_MISMATCH,
                Some(TrngMode::Internal),
            ),
            (
                FipsTestHook::CSRNG_RESEED_FAILURE,
                CaliptraError::KAT_CSRNG_RESEED_FAILURE,
                Some(TrngMode::Internal),
            ),
        ] {
            let mut hw = boot_with_fips_hook(
                hook,
                InitParams {
                    subsystem_mode,
                    trng_mode,
                    ..Default::default()
                },
            );
            hw.step_until(|m| {
                m.soc_ifc().cptra_fw_error_non_fatal().read() == u32::from(error)
                    || m.soc_ifc().cptra_fw_error_fatal().read() != 0
            });
            assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
            assert_eq!(
                hw.soc_ifc().cptra_fw_error_non_fatal().read(),
                u32::from(error)
            );
            hw.step_until_boot_status(RomBootStatus::KatComplete.into(), true);
            assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
            assert_ne!(hw.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
        }
    }
}

#[test]
#[cfg_attr(
    feature = "fpga_subsystem",
    ignore = "boot-time FIPS hook injection is unsupported"
)]
fn test_boot_kat_failures_fatal_provisioned() {
    for lifecycle in [
        DeviceLifecycle::Manufacturing,
        DeviceLifecycle::Reserved2,
        DeviceLifecycle::Production,
    ] {
        for (hook, error, trng_mode) in [
            (
                FipsTestHook::SHA1_DIGEST_FAILURE,
                CaliptraError::KAT_SHA1_DIGEST_FAILURE,
                None,
            ),
            (
                FipsTestHook::SHA256_DIGEST_FAILURE,
                CaliptraError::KAT_SHA256_DIGEST_FAILURE,
                None,
            ),
            (
                FipsTestHook::SHA2_512_384_ACC_DIGEST_512_FAILURE,
                CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_FAILURE,
                None,
            ),
            (
                FipsTestHook::SHA2_512_384_ACC_CORRUPT_DIGEST_512,
                CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_MISMATCH,
                None,
            ),
            (
                FipsTestHook::CSRNG_GENERATE_FAILURE,
                CaliptraError::KAT_CSRNG_GENERATE_FAILURE,
                Some(TrngMode::Internal),
            ),
        ] {
            let mut hw = boot_with_fips_hook(
                hook,
                InitParams {
                    security_state: *SecurityState::default().set_device_lifecycle(lifecycle),
                    trng_mode,
                    ..Default::default()
                },
            );
            hw.step_until_fatal_error(error.into(), 30_000_000);
            assert!(!hw
                .soc_ifc()
                .cptra_flow_status()
                .read()
                .ready_for_mb_processing());
        }
    }
}

#[test]
#[cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
fn test_boot_csrng_restore_failure_is_fatal() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    for hook in [
        FipsTestHook::RSVD,
        FipsTestHook::CSRNG_CORRUPT_OUTPUT,
        FipsTestHook::CSRNG_GENERATE_FAILURE,
        FipsTestHook::CSRNG_RESEED_FAILURE,
    ] {
        let bad_entropy = Arc::new(AtomicBool::new(false));
        let inject_bad_entropy = bad_entropy.clone();
        let mut nibbles = InitParams::default().itrng_nibbles;
        let mut hw = boot_with_fips_hook(
            FipsTestHook::HALT_SELF_TESTS,
            InitParams {
                trng_mode: Some(TrngMode::Internal),
                itrng_nibbles: Box::new(std::iter::from_fn(move || {
                    if inject_bad_entropy.load(Ordering::Relaxed) {
                        Some(0b1111)
                    } else {
                        nibbles.next()
                    }
                })),
                ..Default::default()
            },
        );

        // Let the early CSRNG KAT restore normally before failing live entropy.
        hw.step_until(|m| {
            m.soc_ifc().cptra_dbg_manuf_service_reg().read() >> 16
                == u32::from(FipsTestHook::COMPLETE)
        });
        hw.soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| u32::from(FipsTestHook::CONTINUE) << 16);
        hw.step_until(|m| {
            m.soc_ifc().cptra_dbg_manuf_service_reg().read() >> 16
                == u32::from(FipsTestHook::COMPLETE)
        });
        bad_entropy.store(true, Ordering::Relaxed);
        hw.soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| u32::from(hook) << 16);

        hw.step_until_fatal_error(CaliptraError::KAT_CSRNG_RESTORE_FAILURE.into(), 30_000_000);
        assert_eq!(hw.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
        assert!(!hw
            .soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing());
    }
}

#[test]
#[cfg_attr(
    feature = "fpga_subsystem",
    ignore = "boot-time FIPS hook injection is unsupported"
)]
fn test_boot_continues_after_kat_failure() {
    let image_options = ImageOptions::default();
    let pqc_key_type = image_options.pqc_key_type;
    let image_bundle = helpers::build_image_bundle(image_options);
    let image = image_bundle.to_bytes().unwrap();

    for subsystem_mode in [false, true] {
        for (hook, error, trng_mode) in [
            (
                FipsTestHook::SHA1_CORRUPT_DIGEST,
                CaliptraError::KAT_SHA1_DIGEST_MISMATCH,
                None,
            ),
            (
                FipsTestHook::SHA2_512_384_ACC_DIGEST_512_FAILURE,
                CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_FAILURE,
                None,
            ),
            (
                FipsTestHook::SHA2_512_384_ACC_CORRUPT_DIGEST_512,
                CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_MISMATCH,
                None,
            ),
            (
                FipsTestHook::CSRNG_GENERATE_FAILURE,
                CaliptraError::KAT_CSRNG_GENERATE_FAILURE,
                Some(TrngMode::Internal),
            ),
        ] {
            let mut hw = boot_with_fips_hook(
                hook,
                InitParams {
                    fuses: Fuses {
                        fuse_pqc_key_type: pqc_key_type as u32,
                        ..Default::default()
                    },
                    subsystem_mode,
                    trng_mode,
                    ..Default::default()
                },
            );
            hw.step_until_boot_status(RomBootStatus::KatComplete.into(), true);
            assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
            assert_eq!(
                hw.soc_ifc().cptra_fw_error_non_fatal().read(),
                u32::from(error)
            );
            helpers::test_upload_firmware(&mut hw, &image, pqc_key_type);
            hw.step_until_fatal_error(
                CaliptraError::ROM_GLOBAL_FIPS_HOOKS_ROM_EXIT.into(),
                30_000_000,
            );
        }
    }
}

#[test]
#[cfg_attr(
    feature = "fpga_subsystem",
    ignore = "boot-time FIPS hook injection is unsupported"
)]
fn test_boot_kat_failure_does_not_ignore_fw_signature_failure() {
    let mut hw = boot_with_fips_hook(FipsTestHook::SHA1_CORRUPT_DIGEST, InitParams::default());
    hw.step_until(|m| {
        m.soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing()
            || m.soc_ifc().cptra_fw_error_fatal().read() != 0
    });
    assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::KAT_SHA1_DIGEST_MISMATCH)
    );

    let image_options = ImageOptions::default();
    let pqc_key_type = image_options.pqc_key_type;
    let mut image_bundle = helpers::build_image_bundle(image_options);
    image_bundle.manifest.preamble.vendor_sigs.ecc_sig.r.fill(0);
    helpers::assert_fatal_fw_load(
        &mut hw,
        pqc_key_type,
        &image_bundle.to_bytes().unwrap(),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG,
    );
}

#[test]
fn test_boot_kat_exception_does_not_apply_to_self_test_start() {
    let mut hw = boot_with_fips_hook(FipsTestHook::RSVD, InitParams::default());
    hw.step_until_boot_status(RomBootStatus::LDevIdDerivationComplete.into(), true);
    hw.soc_ifc()
        .cptra_dbg_manuf_service_reg()
        .write(|_| u32::from(FipsTestHook::SHA1_DIGEST_FAILURE) << 16);
    let command = u32::from(CommandId::SELF_TEST_START);
    let request = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(command, &[]),
    };
    hw.start_mailbox_execute(command, request.as_bytes())
        .unwrap();
    hw.step_until_fatal_error(CaliptraError::KAT_SHA1_DIGEST_FAILURE.into(), 30_000_000);
}

#[test]
fn test_fips_hook_exit() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let fpga = cfg!(any(feature = "fpga_realtime", feature = "fpga_subsystem"));
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let rom = caliptra_builder::build_firmware_rom(if fpga {
            &ROM_WITH_FIPS_TEST_HOOKS_FPGA
        } else {
            &ROM_WITH_FIPS_TEST_HOOKS
        })
        .unwrap();

        let fuses = Fuses {
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };

        let image_bundle = caliptra_builder::build_and_sign_image(
            &FMC_WITH_UART,
            if fpga {
                &APP_WITH_UART
            } else {
                &APP_WITH_UART_FPGA
            },
            image_options,
        )
        .unwrap()
        .to_bytes()
        .unwrap();

        let init_params = InitParams {
            fuses,
            rom: &rom,
            ..Default::default()
        };

        let boot_params = BootParams {
            fw_image: Some(&image_bundle),
            ..Default::default()
        };

        let mut hw = caliptra_hw_model::new(init_params, boot_params).unwrap();

        // Wait for fatal error
        hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

        // Verify fatal code is correct
        assert_eq!(
            hw.soc_ifc().cptra_fw_error_fatal().read(),
            u32::from(CaliptraError::ROM_GLOBAL_FIPS_HOOKS_ROM_EXIT)
        );
    }
}

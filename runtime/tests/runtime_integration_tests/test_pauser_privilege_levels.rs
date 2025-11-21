// Licensed under the Apache-2.0 license

use crate::common::PQC_KEY_TYPE;
use caliptra_api::{
    mailbox::{RevokeExportedCdiHandleReq, SignWithExportedEcdsaReq},
    SocManager,
};
use caliptra_builder::{
    build_firmware_elf,
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    CertifyKeyExtendedFlags, CertifyKeyExtendedReq, CommandId, MailboxReq, MailboxReqHeader,
    PopulateIdevEcc384CertReq, StashMeasurementReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_elf::ElfExecutable;
use caliptra_image_gen::{ImageGenerator, ImageGeneratorConfig};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageSignData};
use caliptra_runtime::{
    RtBootStatus, PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD,
    PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD,
};

use dpe::{
    commands::{
        CertifyKeyCmd, CertifyKeyFlags, Command, DeriveContextCmd, DeriveContextFlags, InitCtxCmd,
        RotateCtxCmd, RotateCtxFlags,
    },
    context::ContextHandle,
    response::Response,
    DPE_PROFILE,
};
use zerocopy::IntoBytes;

use crate::common::{
    assert_error, execute_dpe_cmd, run_rt_test, run_rt_test_pqc, DpeResult, RuntimeTestArgs,
    TEST_LABEL,
};

const DATA: [u8; DPE_PROFILE.get_hash_size()] = [0u8; 48];

#[test]
fn test_pl0_derive_context_dpe_context_thresholds() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // First rotate the default context so that we don't run into an error
    // when trying to retain the default context in derive child.
    let rotate_ctx_cmd = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::RotateCtx(&rotate_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::RotateCtx(rotate_ctx_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let mut handle = rotate_ctx_resp.handle;

    // Call DeriveContext with PL0 enough times to breach the threshold on the last iteration.
    // 2 PL0 contexts are used by default by Caliptra. When we initialize DPE, we measure mailbox valid pausers in pl0_pauser's locality.
    // The RT Journey measurement also is counted against PL0's limit. Thus, we can call derive child
    // from PL0 exactly 14 times, and the last iteration of this loop, is expected to throw a threshold reached error.
    let num_iterations = PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD - 1;
    for i in 0..num_iterations {
        let derive_context_cmd = DeriveContextCmd {
            handle,
            data: DATA,
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
        };

        // If we are on the last call to DeriveContext, expect that we get a RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED error.
        if i == num_iterations - 1 {
            let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::DeriveContext(&derive_context_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
            assert!(resp.is_none());
            break;
        }

        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::DeriveContext(&derive_context_cmd),
            DpeResult::Success,
        );
        let Some(Response::DeriveContext(derive_context_resp)) = resp else {
            panic!("Wrong response type!");
        };
        handle = derive_context_resp.handle;
    }
}

#[test]
fn test_pl1_derive_context_dpe_context_thresholds() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut image_opts = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        image_opts.vendor_config.pl0_pauser = None;

        let args = RuntimeTestArgs {
            test_image_options: Some(image_opts),
            ..Default::default()
        };

        let mut model = run_rt_test_pqc(args, *pqc_key_type);

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        // First initialize a simulation context in locality 1
        // so that we get a non-default handle which we can use
        // when calling DeriveContext with the RETAIN_PARENT_CONTEXT flag
        let init_ctx_cmd = InitCtxCmd::new_simulation();
        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::InitCtx(&init_ctx_cmd),
            DpeResult::Success,
        );
        let Some(Response::InitCtx(init_ctx_resp)) = resp else {
            panic!("Wrong response type!");
        };
        let mut handle = init_ctx_resp.handle;

        // Call DeriveContext with PL1 enough times to breach the threshold on the last iteration.
        // Note that this loop runs exactly PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD times.
        // Then, we initialize a simulation context in locality 1. Thus, we can call derive child
        // from PL1 exactly 16 - 1 = 15 times, and the last iteration of this loop, is expected to throw a threshold breached error.
        let num_iterations = PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD;
        for i in 0..num_iterations {
            let derive_context_cmd = DeriveContextCmd {
                handle,
                data: DATA,
                flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
                tci_type: 0,
                target_locality: 0,
            };

            // If we are on the last call to DeriveContext, expect that we get a RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED error.
            if i == num_iterations - 1 {
                let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::DeriveContext(&derive_context_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
                assert!(resp.is_none());
                break;
            }

            let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::DeriveContext(&derive_context_cmd),
                DpeResult::Success,
            );
            let Some(Response::DeriveContext(derive_context_resp)) = resp else {
                panic!("Wrong response type!");
            };
            handle = derive_context_resp.handle;
        }
    }
}

#[test]
fn test_pl0_init_ctx_dpe_context_thresholds() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // 2 PL0 contexts are used by Caliptra
    let num_iterations = PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD - 1;
    for i in 0..num_iterations {
        let init_ctx_cmd = InitCtxCmd::new_simulation();

        // If we are on the last call to InitializeContext, expect that we get a PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED error.
        if i == num_iterations - 1 {
            let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::InitCtx(&init_ctx_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
            assert!(resp.is_none());
            break;
        }

        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::InitCtx(&init_ctx_cmd),
            DpeResult::Success,
        );
        let Some(Response::InitCtx(_)) = resp else {
            panic!("Wrong response type!");
        };
    }
}

#[test]
fn test_pl1_init_ctx_dpe_context_thresholds() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut image_opts = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        image_opts.vendor_config.pl0_pauser = None;

        let args = RuntimeTestArgs {
            test_image_options: Some(image_opts),
            ..Default::default()
        };

        let mut model = run_rt_test_pqc(args, *pqc_key_type);

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        let num_iterations = PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD;
        for i in 0..(num_iterations + 1) {
            let init_ctx_cmd = InitCtxCmd::new_simulation();

            // InitCtx should fail on the PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD iteration
            if i == num_iterations {
                let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::InitCtx(&init_ctx_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
                assert!(resp.is_none());
                break;
            }

            let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::InitCtx(&init_ctx_cmd),
                DpeResult::Success,
            );
            let Some(Response::InitCtx(_)) = resp else {
                panic!("Wrong response type!");
            };
        }
    }
}

#[test]
fn test_change_locality() {
    let args = RuntimeTestArgs {
        ..Default::default()
    };

    let mut model = run_rt_test(args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });
    model.set_axi_user(0x01);

    let derive_context_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: DATA,
        flags: DeriveContextFlags::CHANGE_LOCALITY
            | DeriveContextFlags::MAKE_DEFAULT
            | DeriveContextFlags::INPUT_ALLOW_X509,
        tci_type: 0,
        target_locality: 2,
    };

    let _ = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&derive_context_cmd),
        DpeResult::Success,
    )
    .unwrap();

    model.set_axi_user(0x02);

    let derive_context_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: DATA,
        flags: DeriveContextFlags::MAKE_DEFAULT,
        tci_type: 0,
        target_locality: 2,
    };

    let _ = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&derive_context_cmd),
        DpeResult::Success,
    )
    .unwrap();
}

#[test]
fn test_populate_idev_cannot_be_called_from_pl1() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut image_opts = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        image_opts.vendor_config.pl0_pauser = None;

        let args = RuntimeTestArgs {
            test_image_options: Some(image_opts),
            ..Default::default()
        };
        let mut model = run_rt_test_pqc(args, *pqc_key_type);

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        let mut pop_idev_cmd =
            MailboxReq::PopulateIdevEcc384Cert(PopulateIdevEcc384CertReq::default());
        pop_idev_cmd.populate_chksum().unwrap();

        let resp = model
            .mailbox_execute(
                u32::from(CommandId::POPULATE_IDEV_ECC384_CERT),
                pop_idev_cmd.as_bytes().unwrap(),
            )
            .unwrap_err();
        assert_error(
            &mut model,
            CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
            resp,
        );
    }
}

#[test]
fn test_stash_measurement_cannot_be_called_from_pl1() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut image_opts = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        image_opts.vendor_config.pl0_pauser = None;

        let args = RuntimeTestArgs {
            test_image_options: Some(image_opts),
            ..Default::default()
        };
        let mut model = run_rt_test_pqc(args, *pqc_key_type);

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq::default());
        cmd.populate_chksum().unwrap();

        let resp = model
            .mailbox_execute(
                u32::from(CommandId::STASH_MEASUREMENT),
                cmd.as_bytes().unwrap(),
            )
            .unwrap_err();
        assert_error(
            &mut model,
            CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
            resp,
        );
    }
}

#[test]
fn test_sign_with_exported_ecdsa_cannot_be_called_from_pl1() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;
    image_opts.pqc_key_type = FwVerificationPqcKeyType::LMS;

    let args = RuntimeTestArgs {
        test_image_options: Some(image_opts),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq::default());
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::SIGN_WITH_EXPORTED_ECDSA),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        resp,
    );
}

#[test]
fn test_revoke_export_cdi_handle_cannot_be_called_from_pl1() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;
    image_opts.pqc_key_type = FwVerificationPqcKeyType::LMS;

    let args = RuntimeTestArgs {
        test_image_options: Some(image_opts),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq::default());
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::REVOKE_EXPORTED_CDI_HANDLE),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        resp,
    );
}

#[test]
fn test_export_cdi_cannot_be_called_from_pl1() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;
    image_opts.pqc_key_type = FwVerificationPqcKeyType::LMS;

    let args = RuntimeTestArgs {
        test_image_options: Some(image_opts),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let get_cert_chain_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: [0; DPE_PROFILE.get_tci_size()],
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 0,
        target_locality: 0,
    };
    let _ = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&get_cert_chain_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL),
    );
}

#[test]
fn test_certify_key_x509_cannot_be_called_from_pl1() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut image_opts = ImageOptions::default();
        image_opts.vendor_config.pl0_pauser = None;
        image_opts.pqc_key_type = *pqc_key_type;

        let args = RuntimeTestArgs {
            test_image_options: Some(image_opts),
            ..Default::default()
        };

        let mut model = run_rt_test_pqc(args, *pqc_key_type);

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        let certify_key_cmd = CertifyKeyCmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCmd::FORMAT_X509,
        };
        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::CertifyKey(&certify_key_cmd),
            DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL),
        );
        assert!(resp.is_none());
    }
}

#[test]
fn test_certify_key_extended_cannot_be_called_from_pl1() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut image_opts = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        image_opts.vendor_config.pl0_pauser = None;

        let args = RuntimeTestArgs {
            test_image_options: Some(image_opts),
            ..Default::default()
        };

        let mut model = run_rt_test_pqc(args, *pqc_key_type);

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        let mut certify_key_extended_cmd = MailboxReq::CertifyKeyExtended(CertifyKeyExtendedReq {
            hdr: MailboxReqHeader { chksum: 0 },
            certify_key_req: [0u8; CertifyKeyExtendedReq::CERTIFY_KEY_REQ_SIZE],
            flags: CertifyKeyExtendedFlags::empty(),
        });
        certify_key_extended_cmd.populate_chksum().unwrap();

        let resp = model
            .mailbox_execute(
                u32::from(CommandId::CERTIFY_KEY_EXTENDED),
                certify_key_extended_cmd.as_bytes().unwrap(),
            )
            .unwrap_err();
        assert_error(
            &mut model,
            CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
            resp,
        );
    }
}

#[test]
fn test_derive_context_cannot_be_called_from_pl1_if_changes_locality_to_pl0() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut image_opts = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        image_opts.vendor_config.pl0_pauser = None;

        let args = RuntimeTestArgs {
            test_image_options: Some(image_opts),
            ..Default::default()
        };

        let mut model = run_rt_test_pqc(args, *pqc_key_type);

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        // init ctx since we have currently have no parent handle for pl1
        let init_ctx_cmd = InitCtxCmd::new_simulation();
        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::InitCtx(&init_ctx_cmd),
            DpeResult::Success,
        );
        let Some(Response::InitCtx(init_ctx_resp)) = resp else {
            panic!("Wrong response type!");
        };

        let derive_context_cmd = DeriveContextCmd {
            handle: init_ctx_resp.handle,
            data: DATA,
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::CHANGE_LOCALITY,
            tci_type: 0,
            target_locality: 0,
        };
        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::DeriveContext(&derive_context_cmd),
            DpeResult::MboxCmdFailure(
                caliptra_drivers::CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
            ),
        );
        assert!(resp.is_none());
    }
}

#[test]
fn test_stash_measurement_pl_context_thresholds() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Root node and RT journey (which is technically the Caliptra locality) count as PL0
    let num_iterations = PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD - 2;
    let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0u8; 4],
        measurement: [0u8; 48],
        context: [0u8; 48],
        svn: 0,
    });
    for _ in 0..num_iterations {
        cmd.populate_chksum().unwrap();

        let _ = model
            .mailbox_execute(
                u32::from(CommandId::STASH_MEASUREMENT),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");
    }

    // Attempting one more should return a failure
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::STASH_MEASUREMENT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
        resp,
    );
}

#[test]
fn test_measurement_log_pl_context_threshold() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Upload (PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD - 1) measurements to measurement log
    // Since 2 measurements taken by Caliptra upon startup, this will cause
    // the PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD to be breached.
    for idx in 0..(PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD - 1) as u8 {
        let mut measurement = StashMeasurementReq {
            measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
            hdr: MailboxReqHeader { chksum: 0 },
            metadata: [0u8; 4],
            context: [0u8; 48],
            svn: 0,
        };
        measurement.measurement[0] = idx;
        measurement.context[1] = idx;
        measurement.svn = idx as u32;
        let mut measurement_req = MailboxReq::StashMeasurement(measurement);
        measurement_req.populate_chksum().unwrap();

        if idx == PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD as u8 - 2 {
            model
                .upload_measurement(measurement_req.as_bytes().unwrap())
                .unwrap_err();

            break;
        }

        model
            .upload_measurement(measurement_req.as_bytes().unwrap())
            .unwrap();
    }

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED)
    });
}

#[test]
fn test_pl0_unset_in_header() {
    let fuses = Fuses {
        fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
        ..Default::default()
    };
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let life_cycle = fuses.life_cycle;
    let mut model = caliptra_hw_model::new(
        InitParams {
            fuses,
            rom: &rom,
            security_state: SecurityState::from(life_cycle as u32),
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();

    let mut opts = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    opts.vendor_config.pl0_pauser = None;
    let mut image_bundle =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, opts).unwrap();

    // Change PL0 to 1 so that it matches the real PL0 PAUSER but don't set the
    // flag bit to make it valid. Also need to re-generate and re-sign the image.
    image_bundle.manifest.header.pl0_pauser = 1;

    let opts = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let ecc_index = opts.vendor_config.ecc_key_idx;
    let lms_index = opts.vendor_config.pqc_key_idx;
    let gen = ImageGenerator::new(Crypto::default());
    let vendor_header_digest_384 = gen
        .vendor_header_digest_384(&image_bundle.manifest.header)
        .unwrap();
    let vendor_header_digest_holder = ImageSignData {
        digest_384: &vendor_header_digest_384,
        mldsa_msg: None,
    };

    let owner_header_digest_384 = gen
        .owner_header_digest_384(&image_bundle.manifest.header)
        .unwrap();
    let owner_header_digest_holder = ImageSignData {
        digest_384: &owner_header_digest_384,
        mldsa_msg: None,
    };

    let fmc_elf = build_firmware_elf(&FMC_WITH_UART).unwrap();
    let app_elf = build_firmware_elf(&APP_WITH_UART).unwrap();
    let preamble = gen
        .gen_preamble(
            &ImageGeneratorConfig {
                fmc: ElfExecutable::new(
                    &fmc_elf,
                    opts.fmc_version as u32,
                    *b"~~~~~NO_GIT_REVISION",
                )
                .unwrap(),
                runtime: ElfExecutable::new(&app_elf, opts.app_version, *b"~~~~~NO_GIT_REVISION")
                    .unwrap(),
                fw_svn: opts.fw_svn,
                vendor_config: opts.vendor_config,
                owner_config: opts.owner_config,
                pqc_key_type: FwVerificationPqcKeyType::LMS,
            },
            ecc_index,
            lms_index,
            &vendor_header_digest_holder,
            &owner_header_digest_holder,
        )
        .unwrap();
    image_bundle.manifest.preamble = preamble;

    crate::common::test_upload_firmware(
        &mut model,
        &image_bundle.to_bytes().unwrap(),
        FwVerificationPqcKeyType::LMS,
    );

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // If PL0 PAUSER is unset, make sure PL0-only operation fails
    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(&certify_key_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL),
    );
    assert!(resp.is_none());
}

#[test]
fn test_user_not_pl0() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut opts = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };
        let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
        let life_cycle = fuses.life_cycle;
        let mut model = caliptra_hw_model::new(
            InitParams {
                fuses,
                rom: &rom,
                security_state: SecurityState::from(life_cycle as u32),
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        opts.vendor_config.pl0_pauser = Some(0); // Caller PAUSER is always 1 for current models
        let image_bundle =
            caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, opts).unwrap();

        crate::common::test_upload_firmware(
            &mut model,
            &image_bundle.to_bytes().unwrap(),
            *pqc_key_type,
        );

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        // If PAUSER is not PL0, make sure PL0-only operation fails
        let certify_key_cmd = CertifyKeyCmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCmd::FORMAT_X509,
        };
        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::CertifyKey(&certify_key_cmd),
            DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL),
        );
        assert!(resp.is_none());
    }
}

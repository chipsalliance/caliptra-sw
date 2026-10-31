// Licensed under the Apache-2.0 license.

use crate::common::{
    certify_key, execute_dpe_cmd, get_rt_alias_ecc384_cert, run_rt_test, run_rt_test_return_fw,
    CertifyKeyCommandNoRef, CreateCertifyKeyCmdArgs, DpeResult, RuntimeTestArgs,
};
use crate::test_info::get_fwinfo;
use caliptra_api::mailbox::{
    CommandId, ReallocateDpeContextLimitsReq, ReallocateDpeContextLimitsResp,
};
use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{MailboxReq, MailboxReqHeader};
use caliptra_dpe::commands::{Command, DeriveContextCmd, DeriveContextFlags, InitCtxCmd};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_runtime::CaliptraDpeProfile;
use openssl::x509::X509;
use zerocopy::FromBytes;

#[cfg(feature = "fpga_subsystem")]
const HW_MODEL_MODES_SUBSYSTEM: [bool; 1] = [true];
#[cfg(feature = "fpga_realtime")]
const HW_MODEL_MODES_SUBSYSTEM: [bool; 1] = [false];
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
const HW_MODEL_MODES_SUBSYSTEM: [bool; 2] = [false, true];

fn wait_for_runtime_idle(model: &mut DefaultHwModel) {
    model.step_until_or_timeout("runtime idle", 40_000_000, |model| {
        let status = model.soc_ifc().cptra_flow_status().read();
        status.ready_for_runtime() && status.mailbox_flow_done()
    });
    for _ in 0..10_000 {
        model.step();
    }
}

fn assert_attestation_enabled(model: &mut DefaultHwModel) {
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
    model.set_axi_user(1);
    get_fwinfo(model);
    let rt_response = get_rt_alias_ecc384_cert(model);
    let rt_cert = X509::from_der(&rt_response.data[..rt_response.data_size as usize]).unwrap();
    let mut command = CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs::default());
    let response = certify_key(model, &mut command).unwrap();
    let leaf_cert = X509::from_der(response.cert().unwrap()).unwrap();
    assert!(leaf_cert.verify(&rt_cert.public_key().unwrap()).unwrap());
}

fn minimum_pl0_context_limit(model: &mut DefaultHwModel) -> u32 {
    model.set_axi_user(1);
    for limit in caliptra_runtime::PL0_DPE_ACTIVE_CONTEXT_THRESHOLD_MIN as u32
        ..=caliptra_runtime::PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD as u32
    {
        match reallocate_pl0_pl1_dpe_contexts(model, limit) {
            Ok(Some(_)) => return limit,
            Err(ModelError::MailboxCmdFailed(error))
                if error
                    == u32::from(
                        CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_USED,
                    ) => {}
            result => panic!("Unexpected result for PL0 limit {limit}: {result:?}"),
        }
    }
    panic!("Initial PL0 usage exceeds the default context limit");
}

fn check_context_limits_survive_reset(warm_reset: bool, subsystem_mode: bool) {
    let (mut model, image) = run_rt_test_return_fw(RuntimeTestArgs {
        subsystem_mode,
        ..RuntimeTestArgs::test_productions_args()
    });
    let image = image.to_bytes().unwrap();
    let base_pl0 = minimum_pl0_context_limit(&mut model);
    let mut used_pl0 = base_pl0;
    let mut used_pl1 = 0;
    let derive_context = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
        ..Default::default()
    };
    let init_context = InitCtxCmd::new_simulation();

    for (pl0_limit, target_pl0, target_pl1, reset_pauser) in [
        (base_pl0 + 1, base_pl0, 0, 1),
        (base_pl0, base_pl0, 0, 1),
        (64, base_pl0, 0, 2),
        (63, base_pl0, 1, 2),
        (32, 32, 32, 1),
    ] {
        model.set_axi_user(1);
        reallocate_pl0_pl1_dpe_contexts(&mut model, pl0_limit)
            .unwrap()
            .unwrap();
        for _ in used_pl0..target_pl0 {
            execute_dpe_cmd(
                &mut model,
                CaliptraDpeProfile::Ecc384,
                &mut Command::DeriveContext(&derive_context),
                DpeResult::Success,
            );
        }
        used_pl0 = target_pl0;
        model.set_axi_user(2);
        for _ in used_pl1..target_pl1 {
            execute_dpe_cmd(
                &mut model,
                CaliptraDpeProfile::Ecc384,
                &mut Command::InitCtx(&init_context),
                DpeResult::Success,
            );
        }
        used_pl1 = target_pl1;
        assert_attestation_enabled(&mut model);
        let reset_pauser = if !warm_reset && model.subsystem_mode() {
            1
        } else {
            reset_pauser
        };
        model.set_axi_user(reset_pauser);
        get_fwinfo(&mut model);
        wait_for_runtime_idle(&mut model);

        if warm_reset {
            model.warm_reset_flow().unwrap();
        } else {
            model
                .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
                .unwrap();
        }
        wait_for_runtime_idle(&mut model);
        assert_attestation_enabled(&mut model);

        if used_pl0 == pl0_limit {
            execute_dpe_cmd(
                &mut model,
                CaliptraDpeProfile::Ecc384,
                &mut Command::DeriveContext(&derive_context),
                DpeResult::MboxCmdFailure(
                    CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
        }
        if used_pl1 == 64 - pl0_limit {
            model.set_axi_user(2);
            execute_dpe_cmd(
                &mut model,
                CaliptraDpeProfile::Ecc384,
                &mut Command::InitCtx(&init_context),
                DpeResult::MboxCmdFailure(
                    CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
        }
    }
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_context_limits_survive_warm_reset() {
    for &subsystem_mode in &HW_MODEL_MODES_SUBSYSTEM {
        check_context_limits_survive_reset(true, subsystem_mode);
    }
}

#[test]
fn test_context_limits_survive_update_reset() {
    for &subsystem_mode in &HW_MODEL_MODES_SUBSYSTEM {
        check_context_limits_survive_reset(false, subsystem_mode);
    }
}

fn fill_max_dpe_contexts(model: &mut DefaultHwModel, pl0_limit: u32, pl1_limit: u32) {
    let base_derive_context_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT,
        ..Default::default()
    };

    // In subsystem mode, Caliptra uses 6 base PL0 contexts
    // (root + RT journey + SOMV + SOMO + MCU FW + field entropy state);
    // otherwise, 2 (root + RT journey).
    let caliptra_base_pl0: u32 = if model.subsystem_mode() { 6 } else { 2 };

    // Fill PL0 contexts
    println!("Filling PL0 contexts up to limit {}", pl0_limit);
    for i in 0..(pl0_limit - caliptra_base_pl0) {
        let cmd = DeriveContextCmd {
            tci_type: i,
            ..base_derive_context_cmd
        };
        let _ = execute_dpe_cmd(
            model,
            CaliptraDpeProfile::Ecc384,
            &mut Command::DeriveContext(&cmd),
            DpeResult::Success,
        );
    }

    println!("triggering PL0 failure");
    // Trigger failure by trying to derive one more context to PL0
    let _ = execute_dpe_cmd(
        model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::DeriveContext(&base_derive_context_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED),
    );

    println!("Filling PL1 contexts up to limit {}", pl1_limit);
    // Fill PL1 contexts
    for i in 0..pl1_limit {
        if i == 0 {
            // Transition to PL1 locality on first iteration
            let derive_ctx_cmd = DeriveContextCmd {
                flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::CHANGE_LOCALITY,
                target_locality: 2,
                tci_type: i + pl0_limit,
                ..base_derive_context_cmd
            };
            let _ = execute_dpe_cmd(
                model,
                CaliptraDpeProfile::Ecc384,
                &mut Command::DeriveContext(&derive_ctx_cmd),
                DpeResult::Success,
            );

            model.set_axi_user(2);
        } else {
            let cmd = DeriveContextCmd {
                tci_type: i + pl0_limit,
                ..base_derive_context_cmd
            };
            let _ = execute_dpe_cmd(
                model,
                CaliptraDpeProfile::Ecc384,
                &mut Command::DeriveContext(&cmd),
                DpeResult::Success,
            );
        }
    }

    println!("triggering PL1 failure");
    // Trigger failure by trying to derive one more context to PL1
    let _ = execute_dpe_cmd(
        model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::DeriveContext(&base_derive_context_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED),
    );
}

fn reallocate_pl0_pl1_dpe_contexts(
    model: &mut DefaultHwModel,
    pl0_limit: u32,
) -> Result<Option<Vec<u8>>, ModelError> {
    let mut cmd = MailboxReq::ReallocateDpeContextLimits(ReallocateDpeContextLimitsReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pl0_context_limit: pl0_limit,
    });
    cmd.populate_chksum().unwrap();

    model.mailbox_execute(
        u32::from(CommandId::REALLOCATE_DPE_CONTEXT_LIMITS),
        cmd.as_bytes().unwrap(),
    )
}

#[test]
fn test_pl0_pl1_reallocation_range() {
    // In subsystem mode, Caliptra uses 6 base PL0 contexts
    // (root + RT journey + SOMV + SOMO + MCU FW + field entropy state);
    // we cannot reallocate below the used count.
    let mut first_model = run_rt_test(RuntimeTestArgs::default());
    let min_pl0_limit: u32 = if first_model.subsystem_mode() { 6 } else { 2 };
    drop(first_model);

    for pl0_limit in min_pl0_limit..caliptra_dpe::MAX_HANDLES as u32 {
        println!("\n\n\tPL0 Limit {}\n\n", pl0_limit);
        let mut model = run_rt_test(RuntimeTestArgs::default());
        let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, pl0_limit)
            .unwrap()
            .expect("We should have received a response");
        let reallocate_resp =
            ReallocateDpeContextLimitsResp::read_from_bytes(resp.as_slice()).unwrap();

        assert_eq!(reallocate_resp.new_pl0_context_limit, pl0_limit);
        assert_eq!(reallocate_resp.new_pl1_context_limit, 64 - pl0_limit);

        fill_max_dpe_contexts(&mut model, pl0_limit, 64 - pl0_limit);
    }
}

#[test]
fn test_pl0_pl1_reallocation_call_outside_pl0() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    // Set Non-PL0 PAUSER
    model.set_axi_user(2);
    let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, 20).unwrap_err();
    assert_eq!(
        resp,
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL.into()
        )
    );
}

#[test]
fn test_pl0_pl1_reallocation_pl0_less_than_min() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, 1).unwrap_err();
    assert_eq!(
        resp,
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_MIN.into()
        )
    );
}

#[test]
fn test_pl0_pl1_reallocation_pl0_greater_than_max() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, 65).unwrap_err();
    assert_eq!(
        resp,
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_GREATER_THAN_MAX.into()
        )
    );
}

#[test]
fn test_pl0_pl1_reallocation_pl0_less_than_used() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let derive_context_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT,
        ..Default::default()
    };

    // Use some PL0 contexts without breaching the default PL0 limit first.
    let initial_pl0_contexts = if model.subsystem_mode() { 9 } else { 12 };
    for _ in 0..initial_pl0_contexts {
        let _ = execute_dpe_cmd(
            &mut model,
            CaliptraDpeProfile::Ecc384,
            &mut Command::DeriveContext(&derive_context_cmd),
            DpeResult::Success,
        );
    }

    // Try to reallocate contexts to limit PL0 to 8
    let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, 8).unwrap_err();
    assert_eq!(
        resp,
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_USED.into()
        )
    );
}

#[test]
fn test_pl0_pl1_reallocation_pl1_less_than_used() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let base_derive_context_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT,
        ..Default::default()
    };

    // Use some PL1 contexts
    for i in 0..12 {
        if i == 0 {
            // Transition to PL1 locality on first iteration
            let derive_ctx_cmd = DeriveContextCmd {
                flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::CHANGE_LOCALITY,
                target_locality: 2,
                tci_type: i,
                ..base_derive_context_cmd
            };
            let _ = execute_dpe_cmd(
                &mut model,
                CaliptraDpeProfile::Ecc384,
                &mut Command::DeriveContext(&derive_ctx_cmd),
                DpeResult::Success,
            );

            model.set_axi_user(2);
        } else {
            let derive_ctx_cmd = DeriveContextCmd {
                tci_type: i,
                ..base_derive_context_cmd
            };
            let _ = execute_dpe_cmd(
                &mut model,
                CaliptraDpeProfile::Ecc384,
                &mut Command::DeriveContext(&derive_ctx_cmd),
                DpeResult::Success,
            );
        }
    }

    // Call from PL0
    model.set_axi_user(1);
    // Try to reallocate contexts to limit PL0 to 56
    let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, 56).unwrap_err();
    assert_eq!(
        resp,
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL1_LESS_THAN_USED.into()
        )
    );
}

#[test]
fn test_pl0_pl1_reallocation_warm_reset() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_test_args = RuntimeTestArgs {
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_test_args);

    let derive_context_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT,
        ..Default::default()
    };

    // Use some PL0 contexts without breaching the default PL0 limit first.
    let initial_pl0_contexts = if model.subsystem_mode() { 9 } else { 12 };
    for _ in 0..initial_pl0_contexts {
        let _ = execute_dpe_cmd(
            &mut model,
            CaliptraDpeProfile::Ecc384,
            &mut Command::DeriveContext(&derive_context_cmd),
            DpeResult::Success,
        );
    }

    // Increase PL0 context limit
    reallocate_pl0_pl1_dpe_contexts(&mut model, 24)
        .unwrap()
        .expect("We should have received a response");

    // Trigger update reset to same firmware
    let image =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap()
            .to_bytes()
            .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();

    // Use the rest of the PL0 contexts
    // In subsystem mode, 6 contexts are used by Caliptra
    // (root + RT journey + SOMV + SOMO + MCU FW + field entropy state);
    // otherwise, 2 contexts are used (root + RT journey).
    let caliptra_contexts: u32 = if model.subsystem_mode() { 6 } else { 2 };
    let remaining = 24 - caliptra_contexts - initial_pl0_contexts;
    for _ in 0..remaining {
        let _ = execute_dpe_cmd(
            &mut model,
            CaliptraDpeProfile::Ecc384,
            &mut Command::DeriveContext(&derive_context_cmd),
            DpeResult::Success,
        );
    }

    // Trigger failure by trying to derive one more context to PL0
    let _ = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::DeriveContext(&derive_context_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED),
    );
}

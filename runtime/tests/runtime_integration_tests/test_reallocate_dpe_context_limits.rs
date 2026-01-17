// Licensed under the Apache-2.0 license.

use crate::common::{execute_dpe_cmd, run_rt_test, DpeResult, RuntimeTestArgs};
use caliptra_api::mailbox::{
    CommandId, ReallocateDpeContextLimitsReq, ReallocateDpeContextLimitsResp,
};
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{MailboxReq, MailboxReqHeader};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_image_types::FwVerificationPqcKeyType;
use dpe::commands::{Command, DeriveContextCmd, DeriveContextFlags};
use zerocopy::FromBytes;

fn fill_max_dpe_contexts(model: &mut DefaultHwModel, pl0_limit: u32, pl1_limit: u32) {
    let base_derive_context_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT,
        ..Default::default()
    };

    // 32 contexts = 1 root node (PL0)+
    //               1 rt_journey (PL0)
    //               (pl0_limit - 2) PL0 contexts in loop +
    //               1 PL1 context as transition +
    //               (pl1_limit - 1) PL1 contexts in loop

    // Fill PL0 contexts
    println!("Filling PL0 contexts up to limit {}", pl0_limit);
    for _ in 0..(pl0_limit - 2) {
        let _ = execute_dpe_cmd(
            model,
            &mut Command::DeriveContext(&base_derive_context_cmd),
            DpeResult::Success,
        );
    }

    println!("triggering PL0 failure");
    // Trigger failure by trying to derive one more context to PL0
    let _ = execute_dpe_cmd(
        model,
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
                ..base_derive_context_cmd
            };
            let _ = execute_dpe_cmd(
                model,
                &mut Command::DeriveContext(&derive_ctx_cmd),
                DpeResult::Success,
            );

            model.set_axi_user(2);
        } else {
            let _ = execute_dpe_cmd(
                model,
                &mut Command::DeriveContext(&base_derive_context_cmd),
                DpeResult::Success,
            );
        }
    }

    println!("triggering PL1 failure");
    // Trigger failure by trying to derive one more context to PL1
    let _ = execute_dpe_cmd(
        model,
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
    for pl0_limit in 2..dpe::MAX_HANDLES as u32 {
        println!("\n\n\tPL0 Limit {}\n\n", pl0_limit);
        let mut model = run_rt_test(RuntimeTestArgs::default());
        let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, pl0_limit)
            .unwrap()
            .expect("We should have received a response");
        let reallocate_resp =
            ReallocateDpeContextLimitsResp::read_from_bytes(resp.as_slice()).unwrap();

        assert_eq!(reallocate_resp.new_pl0_context_limit, pl0_limit);
        assert_eq!(reallocate_resp.new_pl1_context_limit, 32 - pl0_limit);

        fill_max_dpe_contexts(&mut model, pl0_limit, 32 - pl0_limit);
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
    let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, 33).unwrap_err();
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

    // Use some PL0 contexts
    for _ in 0..12 {
        let _ = execute_dpe_cmd(
            &mut model,
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
                ..base_derive_context_cmd
            };
            let _ = execute_dpe_cmd(
                &mut model,
                &mut Command::DeriveContext(&derive_ctx_cmd),
                DpeResult::Success,
            );

            model.set_axi_user(2);
        } else {
            let _ = execute_dpe_cmd(
                &mut model,
                &mut Command::DeriveContext(&base_derive_context_cmd),
                DpeResult::Success,
            );
        }
    }

    // Call from PL0
    model.set_axi_user(1);
    // Try to reallocate contexts to limit PL0 to 24
    let resp = reallocate_pl0_pl1_dpe_contexts(&mut model, 24).unwrap_err();
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

    // Use some PL0 contexts
    for _ in 0..12 {
        let _ = execute_dpe_cmd(
            &mut model,
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
    // (2 contexts are used by Caliptra)
    for _ in 0..10 {
        let _ = execute_dpe_cmd(
            &mut model,
            &mut Command::DeriveContext(&derive_context_cmd),
            DpeResult::Success,
        );
    }

    // Trigger failure by trying to derive one more context to PL0
    let _ = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&derive_context_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED),
    );
}

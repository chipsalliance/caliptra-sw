// Licensed under the Apache-2.0 license

use caliptra_hw_model::HwModel;
use caliptra_runtime::{InvokeDpeCmd, RtBootStatus};
use dpe::{
    commands::{Command, DeriveChildCmd, DeriveChildFlags, RotateCtxCmd, RotateCtxFlags},
    context::ContextHandle,
    response::Response,
    DPE_PROFILE,
};

use crate::common::{execute_dpe_cmd, run_rt_test, DpeResult};

#[test]
fn test_pl0_derive_child_dpe_context_thresholds() {
    let mut model = run_rt_test(None, None, None);

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
        &mut Command::RotateCtx(rotate_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::RotateCtx(rotate_ctx_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let mut handle = rotate_ctx_resp.handle;

    // Call DeriveChild with PL0 enough times to breach the threshold on the last iteration.
    // Note that this loop runs exactly PL0_DPE_ACTIVE_CONTEXT_THRESHOLD times. When we initialize
    // DPE, we measure mailbox valid pausers in pl0_pauser's locality. Thus, we can call derive child
    // from PL0 exactly 7 times, and the last iteration of this loop, is expected to throw a threshold breached error.
    let num_iterations = InvokeDpeCmd::PL0_DPE_ACTIVE_CONTEXT_THRESHOLD;
    for i in 0..num_iterations {
        let derive_child_cmd = DeriveChildCmd {
            handle,
            data: [0u8; DPE_PROFILE.get_hash_size()],
            flags: DeriveChildFlags::RETAIN_PARENT,
            tci_type: 0,
            target_locality: 0,
        };

        // If we are on the last call to DeriveChild, expect that we get a PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED error.
        if i == num_iterations - 1 {
            let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::DeriveChild(derive_child_cmd),
                DpeResult::MboxCmdFailure(caliptra_drivers::CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED),
            );
            assert!(resp.is_none());
            break;
        }

        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::DeriveChild(derive_child_cmd),
            DpeResult::Success,
        );
        let Some(Response::DeriveChild(derive_child_resp)) = resp else {
            panic!("Wrong response type!");
        };
        handle = derive_child_resp.handle;
    }
}

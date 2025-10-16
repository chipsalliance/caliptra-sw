use crate::common::{
    build_ready_runtime_model, execute_dpe_cmd, wait_runtime_ready, BuildArgs, DpeResult,
};

use caliptra_hw_model::{DeviceLifecycle, HwModel, SecurityState};

use dpe::{commands::Command, response::Response};

#[test]
fn test_invoke_dpe_get_profile_across_warm_reset() {
    // Boot runtime
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _, _, _) = build_ready_runtime_model(args);

    let resp_before = execute_dpe_cmd(&mut model, &mut Command::GetProfile, DpeResult::Success);
    let Some(Response::GetProfile(profile_before)) = resp_before else {
        panic!("Wrong response type!");
    };

    // warm reset + wait ready again
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // Re-issue the same command after warm reset
    let resp_after = execute_dpe_cmd(&mut model, &mut Command::GetProfile, DpeResult::Success);
    let Some(Response::GetProfile(profile_after)) = resp_after else {
        panic!("Wrong response type!");
    };

    // Parsed responses should match
    assert_eq!(
        profile_before, profile_after,
        "Parsed DPE GetProfile response changed across warm reset"
    );
}

use crate::common::{execute_dpe_cmd, run_rt_test_pqc, DpeResult, RuntimeTestArgs};

use caliptra_hw_model::HwModel;

use dpe::{commands::Command, response::Response};

#[test]
fn test_invoke_dpe_get_profile_across_warm_reset() {
    // Boot runtime
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    let resp_before = execute_dpe_cmd(&mut model, &mut Command::GetProfile, DpeResult::Success);
    let Some(Response::GetProfile(profile_before)) = resp_before else {
        panic!("Wrong response type!");
    };

    // Warm reset  again
    model.warm_reset_flow().unwrap();

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

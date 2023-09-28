// Licensed under the Apache-2.0 license.
pub mod common;
use caliptra_builder::firmware;
use caliptra_hw_model::HwModel;
use common::run_rt_test;

pub const TIMER_CONFIG_IN_PICOSSECONDS: u32 = 1000000000; // 1ms
#[test]
fn test_wdt_timeout() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::WDT), None);

    model
        .soc_ifc()
        .cptra_timer_config()
        .write(|_| TIMER_CONFIG_IN_PICOSSECONDS);

    model.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

    // Make sure we see the right fatal error
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0x0000_DEAD1);
}

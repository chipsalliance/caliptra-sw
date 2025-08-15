// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware::ROM_WITH_UART_OCP_LOCK;
use caliptra_hw_model::{HwModel, InitParams};
use caliptra_runtime::RtBootStatus;

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_supports_ocp_lock() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART_OCP_LOCK).unwrap();
    let mut model = run_rt_test(RuntimeTestArgs {
        init_params: Some(InitParams {
            rom: &rom,
            subsystem_mode: false,
            ..Default::default()
        }),
        ..Default::default()
    });
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });
}

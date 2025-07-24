// Licensed under the Apache-2.0 license.

use crate::common::{run_rt_test, RuntimeTestArgs};
use caliptra_api::{
    mailbox::{FeProgReq, MailboxReq, MailboxReqHeader},
    SocManager,
};
use caliptra_common::mailbox_api::CommandId;
use caliptra_hw_model::{DeviceLifecycle, HwModel, InitParams, SecurityState};
use caliptra_runtime::RtBootStatus;

#[test]
fn test_fe_programming_cmd() {
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let init_params = InitParams {
        rom: &rom,
        security_state: *SecurityState::default()
            .set_device_lifecycle(DeviceLifecycle::Manufacturing),
        ..Default::default()
    };

    let mut model = run_rt_test(RuntimeTestArgs {
        init_params: Some(init_params),
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Create FE programming request with test bitflags
    let mut cmd = MailboxReq::FeProg(FeProgReq {
        hdr: MailboxReqHeader { chksum: 0 },
        bitflags: 0x1, // Test with basic bitflag set
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(u32::from(CommandId::FE_PROG), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We should have received a response");

    // Verify we got a successful response (should be at least header size)
    assert!(resp.len() >= core::mem::size_of::<MailboxReqHeader>());

    // Verify no fatal errors occurred
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
}

// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_hw_model::HwModel;
use zerocopy::AsBytes;

use crate::common::{assert_error, run_rt_test};

/// When a successful command runs after a failed command, ensure the error
/// register is cleared.
#[test]
fn test_error_cleared() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // Send invalid command to cause failure
    let resp = model.mailbox_execute(0xffffffff, &[]).unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        resp,
    );

    // Succeed a command to make sure error gets cleared
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };
    let _ = model
        .mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes())
        .unwrap()
        .unwrap();

    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
}

#[test]
fn test_unimplemented_cmds() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // Send something that is not a valid RT command.
    const INVALID_CMD: u32 = 0xAABBCCDD;
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(INVALID_CMD, &[]),
    };

    let resp = model
        .mailbox_execute(INVALID_CMD, payload.as_bytes())
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND,
        resp,
    );
}

// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_hw_model::HwModel;
use zerocopy::IntoBytes;

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};

/// When a successful command runs after a failed command, ensure the error
/// register is cleared.
#[test]
fn test_error_cleared() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
fn test_mailbox_byte_granular_length() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let command = u32::from(CommandId::VERSION);
    for length in 1..=3 {
        let tail = vec![0xa5; length];
        let checksum = caliptra_common::checksum::calc_checksum(command, &tail);
        let mut payload = checksum.to_le_bytes().to_vec();
        payload.extend_from_slice(&tail);
        model.mailbox_execute(command, &payload).unwrap().unwrap();

        // The checksum must cover the final partial word, not just full words.
        payload[4] ^= 1;
        let error = model.mailbox_execute(command, &payload).unwrap_err();
        assert_error(
            &mut model,
            caliptra_drivers::CaliptraError::RUNTIME_INVALID_CHECKSUM,
            error,
        );
    }
}

#[test]
fn test_unimplemented_cmds() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

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

#[test]
// Changing PAUSER not supported on sw emulator
#[cfg(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
))]
fn test_reserved_pauser() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // Set pauser to the reserved value
    model.set_axi_user(0xffffffff);

    // Send anything
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes())
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_CMD_RESERVED_PAUSER,
        resp,
    );
}

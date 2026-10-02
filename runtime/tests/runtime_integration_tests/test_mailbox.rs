// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_hw_model::{HwModel, SecurityState};
use zerocopy::IntoBytes;

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};

#[cfg_attr(any(feature = "fpga_realtime", feature = "fpga_subsystem"), ignore)]
#[test]
fn test_runtime_wdt_uses_configured_timeout() {
    for configured_cycles in [20_000_000u64, 40_000_000, (1 << 32) + 123] {
        let mut model = run_rt_test(RuntimeTestArgs {
            security_state: Some(*SecurityState::default().set_debug_locked(true)),
            wdt_timeout_cycles: Some(configured_cycles),
            ..Default::default()
        });
        model.step_until_ready_for_runtime();
        model.step_until_or_timeout("Runtime idle watchdog disabled", 100_000, |m| {
            !m.soc_ifc().cptra_wdt_timer1_en().read().timer1_en()
        });

        let payload = MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
        };
        model
            .start_mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes())
            .unwrap();
        model.step_until_or_timeout("Runtime command watchdog enabled", 100_000, |m| {
            m.soc_ifc().cptra_wdt_timer1_en().read().timer1_en()
        });

        let low = model
            .soc_ifc()
            .cptra_wdt_timer1_timeout_period()
            .at(0)
            .read();
        let high = model
            .soc_ifc()
            .cptra_wdt_timer1_timeout_period()
            .at(1)
            .read();
        assert_eq!(u64::from(low) | (u64::from(high) << 32), configured_cycles);
        model
            .finish_mailbox_execute()
            .unwrap()
            .expect("VERSION should return a response");
        model.step_until_or_timeout("Runtime command watchdog stopped", 100_000, |m| {
            !m.soc_ifc().cptra_wdt_timer1_en().read().timer1_en()
        });
    }
}

#[cfg_attr(any(feature = "fpga_realtime", feature = "fpga_subsystem"), ignore)]
#[test]
fn test_runtime_wdt_remains_disabled_when_debug_unlocked() {
    let mut model = run_rt_test(RuntimeTestArgs {
        wdt_timeout_cycles: Some((1 << 32) + 123),
        ..Default::default()
    });
    model.step_until_ready_for_runtime();
    assert!(!model.soc_ifc().cptra_security_state().read().debug_locked());
    let timeout_before = [
        model
            .soc_ifc()
            .cptra_wdt_timer1_timeout_period()
            .at(0)
            .read(),
        model
            .soc_ifc()
            .cptra_wdt_timer1_timeout_period()
            .at(1)
            .read(),
    ];

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };
    model
        .mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes())
        .unwrap()
        .expect("VERSION should return a response");

    assert!(!model.soc_ifc().cptra_wdt_timer1_en().read().timer1_en());
    for (index, expected) in timeout_before.into_iter().enumerate() {
        assert_eq!(
            model
                .soc_ifc()
                .cptra_wdt_timer1_timeout_period()
                .at(index)
                .read(),
            expected
        );
    }
}

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

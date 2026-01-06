// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test_pqc, RuntimeTestArgs};
use caliptra_common::checksum::calc_checksum;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_hw_model::ModelError;
use zerocopy::{FromBytes, IntoBytes};

pub fn mbx_execute_helper<T: HwModel, U: FromBytes + IntoBytes>(
    hw: &mut T,
    cmd: u32,
    req_payload: &[u8],
) -> std::result::Result<U, ModelError> {
    let resp_bytes = hw.mailbox_execute(cmd, req_payload)?.unwrap();

    // Checksum and FIPS statuch check
    let resp_hdr = MailboxRespHeader::read_from_bytes(
        &resp_bytes[..core::mem::size_of::<MailboxRespHeader>()],
    )
    .unwrap();
    assert!(caliptra_common::checksum::verify_checksum(
        resp_hdr.chksum,
        0x0,
        &resp_bytes[core::mem::size_of_val(&resp_hdr.chksum)..],
    ));
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Handle variable-sized responses
    assert!(resp_bytes.len() <= std::mem::size_of::<U>());
    let mut typed_resp = U::new_zeroed();
    typed_resp.as_mut_bytes()[..resp_bytes.len()].copy_from_slice(&resp_bytes);
    Ok(typed_resp)
}

fn send_self_test_start_once<T: HwModel>(hw: &mut T) -> Result<MailboxRespHeader, ModelError> {
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::SELF_TEST_START), &[]),
    };
    mbx_execute_helper::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::SELF_TEST_START),
        payload.as_bytes(),
    )
}

fn send_self_test_get_results_once<T: HwModel>(
    hw: &mut T,
) -> Result<MailboxRespHeader, ModelError> {
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::SELF_TEST_GET_RESULTS), &[]),
    };
    mbx_execute_helper::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::SELF_TEST_GET_RESULTS),
        payload.as_bytes(),
    )
}

/// Spin the model for `cycles` (tiny backoff between polls).
fn spin_cycles<T: HwModel>(hw: &mut T, mut cycles: usize) {
    hw.step_until(|_| {
        cycles -= 1;
        cycles == 0
    });
}

/// Start the self-test and poll GET_RESULTS until it returns Ok (pass).
/// Panics on unexpected error or timeout.
fn wait_for_self_test_pass<T: HwModel>(
    hw: &mut T,
    max_polls: usize,      // e.g. 1_000
    cycles_between: usize, // e.g. 10_000
) {
    send_self_test_start_once(hw).expect("SELF_TEST_START should succeed");

    for i in 0..max_polls {
        match send_self_test_get_results_once(hw) {
            Ok(_hdr) => return, // finished & passed
            Err(ModelError::MailboxCmdFailed(code))
                if code == u32::from(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED) =>
            {
                // START not yet visible or was cleared; keep polling
            }
            Err(ModelError::UnableToLockMailbox) => {
                // FW busy; keep polling
            }
            Err(e) => panic!("Unexpected error from GET_RESULTS at poll #{i}: {e:?}"),
        }
        if cycles_between > 0 {
            spin_cycles(hw, cycles_between);
        }
    }

    panic!("Timed out waiting for SELF_TEST_GET_RESULTS to succeed after {max_polls} polls");
}

/// Assert that querying GET_RESULTS *without* a prior START yields NOT_STARTED.
fn assert_results_not_started<T: HwModel>(hw: &mut T) {
    match send_self_test_get_results_once(hw) {
        Err(ModelError::MailboxCmdFailed(code))
            if code == u32::from(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED) => {}
        other => panic!("Expected NOT_STARTED from GET_RESULTS, got: {other:?}"),
    }
}

#[test]
fn self_test_get_results_resets_after_warm_reset() {
    // Boot to ready runtime
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    // Start self-test and wait until it passes
    wait_for_self_test_pass(&mut model, 1_000, 10_000);

    // Warm reset & wait ready
    model.warm_reset_flow().unwrap();

    // Querying results without re-start should return NOT_STARTED
    assert_results_not_started(&mut model);

    // Re-run the flow to prove it works again post-reset
    wait_for_self_test_pass(&mut model, 1_000, 10_000);
}

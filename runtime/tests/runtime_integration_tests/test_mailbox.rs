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
        caliptra_drivers::CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND,
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
fn test_oversized_payload_rejected() {
    use caliptra_common::mailbox_api::*;
    use std::mem::size_of;

    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // For each command that calls copy_from_mbox, sending one extra byte beyond the
    // request struct size must return RUNTIME_INSUFFICIENT_MEMORY. Commands that do
    // not call copy_from_mbox (GET_LDEV_CERT, GET_FMC_ALIAS_CERT, GET_RT_ALIAS_CERT)
    // are excluded.
    let cmds: &[(u32, usize)] = &[
        (u32::from(CommandId::VERSION), size_of::<MailboxReqHeader>()),
        (
            u32::from(CommandId::CAPABILITIES),
            size_of::<MailboxReqHeader>(),
        ),
        (u32::from(CommandId::FW_INFO), size_of::<MailboxReqHeader>()),
        (
            u32::from(CommandId::DISABLE_ATTESTATION),
            size_of::<MailboxReqHeader>(),
        ),
        (
            u32::from(CommandId::GET_IDEV_INFO),
            size_of::<MailboxReqHeader>(),
        ),
        (
            u32::from(CommandId::GET_PCR_LOG),
            size_of::<MailboxReqHeader>(),
        ),
        (
            u32::from(CommandId::SELF_TEST_START),
            size_of::<MailboxReqHeader>(),
        ),
        (
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            size_of::<MailboxReqHeader>(),
        ),
        (
            u32::from(CommandId::SHUTDOWN),
            size_of::<MailboxReqHeader>(),
        ),
        (
            u32::from(CommandId::GET_IDEV_CERT),
            size_of::<GetIdevCertReq>(),
        ),
        (u32::from(CommandId::INVOKE_DPE), size_of::<InvokeDpeReq>()),
        (
            u32::from(CommandId::ECDSA384_VERIFY),
            size_of::<EcdsaVerifyReq>(),
        ),
        (u32::from(CommandId::LMS_VERIFY), size_of::<LmsVerifyReq>()),
        (u32::from(CommandId::EXTEND_PCR), size_of::<ExtendPcrReq>()),
        (
            u32::from(CommandId::STASH_MEASUREMENT),
            size_of::<StashMeasurementReq>(),
        ),
        (u32::from(CommandId::DPE_TAG_TCI), size_of::<TagTciReq>()),
        (
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            size_of::<GetTaggedTciReq>(),
        ),
        (
            u32::from(CommandId::POPULATE_IDEV_CERT),
            size_of::<PopulateIdevCertReq>(),
        ),
        (
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            size_of::<AddSubjectAltNameReq>(),
        ),
        (
            u32::from(CommandId::CERTIFY_KEY_EXTENDED),
            size_of::<CertifyKeyExtendedReq>(),
        ),
        (
            u32::from(CommandId::INCREMENT_PCR_RESET_COUNTER),
            size_of::<IncrementPcrResetCounterReq>(),
        ),
        (u32::from(CommandId::QUOTE_PCRS), size_of::<QuotePcrsReq>()),
        (
            u32::from(CommandId::SET_AUTH_MANIFEST),
            size_of::<SetAuthManifestReq>(),
        ),
        (
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            size_of::<AuthorizeAndStashReq>(),
        ),
        (
            u32::from(CommandId::GET_IDEV_CSR),
            size_of::<GetIdevCsrReq>(),
        ),
        (
            u32::from(CommandId::GET_FMC_ALIAS_CSR),
            size_of::<GetFmcAliasCsrReq>(),
        ),
        (
            u32::from(CommandId::SIGN_WITH_EXPORTED_ECDSA),
            size_of::<SignWithExportedEcdsaReq>(),
        ),
        (
            u32::from(CommandId::REVOKE_EXPORTED_CDI_HANDLE),
            size_of::<RevokeExportedCdiHandleReq>(),
        ),
        (
            u32::from(CommandId::REALLOCATE_DPE_CONTEXT_LIMITS),
            size_of::<ReallocateDpeContextLimitsReq>(),
        ),
    ];

    for &(cmd, req_size) in cmds {
        let oversized = vec![0u8; req_size + 1];
        let resp = model.mailbox_execute(cmd, &oversized).unwrap_err();
        assert_error(
            &mut model,
            caliptra_drivers::CaliptraError::RUNTIME_INSUFFICIENT_MEMORY,
            resp,
        );
    }
}

#[test]
// Changing PAUSER not supported on sw emulator
#[cfg(any(feature = "verilator", feature = "fpga_realtime"))]
fn test_reserved_pauser() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // Set pauser to the reserved value
    model.set_apb_pauser(0xffffffff);

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

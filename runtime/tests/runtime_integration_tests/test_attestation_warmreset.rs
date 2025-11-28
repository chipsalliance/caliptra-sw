use crate::common::{build_ready_runtime_model, wait_runtime_ready, BuildArgs};

use caliptra_common::{
    checksum::verify_checksum,
    mailbox_api::{CommandId, FwInfoResp, MailboxReqHeader, MailboxRespHeader},
};

use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, HwModel, SecurityState};

use zerocopy::{FromBytes, IntoBytes};

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_disable_attestation_persists_after_warm_reset() {
    // --- Boot
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _, _, _) = build_ready_runtime_model(args);

    //  query FW_INFO and return the parsed struct
    let read_fw_info = |m: &mut DefaultHwModel| {
        let payload = MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
        };

        let resp = m
            .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
            .unwrap()
            .unwrap();
        FwInfoResp::read_from_bytes(resp.as_slice()).unwrap()
    };

    //attestation should be enabled initially (0)
    let info0 = read_fw_info(&mut model);
    assert_eq!(
        info0.attestation_disabled, 0,
        "attestation should start enabled"
    );

    // --- Disable attestation ---
    let disable_payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            disable_payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_bytes()).unwrap();

    // Checksum over everything AFTER the chksum field
    let chksum_region = &resp[core::mem::size_of_val(&resp_hdr.chksum)..];
    assert!(
        verify_checksum(resp_hdr.chksum, 0x0, chksum_region),
        "GetIdevEcc384InfoResp checksum invalid"
    );

    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "DISABLE_ATTESTATION should be FIPS approved"
    );

    // Check flag before warm reset
    let info_before_reset = read_fw_info(&mut model);
    assert_eq!(
        info_before_reset.attestation_disabled, 1,
        "attestation_disabled flag should be set immediately after DISABLE_ATTESTATION"
    );

    // --- Warm reset + wait ready (exactly as requested) ---
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // Verify the flag persists across warm reset
    let info_after_reset = read_fw_info(&mut model);
    assert_eq!(
        info_after_reset.attestation_disabled, 1,
        "attestation_disabled flag should persist across warm reset"
    );
}

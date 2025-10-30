// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test_pqc, RuntimeTestArgs};

use caliptra_common::{
    checksum::verify_checksum,
    mailbox_api::{
        CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, StashMeasurementReq,
        StashMeasurementResp,
    },
};
use caliptra_hw_model::HwModel;
use zerocopy::{FromBytes, IntoBytes};

fn make_stash_req_bytes() -> Vec<u8> {
    let measurement = [1u8; 48];
    let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0u8; 4],
        measurement,
        context: [0u8; 48],
        svn: 0,
    });
    cmd.populate_chksum().expect("populate checksum");
    cmd.as_bytes().expect("serialize request").to_vec()
}

fn send_stash_and_check<T: HwModel>(hw: &mut T, req: &[u8]) -> Vec<u8> {
    let resp = hw
        .mailbox_execute(u32::from(CommandId::STASH_MEASUREMENT), req)
        .expect("mailbox exec should succeed")
        .expect("expected response bytes");

    let resp_hdr: &StashMeasurementResp =
        StashMeasurementResp::ref_from_bytes(resp.as_bytes()).unwrap();

    assert_eq!(resp_hdr.dpe_result, 0);

    // checksum over everything after the chksum field
    assert!(
        verify_checksum(
            resp_hdr.hdr.chksum,
            0x0,
            &resp[core::mem::size_of_val(&resp_hdr.hdr.chksum)..],
        ),
        "STASH_MEASUREMENT response checksum verification failed"
    );

    // FIPS Approved bit
    assert_eq!(
        resp_hdr.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "FIPS status not APPROVED"
    );

    // DPE returned success (0)
    assert_eq!(resp_hdr.dpe_result, 0, "DPE result not success");

    resp
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_stash_measurement_after_warm_reset() {
    // Boot runtime
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    let req_bytes = make_stash_req_bytes();

    // before warm reset
    let resp_before = send_stash_and_check(&mut model, &req_bytes);

    // Warm reset  again
    model.warm_reset_flow().unwrap();

    // after warm reset
    let resp_after = send_stash_and_check(&mut model, &req_bytes);

    // ensure determinism across warm reset
    assert_eq!(
        resp_before, resp_after,
        "STASH_MEASUREMENT response changed across warm reset"
    );
}

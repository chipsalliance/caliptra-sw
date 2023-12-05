// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, StashMeasurementReq, StashMeasurementResp,
};
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use zerocopy::{AsBytes, LayoutVerified};

use crate::common::run_rt_test;

#[test]
fn test_stash_measurement() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0u8; 4],
        measurement: [0u8; 48],
        context: [0u8; 48],
        svn: 0,
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::STASH_MEASUREMENT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let resp_hdr: &StashMeasurementResp =
        LayoutVerified::<&[u8], StashMeasurementResp>::new(resp.as_bytes())
            .unwrap()
            .into_ref();

    assert_eq!(resp_hdr.dpe_result, 0);
}

// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{self, FMC_WITH_UART},
    ImageOptions,
};
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

    let measurement = [1u8; 48];
    let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0u8; 4],
        measurement,
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

    // create a new fw image with the runtime replaced by the mbox responder
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    // trigger an update reset so we can use commands in mbox responder
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

    // hash expected DPE measurements in order to check that stashed measurement was added to DPE
    let measurements_to_be_hashed = [rt_journey_pcr, valid_pauser_hash, measurement].concat();
    let expected_measurement_hash = model
        .mailbox_execute(0x4000_0000, measurements_to_be_hashed.as_bytes())
        .unwrap()
        .unwrap();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash, dpe_measurement_hash);
}

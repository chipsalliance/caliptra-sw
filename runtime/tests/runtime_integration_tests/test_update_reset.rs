// Licensed under the Apache-2.0 license

use std::mem::size_of;

use caliptra_builder::{
    firmware::{self, APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    CommandId, FwInfoResp, MailboxReq, MailboxReqHeader, TagTciReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use dpe::{DpeInstance, U8Bool, MAX_HANDLES};
use zerocopy::{AsBytes, FromBytes};

use crate::common::run_rt_test;

#[test]
fn test_rt_journey_pcr_updated_in_dpe() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // trigger update reset
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let dpe_root_measurement_resp = model.mailbox_execute(0x6000_0000, &[]).unwrap().unwrap();
    let dpe_root_measurement: [u8; 48] = dpe_root_measurement_resp.as_bytes().try_into().unwrap();

    assert_eq!(dpe_root_measurement, rt_journey_pcr);
}

#[test]
fn test_tags_persistence() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Tag default context in order to change the context tags in persistent data
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: [0u8; 16],
        tag: 1,
    });
    cmd.populate_chksum().unwrap();
    let _ = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We expected a response");

    // trigger update reset
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    const TAGS_INFO_SIZE: usize =
        size_of::<u32>() * MAX_HANDLES + size_of::<U8Bool>() * MAX_HANDLES;
    let tags_resp_1 = model.mailbox_execute(0x7000_0000, &[]).unwrap().unwrap();
    let tags_1: [u8; TAGS_INFO_SIZE] = tags_resp_1.as_bytes().try_into().unwrap();

    // trigger another update reset with same fw
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    let tags_resp_2 = model.mailbox_execute(0x7000_0000, &[]).unwrap().unwrap();
    let tags_2: [u8; TAGS_INFO_SIZE] = tags_resp_2.as_bytes().try_into().unwrap();

    // check that the tags are the same across update resets
    assert_eq!(tags_1, tags_2);
    // check that the tags are not default tags
    assert_ne!(tags_1, [0u8; TAGS_INFO_SIZE]);
}

#[test]
fn test_context_tags_validation() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::MBOX), None, None);

    // make context_tags validation fail by "tagging" an inactive context
    let mut context_tags = [0u32; MAX_HANDLES];
    context_tags[20] = 1;

    let _ = model
        .mailbox_execute(0x8000_0000, context_tags.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_CONTEXT_TAGS_VALIDATION_FAILED)
    });
}

#[test]
fn test_context_has_tag_validation() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::MBOX), None, None);

    // make context_has_tag validation fail by "tagging" an inactive context
    let mut context_has_tag = [U8Bool::new(false); MAX_HANDLES];
    context_has_tag[20] = U8Bool::new(true);

    let _ = model
        .mailbox_execute(0x9000_0000, context_has_tag.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_CONTEXT_HAS_TAG_VALIDATION_FAILED)
    });
}

#[test]
fn test_dpe_validation() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::MBOX), None, None);

    // read DPE after RT initialization
    let dpe_resp = model.mailbox_execute(0xA000_0000, &[]).unwrap().unwrap();
    let mut dpe = DpeInstance::read_from(dpe_resp.as_bytes()).unwrap();

    // corrupt DPE structure by creating a cycle in the context tree
    dpe.contexts[1].children = 0b1;
    let _ = model
        .mailbox_execute(0xB000_0000, dpe.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();
    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_DPE_VALIDATION_FAILED)
    });

    // check attestation disabled via FW_INFO
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let info = FwInfoResp::read_from(resp.as_slice()).unwrap();
    assert_eq!(info.attestation_disabled, 1);
}

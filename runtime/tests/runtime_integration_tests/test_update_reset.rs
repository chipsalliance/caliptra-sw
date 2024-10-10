// Licensed under the Apache-2.0 license

use std::mem::size_of;

pub use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{runtime_tests::MBOX, APP_WITH_UART, FMC_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_common::mailbox_api::{
    CommandId, FwInfoResp, IncrementPcrResetCounterReq, MailboxReq, MailboxReqHeader, TagTciReq,
};
use caliptra_drivers::PcrResetCounter;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::{ContextState, RtBootStatus, PL0_DPE_ACTIVE_CONTEXT_THRESHOLD};
use dpe::{
    context::{Context, ContextHandle, ContextType},
    response::DpeErrorCode,
    tci::TciMeasurement,
    validation::ValidationError,
    DpeInstance, U8Bool, DPE_PROFILE, MAX_HANDLES,
};
use zerocopy::{FromBytes, IntoBytes, TryFromBytes};

use crate::common::run_rt_test;

fn update_fw(model: &mut DefaultHwModel, rt_fw: &FwId<'static>, image_opts: ImageOptions) {
    let image = caliptra_builder::build_and_sign_image(&FMC_WITH_UART, rt_fw, image_opts)
        .unwrap()
        .to_bytes()
        .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();
}

#[test]
fn test_rt_journey_pcr_updated_in_dpe() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // trigger update reset
    update_fw(&mut model, &MBOX, ImageOptions::default());

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
    update_fw(&mut model, &MBOX, ImageOptions::default());

    const TAGS_INFO_SIZE: usize =
        size_of::<u32>() * MAX_HANDLES + size_of::<U8Bool>() * MAX_HANDLES;
    let tags_resp_1 = model.mailbox_execute(0x7000_0000, &[]).unwrap().unwrap();
    let tags_1: [u8; TAGS_INFO_SIZE] = tags_resp_1.as_bytes().try_into().unwrap();

    // trigger another update reset with same fw
    update_fw(&mut model, &MBOX, ImageOptions::default());

    let tags_resp_2 = model.mailbox_execute(0x7000_0000, &[]).unwrap().unwrap();
    let tags_2: [u8; TAGS_INFO_SIZE] = tags_resp_2.as_bytes().try_into().unwrap();

    // check that the tags are the same across update resets
    assert_eq!(tags_1, tags_2);
    // check that the tags are not default tags
    assert_ne!(tags_1, [0u8; TAGS_INFO_SIZE]);
}

#[test]
fn test_context_tags_validation() {
    let mut model = run_rt_test(Some(&MBOX), None, None);

    // make context_tags validation fail by "tagging" an inactive context
    let mut context_tags = [0u32; MAX_HANDLES];
    context_tags[20] = 1;

    let _ = model
        .mailbox_execute(0x8000_0000, context_tags.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    update_fw(&mut model, &APP_WITH_UART, ImageOptions::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_CONTEXT_TAGS_VALIDATION_FAILED)
    });
}

#[test]
fn test_context_has_tag_validation() {
    let mut model = run_rt_test(Some(&MBOX), None, None);

    // make context_has_tag validation fail by "tagging" an inactive context
    let mut context_has_tag = [U8Bool::new(false); MAX_HANDLES];
    context_has_tag[20] = U8Bool::new(true);

    let _ = model
        .mailbox_execute(0x9000_0000, context_has_tag.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    update_fw(&mut model, &APP_WITH_UART, ImageOptions::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_CONTEXT_HAS_TAG_VALIDATION_FAILED)
    });
}

#[test]
fn test_dpe_validation_deformed_structure() {
    let mut model = run_rt_test(Some(&MBOX), None, None);

    // read DPE after RT initialization
    let dpe_resp = model.mailbox_execute(0xA000_0000, &[]).unwrap().unwrap();
    let mut dpe = DpeInstance::try_read_from_bytes(dpe_resp.as_bytes()).unwrap();

    // corrupt DPE structure by creating multiple normal connected components
    dpe.contexts[0].children = 0;
    dpe.contexts[0].state = ContextState::Active;
    dpe.contexts[1].parent_idx = Context::ROOT_INDEX;
    let _ = model
        .mailbox_execute(0xB000_0000, dpe.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    update_fw(&mut model, &APP_WITH_UART, ImageOptions::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_DPE_VALIDATION_FAILED)
    });
    assert_eq!(
        model
            .soc_ifc()
            .cptra_fw_extended_error_info()
            .read()
            .as_bytes()[..size_of::<u32>()],
        DpeErrorCode::Validation(ValidationError::MultipleNormalConnectedComponents)
            .get_error_code()
            .to_le_bytes()
    );

    // check attestation disabled via FW_INFO
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let info = FwInfoResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(info.attestation_disabled, 1);
}

#[test]
fn test_dpe_validation_illegal_state() {
    let mut model = run_rt_test(Some(&MBOX), None, None);

    // read DPE after RT initialization
    let dpe_resp = model.mailbox_execute(0xA000_0000, &[]).unwrap().unwrap();
    let mut dpe = DpeInstance::try_read_from_bytes(dpe_resp.as_bytes()).unwrap();

    // corrupt DPE state by messing up parent-child links
    dpe.contexts[1].children = 0b1;
    let _ = model
        .mailbox_execute(0xB000_0000, dpe.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    update_fw(&mut model, &APP_WITH_UART, ImageOptions::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_DPE_VALIDATION_FAILED)
    });
    assert_eq!(
        model
            .soc_ifc()
            .cptra_fw_extended_error_info()
            .read()
            .as_bytes()[..size_of::<u32>()],
        DpeErrorCode::Validation(ValidationError::ParentChildLinksCorrupted)
            .get_error_code()
            .to_le_bytes()
    );

    // check attestation disabled via FW_INFO
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let info = FwInfoResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(info.attestation_disabled, 1);
}

#[test]
fn test_dpe_validation_used_context_threshold_exceeded() {
    let mut model = run_rt_test(Some(&MBOX), None, None);

    // read DPE after RT initialization
    let dpe_resp = model.mailbox_execute(0xA000_0000, &[]).unwrap().unwrap();
    let mut dpe = DpeInstance::try_read_from_bytes(dpe_resp.as_bytes()).unwrap();

    // corrupt DPE structure by creating PL0_DPE_ACTIVE_CONTEXT_THRESHOLD contexts
    let pl0_pauser = ImageOptions::default().vendor_config.pl0_pauser.unwrap();
    // make dpe.contexts[1].handle non-default in order to pass dpe state validation
    dpe.contexts[1].handle = ContextHandle([1u8; ContextHandle::SIZE]);
    // the mbox valid pausers measurement is already in PL0 so creating PL0_DPE_ACTIVE_CONTEXT_THRESHOLD suffices
    for i in 0..PL0_DPE_ACTIVE_CONTEXT_THRESHOLD {
        // skip first two contexts measured by RT
        let idx = i + 2;
        // create simulation contexts in PL0
        dpe.contexts[idx].state = ContextState::Active;
        dpe.contexts[idx].context_type = ContextType::Simulation;
        dpe.contexts[idx].locality = pl0_pauser;
        dpe.contexts[idx].tci.locality = pl0_pauser;
        dpe.contexts[idx].tci.tci_current = TciMeasurement([idx as u8; DPE_PROFILE.get_tci_size()]);
        dpe.contexts[idx].tci.tci_cumulative =
            TciMeasurement([idx as u8; DPE_PROFILE.get_tci_size()]);
        dpe.contexts[idx].handle = ContextHandle([idx as u8; ContextHandle::SIZE]);
    }
    let _ = model
        .mailbox_execute(0xB000_0000, dpe.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    update_fw(&mut model, &APP_WITH_UART, ImageOptions::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED)
    });

    // check attestation disabled via FW_INFO
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let info = FwInfoResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(info.attestation_disabled, 1);
}

#[test]
fn test_pcr_reset_counter_persistence() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Increment counter for PCR0 in order to change the pcr reset counter in persistent data
    let mut cmd = MailboxReq::IncrementPcrResetCounter(IncrementPcrResetCounterReq {
        hdr: MailboxReqHeader { chksum: 0 },
        index: 0,
    });
    cmd.populate_chksum().unwrap();
    let _ = model
        .mailbox_execute(
            u32::from(CommandId::INCREMENT_PCR_RESET_COUNTER),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We expected a response");

    // trigger update reset
    update_fw(&mut model, &MBOX, ImageOptions::default());

    let pcr_reset_counter_resp_1 = model.mailbox_execute(0xC000_0000, &[]).unwrap().unwrap();
    let pcr_reset_counter_1: [u8; size_of::<PcrResetCounter>()] =
        pcr_reset_counter_resp_1.as_bytes().try_into().unwrap();

    // trigger another update reset with same fw
    update_fw(&mut model, &MBOX, ImageOptions::default());

    let pcr_reset_counter_resp_2 = model.mailbox_execute(0xC000_0000, &[]).unwrap().unwrap();
    let pcr_reset_counter_2: [u8; size_of::<PcrResetCounter>()] =
        pcr_reset_counter_resp_2.as_bytes().try_into().unwrap();

    // check that the pcr reset counters are the same across update resets
    assert_eq!(pcr_reset_counter_1, pcr_reset_counter_2);
    // check that the pcr reset counters are not default
    assert_ne!(pcr_reset_counter_1, [0u8; size_of::<PcrResetCounter>()]);
}

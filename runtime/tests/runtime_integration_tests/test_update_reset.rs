// Licensed under the Apache-2.0 license

use std::mem::size_of;

use caliptra_builder::{
    firmware::{runtime_tests::MBOX, APP_WITH_UART, FMC_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_common::mailbox_api::{
    CommandId, FwInfoResp, IncrementPcrResetCounterReq, MailboxReq, MailboxReqHeader, TagTciReq,
};
use caliptra_drivers::PcrResetCounter;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_runtime::{ContextState, RtBootStatus, PL0_DPE_ACTIVE_CONTEXT_THRESHOLD};
use dpe::{
    context::{Context, ContextHandle, ContextType},
    response::DpeErrorCode,
    tci::TciMeasurement,
    validation::ValidationError,
    DpeInstance, U8Bool, DPE_PROFILE, MAX_HANDLES,
};
use zerocopy::{AsBytes, FromBytes};

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
    let mut dpe = DpeInstance::read_from(dpe_resp.as_bytes()).unwrap();

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
    let info = FwInfoResp::read_from(resp.as_slice()).unwrap();
    assert_eq!(info.attestation_disabled, 1);
}

#[test]
fn test_dpe_validation_illegal_state() {
    let mut model = run_rt_test(Some(&MBOX), None, None);

    // read DPE after RT initialization
    let dpe_resp = model.mailbox_execute(0xA000_0000, &[]).unwrap().unwrap();
    let mut dpe = DpeInstance::read_from(dpe_resp.as_bytes()).unwrap();

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
    let info = FwInfoResp::read_from(resp.as_slice()).unwrap();
    assert_eq!(info.attestation_disabled, 1);
}

#[test]
fn test_dpe_validation_used_context_threshold_exceeded() {
    let mut model = run_rt_test(Some(&MBOX), None, None);

    // read DPE after RT initialization
    let dpe_resp = model.mailbox_execute(0xA000_0000, &[]).unwrap().unwrap();
    let mut dpe = DpeInstance::read_from(dpe_resp.as_bytes()).unwrap();

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
    let info = FwInfoResp::read_from(resp.as_slice()).unwrap();
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

fn get_image_opts(svn: u32, epoch: &[u8; 2]) -> ImageOptions {
    let mut options = ImageOptions {
        app_svn: svn,
        ..Default::default()
    };

    options.owner_config.as_mut().unwrap().epoch = *epoch;
    options
}

fn get_chain_digest(model: &mut DefaultHwModel, num_hashes: u32) -> Vec<u8> {
    let digest = model
        .mailbox_execute(0xF000_0000, num_hashes.as_bytes())
        .unwrap()
        .unwrap();

    assert!(!digest.is_empty());
    digest
}

const MAX_SVN: u32 = 128;

#[test]
fn test_hash_chain() {
    let epoch = [0x00, 0x01];

    let update_to_svn = |model: &mut DefaultHwModel, svn: u32| {
        update_fw(model, &MBOX, get_image_opts(svn, &epoch));
    };

    let mut model = run_rt_test(Some(&MBOX), Some(get_image_opts(0, &epoch)), None);

    let chain_0 = get_chain_digest(&mut model, 0);

    update_to_svn(&mut model, 1);

    // FW should now have a different hash chain.
    let chain_1 = get_chain_digest(&mut model, 0);

    // Ask FW to hash the chain once before returning a digest.
    let chain_1_hashed = get_chain_digest(&mut model, 1);

    assert_ne!(chain_1_hashed, chain_1);
    assert_eq!(chain_1_hashed, chain_0);

    // Update to the max SVN supported by FMC.
    update_to_svn(&mut model, MAX_SVN);

    let chain_max = get_chain_digest(&mut model, 0);

    // Ask FW to hash the chain enough times to get back to 1.
    let chain_max_hashed = get_chain_digest(&mut model, MAX_SVN - 1);

    assert_ne!(chain_max_hashed, chain_max);
    assert_eq!(chain_max_hashed, chain_1);

    // Update past the max supported by FMC.
    update_to_svn(&mut model, MAX_SVN + 1);

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RT_SVN_EXCEEDS_MAX)
            && m.soc_ifc().cptra_fw_error_fatal().read()
                == u32::from(CaliptraError::RT_SVN_EXCEEDS_MAX)
    });

    assert_eq!(
        model
            .mailbox_execute(0xF000_0000, 0_u32.as_bytes())
            .unwrap_err(),
        ModelError::MailboxCmdFailed(CaliptraError::RT_SVN_EXCEEDS_MAX.into())
    );
}

#[test]
fn test_hash_chain_different_epochs() {
    // Same SVN, different epochs.
    let options_0 = get_image_opts(0, &[0x00, 0x00]);
    let options_1 = get_image_opts(0, &[0x00, 0x01]);

    let mut model = run_rt_test(Some(&MBOX), Some(options_0), None);

    let chain_0 = get_chain_digest(&mut model, 0);

    update_fw(&mut model, &MBOX, options_1);

    let chain_1 = get_chain_digest(&mut model, 0);

    assert_ne!(chain_0, chain_1);
}

#[test]
fn test_hash_chain_max_svn() {
    let mut model = run_rt_test(Some(&MBOX), None, None);
    let resp = model.mailbox_execute(0xE000_0000, &[]).unwrap().unwrap();

    let max = u16::from_le_bytes(resp.try_into().unwrap());
    assert_eq!(max as u32, MAX_SVN);
}

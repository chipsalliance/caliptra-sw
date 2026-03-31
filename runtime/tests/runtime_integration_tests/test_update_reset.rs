// Licensed under the Apache-2.0 license

use std::mem::size_of;

pub use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{
        runtime_tests::{MBOX, MBOX_FPGA, MBOX_WITHOUT_UART, MBOX_WITHOUT_UART_FPGA},
        APP_WITH_UART, FMC_FAKE_WITH_UART, FMC_WITH_UART,
    },
    FwId, ImageOptions,
};
use caliptra_common::mailbox_api::{
    CommandId, FwInfoResp, IncrementPcrResetCounterReq, MailboxReq, MailboxReqHeader, TagTciReq,
};
use caliptra_drivers::PcrResetCounter;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    DefaultHwModel, DeviceLifecycle, HwModel, InitParams, ModelError, SecurityState,
};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_runtime::{ContextState, PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD};
use dpe::{
    context::{Context, ContextHandle, ContextType},
    response::DpeErrorCode,
    tci::TciMeasurement,
    validation::ValidationError,
    DpeInstance, U8Bool, DPE_PROFILE, MAX_HANDLES,
};
use zerocopy::{FromBytes, IntoBytes, TryFromBytes};

use crate::common::{
    calculate_cptra_config_init_vals_hash, run_rt_test, run_rt_test_return_fw, RuntimeTestArgs,
};

pub fn update_fw(model: &mut DefaultHwModel, rt_fw: &FwId<'static>, image_opts: ImageOptions) {
    let image = caliptra_builder::build_and_sign_image(&FMC_WITH_UART, rt_fw, image_opts)
        .unwrap()
        .to_bytes()
        .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();
}

pub fn mbox_test_image() -> &'static FwId<'static> {
    if cfg!(any(feature = "fpga_realtime", feature = "fpga_subsystem")) {
        &MBOX_FPGA
    } else {
        &MBOX
    }
}

pub fn mbox_test_image_without_uart() -> &'static FwId<'static> {
    if cfg!(any(feature = "fpga_realtime", feature = "fpga_subsystem")) {
        &MBOX_WITHOUT_UART_FPGA
    } else {
        &MBOX_WITHOUT_UART
    }
}

#[test]
fn test_rt_pcr_updated_in_dpe() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_test_args = RuntimeTestArgs {
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_test_args);

    model.step_until_ready_for_runtime();

    // trigger update reset
    update_fw(&mut model, mbox_test_image(), image_options);

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let dpe_root_measurement_resp = model.mailbox_execute(0x6000_0001, &[]).unwrap().unwrap();
    let dpe_root_measurement: [u8; 48] = dpe_root_measurement_resp.as_bytes().try_into().unwrap();

    assert_eq!(dpe_root_measurement, rt_journey_pcr);

    let rt_current_pcr_resp = model.mailbox_execute(0x1000_0001, &[]).unwrap().unwrap();
    let rt_current_pcr: [u8; 48] = rt_current_pcr_resp.as_bytes().try_into().unwrap();

    let dpe_root_measurement_resp = model.mailbox_execute(0x6000_0000, &[]).unwrap().unwrap();
    let dpe_root_measurement: [u8; 48] = dpe_root_measurement_resp.as_bytes().try_into().unwrap();

    assert_eq!(dpe_root_measurement, rt_current_pcr);
}

#[test]
fn test_rt_journey_pcr_updated_with_good_fw() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_test_args = RuntimeTestArgs {
        test_image_options: Some(image_options.clone()),
        test_fwid: Some(mbox_test_image()),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_test_args);

    model.step_until_ready_for_runtime();

    let orig_rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let orig_rt_journey_pcr: [u8; 48] = orig_rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    // trigger update reset
    update_fw(&mut model, mbox_test_image_without_uart(), image_options);

    model.step_until_ready_for_runtime();

    let new_rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let new_rt_journey_pcr: [u8; 48] = new_rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    assert_ne!(orig_rt_journey_pcr, new_rt_journey_pcr);
}

#[test]
fn test_rt_journey_pcr_not_updated_with_bad_fw() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_test_args = RuntimeTestArgs {
        test_image_options: Some(image_options.clone()),
        test_fwid: Some(mbox_test_image()),
        subsystem_mode: true,
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_test_args);

    model.step_until_ready_for_runtime();

    let orig_rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let orig_rt_journey_pcr: [u8; 48] = orig_rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    // TODO(nquarton): In subsystem mode, this expected ROM_UPDATE_RESET_FLOW_IMAGE_NOT_IN_MCU_SRAM in 2.1 FW
    //                 This error does not exist in 2.0. May or may not need to be updated
    let expected_error = CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH.into();

    // trigger update reset with bad FW bundle
    assert_eq!(
        model.mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &[0u8; 128]),
        Err(ModelError::MailboxCmdFailed(expected_error))
    );

    model.step_until_ready_for_runtime();

    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        expected_error
    );

    let new_rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let new_rt_journey_pcr: [u8; 48] = new_rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    assert_eq!(orig_rt_journey_pcr, new_rt_journey_pcr);
}

#[test]
fn test_tags_persistence() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_test_args = RuntimeTestArgs {
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_test_args);

    model.step_until_ready_for_runtime();

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
    update_fw(&mut model, mbox_test_image(), image_options.clone());

    const TAGS_INFO_SIZE: usize =
        size_of::<u32>() * MAX_HANDLES + size_of::<U8Bool>() * MAX_HANDLES;
    let tags_resp_1 = model.mailbox_execute(0x7000_0000, &[]).unwrap().unwrap();
    let tags_1: [u8; TAGS_INFO_SIZE] = tags_resp_1.as_bytes().try_into().unwrap();

    // trigger another update reset with same fw
    update_fw(&mut model, mbox_test_image(), image_options);

    let tags_resp_2 = model.mailbox_execute(0x7000_0000, &[]).unwrap().unwrap();
    let tags_2: [u8; TAGS_INFO_SIZE] = tags_resp_2.as_bytes().try_into().unwrap();

    // check that the tags are the same across update resets
    assert_eq!(tags_1, tags_2);
    // check that the tags are not default tags
    assert_ne!(tags_1, [0u8; TAGS_INFO_SIZE]);
}

#[test]
fn test_context_tags_validation() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_test_args = RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_test_args);

    // make context_tags validation fail by "tagging" an inactive context
    let mut context_tags = [0u32; MAX_HANDLES];
    context_tags[20] = 1;

    let _ = model
        .mailbox_execute(0x8000_0000, context_tags.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    let fw_id = if cfg!(any(feature = "fpga_realtime", feature = "fpga_subsystem")) {
        &MBOX_WITHOUT_UART
    } else {
        &MBOX_WITHOUT_UART_FPGA
    };
    update_fw(&mut model, fw_id, image_options);

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_CONTEXT_TAGS_VALIDATION_FAILED)
    });
}

#[test]
fn test_context_has_tag_validation() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let args = RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    // make context_has_tag validation fail by "tagging" an inactive context
    let mut context_has_tag = [U8Bool::new(false); MAX_HANDLES];
    context_has_tag[20] = U8Bool::new(true);

    let _ = model
        .mailbox_execute(0x9000_0000, context_has_tag.as_bytes())
        .unwrap()
        .unwrap();

    // trigger update reset
    update_fw(&mut model, &APP_WITH_UART, image_options);

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_CONTEXT_HAS_TAG_VALIDATION_FAILED)
    });
}

#[test]
fn test_dpe_validation_deformed_structure() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let args = RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

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
    update_fw(&mut model, &APP_WITH_UART, image_options);
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
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let args = RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

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
    update_fw(&mut model, &APP_WITH_UART, image_options);
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
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let args = RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    // read DPE after RT initialization
    let dpe_resp = model.mailbox_execute(0xA000_0000, &[]).unwrap().unwrap();
    let mut dpe = DpeInstance::try_read_from_bytes(dpe_resp.as_bytes()).unwrap();

    // corrupt DPE structure by creating PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD contexts
    let pl0_pauser = ImageOptions::default().vendor_config.pl0_pauser.unwrap();
    // make dpe.contexts[1].handle non-default in order to pass dpe state validation
    dpe.contexts[1].handle = ContextHandle([1u8; ContextHandle::SIZE]);
    // the mbox valid pausers measurement and RT journey measurement already count as PL0
    // so creating PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD suffices
    for i in 0..(PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD - 1) {
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
    update_fw(&mut model, &APP_WITH_UART, image_options);
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
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_args = RuntimeTestArgs {
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_args);

    model.step_until_ready_for_runtime();

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
    update_fw(&mut model, mbox_test_image(), image_options.clone());

    let pcr_reset_counter_resp_1 = model.mailbox_execute(0xC000_0000, &[]).unwrap().unwrap();
    let pcr_reset_counter_1: [u8; size_of::<PcrResetCounter>()] =
        pcr_reset_counter_resp_1.as_bytes().try_into().unwrap();

    // trigger another update reset with same fw
    update_fw(&mut model, mbox_test_image(), image_options);

    let pcr_reset_counter_resp_2 = model.mailbox_execute(0xC000_0000, &[]).unwrap().unwrap();
    let pcr_reset_counter_2: [u8; size_of::<PcrResetCounter>()] =
        pcr_reset_counter_resp_2.as_bytes().try_into().unwrap();

    // check that the pcr reset counters are the same across update resets
    assert_eq!(pcr_reset_counter_1, pcr_reset_counter_2);
    // check that the pcr reset counters are not default
    assert_ne!(pcr_reset_counter_1, [0u8; size_of::<PcrResetCounter>()]);
}

fn get_image_opts(svn: u32) -> ImageOptions {
    ImageOptions {
        fw_svn: svn,
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    }
}

fn cold_update_to_svn(model: DefaultHwModel, svn: u32) -> DefaultHwModel {
    drop(model);
    run_rt_test(RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(get_image_opts(svn)),
        ..Default::default()
    })
}

fn runtime_update_to_svn(model: &mut DefaultHwModel, svn: u32) {
    update_fw(model, mbox_test_image(), get_image_opts(svn));
}

fn get_ladder_digest(model: &mut DefaultHwModel, target_svn: u32) -> Vec<u8> {
    let digest = model
        .mailbox_execute(0x1000_1000, target_svn.as_bytes())
        .unwrap()
        .unwrap();

    assert!(!digest.is_empty());
    digest
}

fn assert_target_svn_too_large(model: &mut DefaultHwModel, target_svn: u32) {
    assert_eq!(
        model.mailbox_execute(0x1000_1000, target_svn.as_bytes()),
        Err(ModelError::MailboxCmdFailed(u32::from(
            CaliptraError::RUNTIME_KEY_LADDER_TARGET_SVN_TOO_LARGE,
        )))
    );
}

const MAX_SVN: u32 = 128;

#[test]
fn test_key_ladder_cold_boot() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(get_image_opts(0)),
        ..Default::default()
    });

    let ladder_0 = get_ladder_digest(&mut model, 0);

    model = cold_update_to_svn(model, 1);

    // FW should now have a different key ladder.
    let ladder_1 = get_ladder_digest(&mut model, 1);

    // Ask FW to extend the ladder once before returning a digest.
    let ladder_0_from_1 = get_ladder_digest(&mut model, 0);

    assert_ne!(ladder_0_from_1, ladder_1);
    assert_eq!(ladder_0_from_1, ladder_0);

    // Update to the max SVN supported by ROM.
    model = cold_update_to_svn(model, MAX_SVN);

    let ladder_max = get_ladder_digest(&mut model, MAX_SVN);

    // Ask FW for a secret available to SVN 1.
    let ladder_1_from_max = get_ladder_digest(&mut model, 1);

    assert_ne!(ladder_1_from_max, ladder_max);
    assert_eq!(ladder_1_from_max, ladder_1);
}

#[test]
fn test_key_ladder_runtime_update() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(get_image_opts(5)),
        ..Default::default()
    });

    // Start at SVN 5. (Min-SVN = 5)
    let ladder_5 = get_ladder_digest(&mut model, 5);

    // Update to SVN 6. (Min-SVN = 5)
    runtime_update_to_svn(&mut model, 6);
    let ladder_6 = get_ladder_digest(&mut model, 5);
    assert_eq!(ladder_5, ladder_6);

    // Try to get a secret for SVN 6 while the min-SVN is still 5.
    assert_target_svn_too_large(&mut model, 6);

    // Downgrade to SVN 4. (Min-SVN = 4)
    runtime_update_to_svn(&mut model, 4);
    let ladder_4 = get_ladder_digest(&mut model, 4);
    assert_ne!(ladder_4, ladder_5);

    assert_target_svn_too_large(&mut model, 5);

    // Upgrade to SVN 5. (Min-SVN = 4)
    runtime_update_to_svn(&mut model, 5);
    let ladder_5_after_4 = get_ladder_digest(&mut model, 4);
    assert_eq!(ladder_5_after_4, ladder_4);

    assert_target_svn_too_large(&mut model, 5);

    // Upgrade to SVN 6. (Min-SVN = 4)
    runtime_update_to_svn(&mut model, 6);
    let ladder_6_after_4 = get_ladder_digest(&mut model, 4);
    assert_eq!(ladder_6_after_4, ladder_4);

    assert_target_svn_too_large(&mut model, 5);
    assert_target_svn_too_large(&mut model, 6);

    // Cold-boot to SVN 6 (Min-SVN = 6)
    model = cold_update_to_svn(model, 6);
    let ladder_6_after_boot = get_ladder_digest(&mut model, 6);
    assert_ne!(ladder_6_after_boot, ladder_6_after_4);

    let ladder_5_from_6 = get_ladder_digest(&mut model, 5);
    let ladder_4_from_6 = get_ladder_digest(&mut model, 4);
    assert_eq!(ladder_5_from_6, ladder_5);
    assert_eq!(ladder_4_from_6, ladder_4);

    // Can still get its own secret after deriving older ones.
    let ladder_6_from_self = get_ladder_digest(&mut model, 6);
    assert_eq!(ladder_6_from_self, ladder_6_after_boot);

    assert_target_svn_too_large(&mut model, 7);

    // Downgrade to SVN 5 (Min-SVN = 5)
    runtime_update_to_svn(&mut model, 5);
    let ladder_5_after_boot = get_ladder_digest(&mut model, 5);
    assert_eq!(ladder_5_after_boot, ladder_5);

    let ladder_4_from_5 = get_ladder_digest(&mut model, 4);
    assert_eq!(ladder_4_from_5, ladder_4);

    assert_target_svn_too_large(&mut model, 6);
}

#[test]
fn test_key_ladder_max_svn() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        ..Default::default()
    });

    let resp = model.mailbox_execute(0xF000_0000, &[]).unwrap().unwrap();

    let max = u16::from_le_bytes(resp.try_into().unwrap());
    assert_eq!(max as u32, MAX_SVN);
}

fn make_model_with_security_state(
    fmc: &'static FwId<'static>,
    app: &'static FwId<'static>,
    debug_locked: bool,
    lifecycle: DeviceLifecycle,
) -> DefaultHwModel {
    run_rt_test(RuntimeTestArgs {
        test_fwid: Some(app),
        test_fmc_fwid: Some(fmc),
        init_params: Some(InitParams {
            rom: &crate::common::rom_for_fw_integration_tests().unwrap(),
            security_state: *SecurityState::default()
                .set_debug_locked(debug_locked)
                .set_device_lifecycle(lifecycle),
            ..Default::default()
        }),
        ..Default::default()
    })
}

#[test]
// With FPGA subsystem setting the device lifecycle automatically sets a value of debug_unlock
#[cfg_attr(feature = "fpga_subsystem", ignore)]
fn test_key_ladder_changes_with_lifecycle() {
    // Test with several combinations of security state.

    let ladder_a = {
        let mut model = make_model_with_security_state(
            &FMC_WITH_UART,
            mbox_test_image(),
            false,
            DeviceLifecycle::Production,
        );
        get_ladder_digest(&mut model, 0)
    };

    let ladder_b = {
        let mut model = make_model_with_security_state(
            &FMC_WITH_UART,
            mbox_test_image(),
            false,
            DeviceLifecycle::Manufacturing,
        );
        get_ladder_digest(&mut model, 0)
    };

    let ladder_c = {
        let mut model = make_model_with_security_state(
            &FMC_WITH_UART,
            mbox_test_image(),
            true,
            DeviceLifecycle::Production,
        );
        get_ladder_digest(&mut model, 0)
    };

    let ladder_d = {
        let mut model = make_model_with_security_state(
            &FMC_WITH_UART,
            mbox_test_image(),
            true,
            DeviceLifecycle::Manufacturing,
        );
        get_ladder_digest(&mut model, 0)
    };

    assert_ne!(ladder_a, ladder_b);
    assert_ne!(ladder_a, ladder_c);
    assert_ne!(ladder_a, ladder_d);

    assert_ne!(ladder_b, ladder_c);
    assert_ne!(ladder_b, ladder_d);

    assert_ne!(ladder_c, ladder_d);
}

#[test]
fn test_key_ladder_stable_across_fw_updates() {
    // Update both FMC and app FW, and ensure the key ladder is still identical.

    let (fmc_a, app_a) = (&FMC_WITH_UART, mbox_test_image());
    let (fmc_b, app_b) = (
        &FMC_FAKE_WITH_UART,
        if cfg!(feature = "fpga_subsystem") {
            &MBOX_WITHOUT_UART_FPGA
        } else {
            &MBOX_WITHOUT_UART
        },
    );

    let ladder_a = {
        let mut model =
            make_model_with_security_state(fmc_a, app_a, true, DeviceLifecycle::Production);
        get_ladder_digest(&mut model, 0)
    };

    let ladder_b = {
        let mut model =
            make_model_with_security_state(fmc_b, app_b, true, DeviceLifecycle::Production);
        get_ladder_digest(&mut model, 0)
    };

    assert_eq!(ladder_a, ladder_b);
}

#[test]
fn test_cciv_updated_in_dpe() {
    // Helper function to calculate updated journey measurement
    fn update_journey_measurement(prev_journey: [u8; 48], current: [u8; 48]) -> [u8; 48] {
        use sha2::{Digest, Sha384};

        let mut hasher = Sha384::new();

        hasher.update(prev_journey);
        hasher.update(current);

        hasher.finalize().into()
    }

    // Use both a standard FW and the mailbox responder FW
    let image_opts = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::MLDSA,
        ..Default::default()
    };
    let image_bundle_standard =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_opts.clone())
            .unwrap();

    // Start model with mailbox responder FW first
    let args = RuntimeTestArgs {
        test_fwid: Some(mbox_test_image()),
        test_image_options: Some(image_opts.clone()),
        key_type: Some(FwVerificationPqcKeyType::MLDSA),
        ..Default::default()
    };
    let (mut model, image_bundle_mbox) = run_rt_test_return_fw(args);

    // Generate the expected CCIV values for each of the two FWs
    let cciv_hash_mbox_bundle_exp: [u8; 48] =
        calculate_cptra_config_init_vals_hash(&mut model, &image_bundle_mbox);
    let cciv_hash_standard_bundle_exp: [u8; 48] =
        calculate_cptra_config_init_vals_hash(&mut model, &image_bundle_standard);
    assert_ne!(cciv_hash_mbox_bundle_exp, cciv_hash_standard_bundle_exp);

    // Calculate initial journey measurement
    let zero_hash = [0u8; 48];
    let cciv_journey_exp: [u8; 48] =
        update_journey_measurement(zero_hash, cciv_hash_mbox_bundle_exp);

    // Get actual values from FW
    let cciv_current_resp = model.mailbox_execute(0x6000_0002, &[]).unwrap().unwrap();
    let cciv_current: [u8; 48] = cciv_current_resp.as_bytes().try_into().unwrap();

    let cciv_journey_resp = model.mailbox_execute(0x6000_0003, &[]).unwrap().unwrap();
    let cciv_journey: [u8; 48] = cciv_journey_resp.as_bytes().try_into().unwrap();

    // Compare actual vs expected
    assert_eq!(cciv_hash_mbox_bundle_exp, cciv_current);
    assert_eq!(cciv_journey_exp, cciv_journey);

    // Trigger update to the same FW
    model
        .mailbox_execute(
            u32::from(CommandId::FIRMWARE_LOAD),
            &image_bundle_mbox.to_bytes().unwrap(),
        )
        .unwrap();
    model.step_until_ready_for_runtime();

    // Get actual values from FW
    let cciv_current_resp = model.mailbox_execute(0x6000_0002, &[]).unwrap().unwrap();
    let cciv_current: [u8; 48] = cciv_current_resp.as_bytes().try_into().unwrap();

    let cciv_journey_resp = model.mailbox_execute(0x6000_0003, &[]).unwrap().unwrap();
    let cciv_journey: [u8; 48] = cciv_journey_resp.as_bytes().try_into().unwrap();

    // Compare actual vs expected
    // Journey should not have been updated since current did not change
    assert_eq!(cciv_hash_mbox_bundle_exp, cciv_current);
    assert_eq!(cciv_journey_exp, cciv_journey);

    // Trigger update reset to standard FW
    model
        .mailbox_execute(
            u32::from(CommandId::FIRMWARE_LOAD),
            &image_bundle_standard.to_bytes().unwrap(),
        )
        .unwrap();
    model.step_until_ready_for_runtime();

    // Update CCIV journey measurement
    let cciv_journey_exp: [u8; 48] =
        update_journey_measurement(cciv_journey_exp, cciv_hash_standard_bundle_exp);

    // Trigger update reset back to mailbox responder FW
    model
        .mailbox_execute(
            u32::from(CommandId::FIRMWARE_LOAD),
            &image_bundle_mbox.to_bytes().unwrap(),
        )
        .unwrap();
    model.step_until_ready_for_runtime();

    // Update expected CCIV journey measurement
    let cciv_journey_exp: [u8; 48] =
        update_journey_measurement(cciv_journey_exp, cciv_hash_mbox_bundle_exp);

    // Get actual values from FW
    let cciv_current_resp = model.mailbox_execute(0x6000_0002, &[]).unwrap().unwrap();
    let cciv_current: [u8; 48] = cciv_current_resp.as_bytes().try_into().unwrap();

    let cciv_journey_resp = model.mailbox_execute(0x6000_0003, &[]).unwrap().unwrap();
    let cciv_journey: [u8; 48] = cciv_journey_resp.as_bytes().try_into().unwrap();

    // Compare actual vs expected
    assert_eq!(cciv_hash_mbox_bundle_exp, cciv_current);
    assert_eq!(cciv_journey_exp, cciv_journey);
}

// Licensed under the Apache-2.0 license

use std::mem::size_of;

pub use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{
        runtime_tests::{MBOX, MBOX_WITHOUT_UART},
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
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, ModelError,
    SecurityState,
};
use caliptra_runtime::{ContextState, RtBootStatus, PL0_DPE_ACTIVE_CONTEXT_THRESHOLD};
use caliptra_test::image_pk_desc_hash;
use dpe::{
    context::{Context, ContextHandle, ContextType},
    response::DpeErrorCode,
    tci::TciMeasurement,
    validation::ValidationError,
    DpeInstance, U8Bool, DPE_PROFILE, MAX_HANDLES,
};
use zerocopy::{AsBytes, FromBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

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
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
    let args = RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

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
    let args = RuntimeTestArgs {
        test_fwid: Some(&MBOX),
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
    update_fw(&mut model, &APP_WITH_UART, ImageOptions::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_CONTEXT_HAS_TAG_VALIDATION_FAILED)
    });
}

#[test]
fn test_dpe_validation_deformed_structure() {
    let args = RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

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
    let args = RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

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
    let args = RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

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
    let mut model = run_rt_test(RuntimeTestArgs::default());

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

fn get_image_opts(epoch: &[u8; 2], svn: u32) -> ImageOptions {
    let mut options = ImageOptions {
        app_svn: svn,
        ..Default::default()
    };

    options.owner_config.as_mut().unwrap().epoch = *epoch;
    options
}

fn cold_update_to_svn(model: DefaultHwModel, epoch: &[u8; 2], svn: u32) -> DefaultHwModel {
    drop(model);
    run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        test_image_options: Some(get_image_opts(epoch, svn)),
        ..Default::default()
    })
}

fn runtime_update_to_svn(model: &mut DefaultHwModel, epoch: &[u8; 2], svn: u32) {
    update_fw(model, &MBOX, get_image_opts(epoch, svn));
}

fn get_ladder_digest(model: &mut DefaultHwModel, target_svn: u32) -> Vec<u8> {
    let digest = model
        .mailbox_execute(0xF000_0000, target_svn.as_bytes())
        .unwrap()
        .unwrap();

    assert!(!digest.is_empty());
    digest
}

fn assert_target_svn_too_large(model: &mut DefaultHwModel, target_svn: u32) {
    assert_eq!(
        model.mailbox_execute(0xF000_0000, target_svn.as_bytes()),
        Err(ModelError::MailboxCmdFailed(u32::from(
            CaliptraError::RUNTIME_KEY_LADDER_TARGET_SVN_TOO_LARGE,
        )))
    );
}

const MAX_SVN: u32 = 128;

#[test]
fn test_key_ladder_cold_boot() {
    let epoch = [0x00, 0x01];

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        test_image_options: Some(get_image_opts(&epoch, 0)),
        ..Default::default()
    });

    let ladder_0 = get_ladder_digest(&mut model, 0);

    model = cold_update_to_svn(model, &epoch, 1);

    // FW should now have a different key ladder.
    let ladder_1 = get_ladder_digest(&mut model, 1);

    // Ask FW to extend the ladder once before returning a digest.
    let ladder_0_from_1 = get_ladder_digest(&mut model, 0);

    assert_ne!(ladder_0_from_1, ladder_1);
    assert_eq!(ladder_0_from_1, ladder_0);

    // Update to the max SVN supported by ROM.
    model = cold_update_to_svn(model, &epoch, MAX_SVN);

    let ladder_max = get_ladder_digest(&mut model, MAX_SVN);

    // Ask FW for a secret available to SVN 1.
    let ladder_1_from_max = get_ladder_digest(&mut model, 1);

    assert_ne!(ladder_1_from_max, ladder_max);
    assert_eq!(ladder_1_from_max, ladder_1);
}

#[test]
fn test_key_ladder_runtime_update() {
    let epoch = [0x00, 0x01];

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        test_image_options: Some(get_image_opts(&epoch, 5)),
        ..Default::default()
    });

    // Start at SVN 5. (Min-SVN = 5)
    let ladder_5 = get_ladder_digest(&mut model, 5);

    // Update to SVN 6. (Min-SVN = 5)
    runtime_update_to_svn(&mut model, &epoch, 6);
    let ladder_6 = get_ladder_digest(&mut model, 5);
    assert_eq!(ladder_5, ladder_6);

    // Try to get a secret for SVN 6 while the min-SVN is still 5.
    assert_target_svn_too_large(&mut model, 6);

    // Downgrade to SVN 4. (Min-SVN = 4)
    runtime_update_to_svn(&mut model, &epoch, 4);
    let ladder_4 = get_ladder_digest(&mut model, 4);
    assert_ne!(ladder_4, ladder_5);

    assert_target_svn_too_large(&mut model, 5);

    // Upgrade to SVN 5. (Min-SVN = 4)
    runtime_update_to_svn(&mut model, &epoch, 5);
    let ladder_5_after_4 = get_ladder_digest(&mut model, 4);
    assert_eq!(ladder_5_after_4, ladder_4);

    assert_target_svn_too_large(&mut model, 5);

    // Upgrade to SVN 6. (Min-SVN = 4)
    runtime_update_to_svn(&mut model, &epoch, 6);
    let ladder_6_after_4 = get_ladder_digest(&mut model, 4);
    assert_eq!(ladder_6_after_4, ladder_4);

    assert_target_svn_too_large(&mut model, 5);
    assert_target_svn_too_large(&mut model, 6);

    // Cold-boot to SVN 6 (Min-SVN = 6)
    model = cold_update_to_svn(model, &epoch, 6);
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
    runtime_update_to_svn(&mut model, &epoch, 5);
    let ladder_5_after_boot = get_ladder_digest(&mut model, 5);
    assert_eq!(ladder_5_after_boot, ladder_5);

    let ladder_4_from_5 = get_ladder_digest(&mut model, 4);
    assert_eq!(ladder_4_from_5, ladder_4);

    assert_target_svn_too_large(&mut model, 6);
}

#[test]
fn test_key_ladder_across_warm_boot_epoch_changes() {
    let epoch_a = [0x00, 0x01];
    let epoch_b = [0x00, 0x02];

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        test_image_options: Some(get_image_opts(&epoch_a, 1)),
        ..Default::default()
    });

    let ladder_a = get_ladder_digest(&mut model, 1);

    runtime_update_to_svn(&mut model, &epoch_b, 1);
    let ladder_b = get_ladder_digest(&mut model, 1);

    // A runtime update of the epoch does not affect the key ladder.
    assert_eq!(ladder_a, ladder_b);
}

#[test]
fn test_key_ladder_across_cold_boot_epoch_changes() {
    let epoch_a = [0x00, 0x01];
    let epoch_b = [0x00, 0x02];

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        test_image_options: Some(get_image_opts(&epoch_a, 1)),
        ..Default::default()
    });

    let ladder_a = get_ladder_digest(&mut model, 1);

    // Same SVN, different epoch.
    model = cold_update_to_svn(model, &epoch_b, 1);

    let ladder_b = get_ladder_digest(&mut model, 1);

    assert_ne!(ladder_a, ladder_b);
}

#[test]
fn test_key_ladder_max_svn() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&MBOX),
        ..Default::default()
    });

    let resp = model.mailbox_execute(0xE000_0000, &[]).unwrap().unwrap();

    let max = u16::from_le_bytes(resp.try_into().unwrap());
    assert_eq!(max as u32, MAX_SVN);
}

fn make_model_with_security_state(
    fmc: &FwId<'static>,
    app: &FwId<'static>,
    debug_locked: bool,
    lifecycle: DeviceLifecycle,
) -> DefaultHwModel {
    let security_state = *SecurityState::default()
        .set_debug_locked(debug_locked)
        .set_device_lifecycle(lifecycle);

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let image = caliptra_builder::build_and_sign_image(fmc, app, ImageOptions::default()).unwrap();
    let (vendor_pk_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                key_manifest_pk_hash: vendor_pk_hash,
                owner_pk_hash,
                ..Default::default()
            },
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    model.step_until(|m| {
        m.soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing()
    });
    model
}

#[test]
fn test_key_ladder_changes_with_lifecycle() {
    // Test with several combinations of security state.

    let mut model =
        make_model_with_security_state(&FMC_WITH_UART, &MBOX, false, DeviceLifecycle::Production);
    let ladder_a = get_ladder_digest(&mut model, 0);

    model = make_model_with_security_state(
        &FMC_WITH_UART,
        &MBOX,
        false,
        DeviceLifecycle::Manufacturing,
    );
    let ladder_b = get_ladder_digest(&mut model, 0);

    model =
        make_model_with_security_state(&FMC_WITH_UART, &MBOX, true, DeviceLifecycle::Production);
    let ladder_c = get_ladder_digest(&mut model, 0);

    model =
        make_model_with_security_state(&FMC_WITH_UART, &MBOX, true, DeviceLifecycle::Manufacturing);
    let ladder_d = get_ladder_digest(&mut model, 0);

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

    let (fmc_a, app_a) = (&FMC_WITH_UART, &MBOX);
    let (fmc_b, app_b) = (&FMC_FAKE_WITH_UART, &MBOX_WITHOUT_UART);

    let mut model = make_model_with_security_state(fmc_a, app_a, true, DeviceLifecycle::Production);
    let ladder_a = get_ladder_digest(&mut model, 0);

    model = make_model_with_security_state(fmc_b, app_b, true, DeviceLifecycle::Production);
    let ladder_b = get_ladder_digest(&mut model, 0);

    assert_eq!(ladder_a, ladder_b);
}

// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, StashMeasurementReq, StashMeasurementResp,
};
use caliptra_hw_model::HwModel;
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_runtime::RtBootStatus;
use sha2::{Digest, Sha384};
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_stash_measurement() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_test_args = RuntimeTestArgs {
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_test_args);

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
        StashMeasurementResp::ref_from_bytes(resp.as_bytes()).unwrap();

    assert_eq!(resp_hdr.dpe_result, 0);

    // create a new fw image with the runtime replaced by the mbox responder

    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        crate::test_update_reset::mbox_test_image(),
        image_options,
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    // trigger an update reset so we can use commands in mbox responder
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    let rt_current_pcr_resp = model.mailbox_execute(0x1000_0001, &[]).unwrap().unwrap();
    let rt_current_pcr: [u8; 48] = rt_current_pcr_resp.as_bytes().try_into().unwrap();

    let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

    // hash expected DPE measurements in order to check that stashed measurement was added to DPE
    let mut hasher = Sha384::new();
    hasher.update(rt_current_pcr);
    hasher.update(valid_pauser_hash);
    hasher.update(measurement);
    let expected_measurement_hash = hasher.finalize();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash.as_bytes(), dpe_measurement_hash);
}

#[test]
fn test_pcr31_extended_upon_stash_measurement() {
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let runtime_test_args = RuntimeTestArgs {
        test_fwid: Some(crate::test_update_reset::mbox_test_image()),
        test_image_options: Some(image_options.clone()),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_test_args);

    // Read PCR_ID_STASH_MEASUREMENT
    let pcr_31_resp = model.mailbox_execute(0x5000_0000, &[]).unwrap().unwrap();
    let pcr_31: [u8; 48] = pcr_31_resp.as_bytes().try_into().unwrap();

    // update reset to the real runtime image
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        image_options.clone(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    // stash a measurement
    let measurement = [2u8; 48];
    let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0u8; 4],
        measurement,
        context: [0u8; 48],
        svn: 0,
    });
    cmd.populate_chksum().unwrap();

    let _ = model
        .mailbox_execute(
            u32::from(CommandId::STASH_MEASUREMENT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    // update reset back to mbox responder
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        crate::test_update_reset::mbox_test_image(),
        image_options.clone(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        crate::test_update_reset::mbox_test_image(),
        image_options,
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    // Read extended PCR_ID_STASH_MEASUREMENT
    let extended_pcr_31_resp = model.mailbox_execute(0x5000_0000, &[]).unwrap().unwrap();
    let extended_pcr_31: [u8; 48] = extended_pcr_31_resp.as_bytes().try_into().unwrap();

    // no need to flip endianness here since PCRs are already in same endianness
    // as sha2 hashes
    let mut hasher = Sha384::new();
    hasher.update(pcr_31);
    hasher.update(measurement);
    let expected_pcr_31 = hasher.finalize();

    assert_eq!(expected_pcr_31.as_bytes(), extended_pcr_31);
}

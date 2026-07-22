// Licensed under the Apache-2.0 license

use crate::common::{
    calculate_cptra_config_init_vals_hash, default_soc_manifest_measurements, run_rt_test,
    RuntimeTestArgs, DEFAULT_MCU_FW,
};
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
    .unwrap();

    // trigger an update reset so we can use commands in mbox responder
    model
        .mailbox_execute(
            u32::from(CommandId::FIRMWARE_LOAD),
            &updated_fw_image.to_bytes().unwrap(),
        )
        .unwrap();

    let rt_current_pcr_resp = model.mailbox_execute(0x1000_0001, &[]).unwrap().unwrap();
    let rt_current_pcr: [u8; 48] = rt_current_pcr_resp.as_bytes().try_into().unwrap();

    let cptra_config_init_vals_hash: [u8; 48] =
        calculate_cptra_config_init_vals_hash(&mut model, &updated_fw_image);

    // hash expected DPE measurements in order to check that stashed measurement was added to DPE
    let mut hasher = Sha384::new();
    hasher.update(rt_current_pcr);
    hasher.update(cptra_config_init_vals_hash);
    if model.subsystem_mode() {
        let (somv_measurement, somo_measurement) =
            default_soc_manifest_measurements(FwVerificationPqcKeyType::LMS, 0);
        hasher.update(somv_measurement);
        hasher.update(somo_measurement);
        let mut mcu_hasher = Sha384::new();
        mcu_hasher.update(DEFAULT_MCU_FW);
        hasher.update(mcu_hasher.finalize());
    }
    hasher.update(measurement);
    let expected_measurement_hash = hasher.finalize();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash.as_bytes(), dpe_measurement_hash);
}

#[test]
fn test_pcr31_extended_upon_stash_measurement() {
    fn run_sequence(stash_measurement: bool) -> [u8; 48] {
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

        if stash_measurement {
            let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq {
                hdr: MailboxReqHeader { chksum: 0 },
                metadata: [0u8; 4],
                measurement: [2u8; 48],
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
        }

        // update reset back to mbox responder so we can read PCR31
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

        let pcr_31_resp = model.mailbox_execute(0x5000_0000, &[]).unwrap().unwrap();
        pcr_31_resp.as_bytes().try_into().unwrap()
    }

    assert_ne!(run_sequence(false), run_sequence(true));
}

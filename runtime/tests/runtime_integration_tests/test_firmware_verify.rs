// Licensed under the Apache-2.0 license

use crate::common::{start_rt_test_pqc_model, RuntimeTestArgs};
use caliptra_api::mailbox::{FirmwareVerifyResp, FirmwareVerifyResult};
use caliptra_api::SocManager;
use caliptra_common::mailbox_api::CommandId;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_kat::CaliptraError;
use zerocopy::FromBytes;

#[test]
fn test_firmware_verify_success() {
    let (mut model, image) = start_rt_test_pqc_model(
        RuntimeTestArgs::default(),
        FwVerificationPqcKeyType::default(),
    );
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let resp = model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_VERIFY), image.as_slice())
        .unwrap()
        .expect("Failed to verify valid caliptra image");

    let firmware_verify_resp = FirmwareVerifyResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        firmware_verify_resp.verify_result,
        FirmwareVerifyResult::Success as u32
    );
}

#[test]
fn test_firmware_verify_invalid_image() {
    let (mut model, _) = start_rt_test_pqc_model(
        RuntimeTestArgs::default(),
        FwVerificationPqcKeyType::default(),
    );
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let invalid_image = vec![0u8; 1024]; // An obviously invalid image

    let resp = model.mailbox_execute(
        u32::from(CommandId::FIRMWARE_VERIFY),
        invalid_image.as_slice(),
    );

    if cfg!(feature = "fpga_subsystem") {
        // Since the mbox is smaller a different error gets reported
        assert_eq!(
            resp.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH.into()
            )
        );
    } else {
        let resp = resp
            .unwrap()
            .expect("Expected a response for invalid image");
        let firmware_verify_resp = FirmwareVerifyResp::read_from_bytes(resp.as_slice()).unwrap();
        assert_eq!(
            firmware_verify_resp.verify_result,
            FirmwareVerifyResult::Failure as u32
        );
    }

    let invalid_image = vec![0u8; 32 * 1024]; // An obviously invalid image
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::FIRMWARE_VERIFY),
            invalid_image.as_slice(),
        )
        .unwrap()
        .expect("Expected a response for invalid image");
    let firmware_verify_resp = FirmwareVerifyResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        firmware_verify_resp.verify_result,
        FirmwareVerifyResult::Failure as u32
    );
}

// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_common::RomBootStatus::*;
use caliptra_hw_model::Fuses;
use caliptra_hw_model::HwModel;

use crate::helpers::step_until_boot_status;
use crate::helpers::FW_LOAD_CMD_OPCODE;

pub mod helpers;

#[test]
fn test_cold_reset_status_reporting() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    step_until_boot_status(&mut hw, ColdResetStarted, false);
    step_until_boot_status(&mut hw, IDevIdDecryptUdsComplete, false);
    step_until_boot_status(&mut hw, IDevIdDecryptFeComplete, false);
    step_until_boot_status(&mut hw, IDevIdClearDoeSecretsComplete, false);
    step_until_boot_status(&mut hw, IDevIdCdiDerivationComplete, false);
    step_until_boot_status(&mut hw, IDevIdKeyPairDerivationComplete, false);
    step_until_boot_status(&mut hw, IDevIdSubjIdSnGenerationComplete, false);
    step_until_boot_status(&mut hw, IDevIdSubjKeyIdGenerationComplete, false);
    // step_until_boot_status(IdevIdMakeCsrComplete, false);
    // step_until_boot_status(IdevIdSendCsrComplete, false);
    step_until_boot_status(&mut hw, IDevIdDerivationComplete, false);
    step_until_boot_status(&mut hw, LDevIdCdiDerivationComplete, false);
    step_until_boot_status(&mut hw, LDevIdKeyPairDerivationComplete, false);
    step_until_boot_status(&mut hw, LDevIdSubjIdSnGenerationComplete, false);
    step_until_boot_status(&mut hw, LDevIdSubjKeyIdGenerationComplete, false);
    step_until_boot_status(&mut hw, LDevIdCertSigGenerationComplete, false);
    step_until_boot_status(&mut hw, LDevIdDerivationComplete, false);

    // Wait for uploading firmware.
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    // Manually put the firmware in the mailbox because
    // HwModel::upload_firmware returns only when the transaction is complete.
    // This is too late for this test.
    let buf: &[u8] = &image_bundle.to_bytes().unwrap();
    assert!(!hw.soc_mbox().lock().read().lock());
    hw.soc_mbox().cmd().write(|_| FW_LOAD_CMD_OPCODE);
    hw.soc_mbox().dlen().write(|_| buf.len() as u32);
    let mut remaining = buf;
    while remaining.len() >= 4 {
        // Panic is impossible because the subslice is always 4 bytes
        let word = u32::from_le_bytes(remaining[..4].try_into().unwrap());
        hw.soc_mbox().datain().write(|_| word);
        remaining = &remaining[4..];
    }
    if !remaining.is_empty() {
        let mut word_bytes = [0u8; 4];
        word_bytes[..remaining.len()].copy_from_slice(remaining);
        let word = u32::from_le_bytes(word_bytes);
        hw.soc_mbox().datain().write(|_| word);
    }
    hw.soc_mbox().execute().write(|w| w.execute(true));

    step_until_boot_status(&mut hw, FwProcessorDownloadImageComplete, false);
    step_until_boot_status(&mut hw, FwProcessorManifestLoadComplete, false);
    step_until_boot_status(&mut hw, FwProcessorImageVerificationComplete, false);
    step_until_boot_status(&mut hw, FwProcessorPopulateDataVaultComplete, false);
    step_until_boot_status(&mut hw, FwProcessorExtendPcrComplete, false);
    step_until_boot_status(&mut hw, FwProcessorLoadImageComplete, false);
    step_until_boot_status(&mut hw, FwProcessorFirmwareDownloadTxComplete, false);
    step_until_boot_status(&mut hw, FwProcessorComplete, false);
    step_until_boot_status(&mut hw, FmcAliasDeriveCdiComplete, false);
    step_until_boot_status(&mut hw, FmcAliasKeyPairDerivationComplete, false);
    step_until_boot_status(&mut hw, FmcAliasSubjIdSnGenerationComplete, false);
    step_until_boot_status(&mut hw, FmcAliasSubjKeyIdGenerationComplete, false);
    step_until_boot_status(&mut hw, FmcAliasCertSigGenerationComplete, false);
    step_until_boot_status(&mut hw, FmcAliasDerivationComplete, false);
    step_until_boot_status(&mut hw, ColdResetComplete, false);
}

// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::RomBootStatus::*;
use caliptra_hw_model::Fuses;
use caliptra_hw_model::HwModel;

pub mod helpers;

#[test]
fn test_cold_reset_status_reporting() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    hw.step_until_boot_status(KatStarted.into(), false);
    hw.step_until_boot_status(KatComplete.into(), false);
    hw.step_until_boot_status(ColdResetStarted.into(), false);
    hw.step_until_boot_status(IDevIdDecryptUdsComplete.into(), false);
    hw.step_until_boot_status(IDevIdDecryptFeComplete.into(), false);
    hw.step_until_boot_status(IDevIdClearDoeSecretsComplete.into(), false);
    hw.step_until_boot_status(IDevIdCdiDerivationComplete.into(), false);
    hw.step_until_boot_status(IDevIdKeyPairDerivationComplete.into(), false);
    hw.step_until_boot_status(IDevIdSubjIdSnGenerationComplete.into(), false);
    hw.step_until_boot_status(IDevIdSubjKeyIdGenerationComplete.into(), false);
    // step_until_boot_status(IdevIdMakeCsrComplete, false);
    // step_until_boot_status(IdevIdSendCsrComplete, false);
    hw.step_until_boot_status(IDevIdDerivationComplete.into(), false);
    hw.step_until_boot_status(LDevIdCdiDerivationComplete.into(), false);
    hw.step_until_boot_status(LDevIdKeyPairDerivationComplete.into(), false);
    hw.step_until_boot_status(LDevIdSubjIdSnGenerationComplete.into(), false);
    hw.step_until_boot_status(LDevIdSubjKeyIdGenerationComplete.into(), false);
    hw.step_until_boot_status(LDevIdCertSigGenerationComplete.into(), false);
    hw.step_until_boot_status(LDevIdDerivationComplete.into(), false);

    // Wait for uploading firmware.
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    // Manually put the firmware in the mailbox because
    // HwModel::upload_firmware returns only when the transaction is complete.
    // This is too late for this test.
    let buf: &[u8] = &image_bundle.to_bytes().unwrap();
    assert!(!hw.soc_mbox().lock().read().lock());
    hw.soc_mbox()
        .cmd()
        .write(|_| CommandId::FIRMWARE_LOAD.into());
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

    hw.step_until_boot_status(FwProcessorDownloadImageComplete.into(), false);
    hw.step_until_boot_status(FwProcessorManifestLoadComplete.into(), false);
    hw.step_until_boot_status(FwProcessorImageVerificationComplete.into(), false);
    hw.step_until_boot_status(FwProcessorPopulateDataVaultComplete.into(), false);
    hw.step_until_boot_status(FwProcessorExtendPcrComplete.into(), false);
    hw.step_until_boot_status(FwProcessorLoadImageComplete.into(), false);
    hw.step_until_boot_status(FwProcessorFirmwareDownloadTxComplete.into(), false);
    hw.step_until_boot_status(FwProcessorComplete.into(), false);
    hw.step_until_boot_status(FmcAliasDeriveCdiComplete.into(), false);
    hw.step_until_boot_status(FmcAliasKeyPairDerivationComplete.into(), false);
    hw.step_until_boot_status(FmcAliasSubjIdSnGenerationComplete.into(), false);
    hw.step_until_boot_status(FmcAliasSubjKeyIdGenerationComplete.into(), false);
    hw.step_until_boot_status(FmcAliasCertSigGenerationComplete.into(), false);
    hw.step_until_boot_status(FmcAliasDerivationComplete.into(), false);
    hw.step_until_boot_status(ColdResetComplete.into(), false);
}

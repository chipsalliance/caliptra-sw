// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_common::RomBootStatus;
use caliptra_common::RomBootStatus::*;
use caliptra_hw_model::DefaultHwModel;
use caliptra_hw_model::Fuses;
use caliptra_hw_model::HwModel;

pub mod helpers;

#[track_caller]
fn step_until_boot_status(hw: &mut DefaultHwModel, expected_status: RomBootStatus) {
    // Since the boot takes less than 20M cycles, we know something is wrong if
    // we're stuck at the same state for that duration.
    const MAX_WAIT_CYCLES: u32 = 20_000_000;

    let mut cycle_count = 0u32;
    let expected_status_u32: u32 = expected_status.into();
    let initial_boot_status_u32 = hw.soc_ifc().cptra_boot_status().read();
    loop {
        let actual_status_u32 = hw.soc_ifc().cptra_boot_status().read();
        if expected_status_u32 == actual_status_u32 {
            break;
        }
        if actual_status_u32 != initial_boot_status_u32 {
            panic!(
                "Expected the next boot_status to be {expected_status:?} \
                    ({expected_status_u32}), but status changed from \
                    {initial_boot_status_u32} to {actual_status_u32})"
            );
        }
        hw.step();
        cycle_count += 1;
        if cycle_count >= MAX_WAIT_CYCLES {
            panic!(
                "Expected boot_status to be {expected_status:?} \
                    ({expected_status_u32}), but was stuck at ({actual_status_u32})"
            );
        }
    }
}

#[test]
fn test_status_reporting() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    step_until_boot_status(&mut hw, IDevIdDecryptUdsComplete);
    step_until_boot_status(&mut hw, IDevIdDecryptFeComplete);
    step_until_boot_status(&mut hw, IDevIdClearDoeSecretsComplete);
    step_until_boot_status(&mut hw, IDevIdCdiDerivationComplete);
    step_until_boot_status(&mut hw, IDevIdKeyPairDerivationComplete);
    step_until_boot_status(&mut hw, IDevIdSubjIdSnGenerationComplete);
    step_until_boot_status(&mut hw, IDevIdSubjKeyIdGenerationComplete);
    // step_until_boot_status(IdevIdMakeCsrComplete);
    // step_until_boot_status(IdevIdSendCsrComplete);
    step_until_boot_status(&mut hw, IDevIdDerivationComplete);
    step_until_boot_status(&mut hw, LDevIdCdiDerivationComplete);
    step_until_boot_status(&mut hw, LDevIdKeyPairDerivationComplete);
    step_until_boot_status(&mut hw, LDevIdSubjIdSnGenerationComplete);
    step_until_boot_status(&mut hw, LDevIdSubjKeyIdGenerationComplete);
    step_until_boot_status(&mut hw, LDevIdCertSigGenerationComplete);
    step_until_boot_status(&mut hw, LDevIdDerivationComplete);

    // Wait for uploading firmware.
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    assert!(hw
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .is_ok());

    // [TODO] Don't use upload_firmware (whic returns only when the txn is complete); manually upload the firmware to test these boot statuses.
    // step_until_boot_status(FwProcessorDownloadImageComplete);
    // step_until_boot_status(FwProcessorManifestLoadComplete);
    // step_until_boot_status(FwProcessorImageVerificationComplete);
    // step_until_boot_status(FwProcessorPopulateDataVaultComplete);
    // step_until_boot_status(FwProcessorExtendPcrComplete);
    // step_until_boot_status(FwProcessorLoadImageComplete);
    step_until_boot_status(&mut hw, FwProcessorComplete);
    step_until_boot_status(&mut hw, FmcAliasDeriveCdiComplete);
    step_until_boot_status(&mut hw, FmcAliasKeyPairDerivationComplete);
    step_until_boot_status(&mut hw, FmcAliasSubjIdSnGenerationComplete);
    step_until_boot_status(&mut hw, FmcAliasSubjKeyIdGenerationComplete);
    step_until_boot_status(&mut hw, FmcAliasCertSigGenerationComplete);
    step_until_boot_status(&mut hw, FmcAliasDerivationComplete);
}

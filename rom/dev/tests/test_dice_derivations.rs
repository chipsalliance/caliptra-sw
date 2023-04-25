// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_common::RomBootStatus::*;
use caliptra_hw_model::Fuses;
use caliptra_hw_model::HwModel;

pub mod helpers;

#[test]
fn test_status_reporting() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    hw.step_until(|m| m.soc_ifc().cptra_boot_status().read() == IDevIdDecryptUdsComplete.into());
    hw.step_until(|m| m.soc_ifc().cptra_boot_status().read() == IDevIdDecryptFeComplete.into());
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == IDevIdClearDoeSecretsComplete.into()
    });
    hw.step_until(|m| m.soc_ifc().cptra_boot_status().read() == IDevIdCdiDerivationComplete.into());
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == IDevIdKeyPairDerivationComplete.into()
    });
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == IDevIdSubjIdSnGenerationComplete.into()
    });
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == IDevIdSubjKeyIdGenerationComplete.into()
    });
    while hw.soc_ifc().cptra_boot_status().read() == IDevIdSubjIdSnGenerationComplete.into() {
        hw.step();
    }
    // while hw.soc_ifc().cptra_boot_status().read() != IdevIdMakeCsrComplete as u32 {
    //     hw.step();
    //     println!("IdevIdMakeCsrComplete");
    // }
    // while hw.soc_ifc().cptra_boot_status().read() != IdevIdSendCsrComplete as u32 {
    //     hw.step();
    //     println!("IdevIdSendCsrComplete");
    // }
    hw.step_until(|m| m.soc_ifc().cptra_boot_status().read() == IDevIdDerivationComplete as u32);
    hw.step_until(|m| m.soc_ifc().cptra_boot_status().read() == LDevIdCdiDerivationComplete as u32);
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == LDevIdKeyPairDerivationComplete.into()
    });
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == LDevIdSubjIdSnGenerationComplete.into()
    });
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == LDevIdSubjKeyIdGenerationComplete.into()
    });
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == LDevIdCertSigGenerationComplete.into()
    });
    hw.step_until(|m| m.soc_ifc().cptra_boot_status().read() == LDevIdDerivationComplete.into());

    // Wait for uploading firmware.
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    assert!(hw
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .is_ok());

    // [TODO] Don't use upload_firmware (whic returns only when the txn is complete); manually upload the firmware to test these boot statuses.
    // while hw.soc_ifc().cptra_boot_status().read() != FmcAliasDownloadImageComplete as u32 {
    //     hw.step();
    // }
    // while hw.soc_ifc().cptra_boot_status().read() != FmcAliasManifestLoadComplete as u32 {
    //     hw.step();
    // }
    // while hw.soc_ifc().cptra_boot_status().read() != FmcAliasImageVerificationComplete as u32 {
    //     hw.step();
    // }
    // while hw.soc_ifc().cptra_boot_status().read() != FmcAliasPopulateDataVaultComplete as u32 {
    //     hw.step();
    // }
    // while hw.soc_ifc().cptra_boot_status().read() != FmcAliasExtendPcrComplete as u32 {
    //     hw.step();
    // }
    // while hw.soc_ifc().cptra_boot_status().read() != FmcAliasLoadImageComplete as u32 {
    //     hw.step();
    // }
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == FmcAliasFirmwareDownloadTxComplete.into()
    });
    hw.step_until(|m| m.soc_ifc().cptra_boot_status().read() == FmcAliasDeriveCdiComplete.into());
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == FmcAliasKeyPairDerivationComplete.into()
    });
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == FmcAliasSubjIdSnGenerationComplete.into()
    });
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == FmcAliasSubjKeyIdGenerationComplete.into()
    });
    hw.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == FmcAliasCertSigGenerationComplete.into()
    });
    hw.step_until(|m| m.soc_ifc().cptra_boot_status().read() == FmcAliasDerivationComplete.into());
}

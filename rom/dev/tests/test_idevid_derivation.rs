// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_drivers::{state::MfgFlags, IdevidCertAttr, X509KeyIdAlgo};
//use caliptra_drivers::{state::MfgFlags, IdevidCertAttr, X509KeyIdAlgo};
use caliptra_hw_model::{Fuses, HwModel};

mod helpers;

#[track_caller]
fn assert_output_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "Expected substring in output not found: {needle}"
    );
}

#[test]
fn test_generate_csr() {
    let mut output = vec![];
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Set gen_idev_id_csr to generate CSR.
    let flags = MfgFlags::GENERATE_IDEVID_CSR;
    hw.soc_ifc()
        .cptra_dbg_manuf_service_reg()
        .write(|_| flags.bits());

    #[cfg(feature = "verilator")]
    {
        // [TODO] Download the CSR from the mailbox and set the gen_idev_id_csr bit 0.
    }

    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    let result = hw.copy_output_until_exit_success(&mut output);
    assert!(result.is_ok());

    let output = String::from_utf8_lossy(&output);
    assert_output_contains(&output, "[idev] CSR uploaded");
}

#[test]
fn test_idev_subj_key_id_algo() {
    let mut output = vec![];
    for algo in 0..(X509KeyIdAlgo::Fuse as u32 + 1) {
        let mut fuses = Fuses::default();
        fuses.idevid_cert_attr[IdevidCertAttr::Flags as usize] = algo;

        let (mut hw, image_bundle) =
            helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap();

        let result = hw.copy_output_until_exit_success(&mut output);
        assert!(result.is_ok());
    }
}

// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_drivers::{IdevidCertAttr, MfgFlags, X509KeyIdAlgo};
use caliptra_hw_model::{DefaultHwModel, Fuses, HwModel};
use caliptra_image_types::ImageBundle;
use openssl::{rand::rand_bytes, x509::X509Req};
use std::io::Write;

use crate::helpers;

fn generate_csr(hw: &mut DefaultHwModel, image_bundle: &ImageBundle) -> Csrs {
    let mut output = vec![];

    // Set gen_idev_id_csr to generate CSR.
    let flags = MfgFlags::GENERATE_IDEVID_CSR;
    hw.soc_ifc()
        .cptra_dbg_manuf_service_reg()
        .write(|_| flags.bits());

    // Download the CSR from the mailbox.
    let downloaded = helpers::get_csr(hw).unwrap();

    // Wait for uploading firmware.
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();

    output
        .write_all(hw.output().take(usize::MAX).as_bytes())
        .unwrap();
    let output = String::from_utf8_lossy(&output);
    let csr_str = helpers::get_data("[idev] CSR = ", &output);
    let uploaded = hex::decode(csr_str).unwrap();
    Csrs {
        uploaded,
        downloaded,
    }
}

#[test]
fn test_generate_csr() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let Csrs {
        uploaded,
        downloaded,
    } = generate_csr(&mut hw, &image_bundle);
    assert_eq!(uploaded, downloaded);
}

#[test]
fn test_idev_subj_key_id_algo() {
    for algo in 0..(X509KeyIdAlgo::Fuse as u32 + 1) {
        let mut fuses = Fuses::default();
        fuses.idevid_cert_attr[IdevidCertAttr::Flags as usize] = algo;

        let (mut hw, image_bundle) =
            helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap();

        hw.step_until_output_contains("Caliptra RT listening for mailbox commands...")
            .unwrap();
    }
}

fn fuses_with_random_uds() -> Fuses {
    const UDS_LEN: usize = core::mem::size_of::<u32>() * 12;
    let mut uds_bytes = [0; UDS_LEN];
    rand_bytes(&mut uds_bytes).unwrap();
    let mut uds_seed = [0u32; 12];

    for (word, bytes) in uds_seed.iter_mut().zip(uds_bytes.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().unwrap());
    }
    Fuses {
        uds_seed,
        ..Default::default()
    }
}

#[test]
fn test_generate_csr_stress() {
    let num_tests = if cfg!(feature = "slow_tests") {
        1000
    } else {
        1
    };

    for _ in 0..num_tests {
        let fuses = fuses_with_random_uds();
        let (mut hw, image_bundle) =
            helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

        let Csrs {
            uploaded,
            downloaded: _,
        } = generate_csr(&mut hw, &image_bundle);

        // Ensure CSR is valid X.509
        let req = X509Req::from_der(&uploaded).unwrap_or_else(|_| {
            panic!(
                "Failed to create a valid X509 cert with UDS seed {:?}",
                fuses.uds_seed
            )
        });
        let pub_key = req.public_key().unwrap();
        assert!(
            req.verify(&pub_key).unwrap(),
            "Invalid public key. Unable to verify CSR with UDS seed {:?}",
            fuses.uds_seed
        );
    }
}

struct Csrs {
    uploaded: Vec<u8>,
    downloaded: Vec<u8>,
}

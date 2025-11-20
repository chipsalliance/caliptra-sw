// Licensed under the Apache-2.0 license

#![allow(dead_code)]

use caliptra_api::mailbox::{
    AlgorithmType, GetFmcAliasEcc384CertReq, GetFmcAliasMlDsa87CertReq, GetLdevEcc384CertReq,
    GetLdevMldsa87CertReq,
};
use caliptra_api_types::Fuses;
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_FAKE_WITH_UART, ROM_FAKE_WITH_UART},
    ImageOptions,
};
use caliptra_hw_model::{BootParams, DeviceLifecycle, HwModel, InitParams, SecurityState};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_test::{
    derive::{DoeInput, DoeOutput, LDevId},
    image_pk_desc_hash,
    x509::{DiceFwid, DiceTcbInfo},
};
use std::io::Write;

const RT_READY_FOR_COMMANDS: u32 = 0x600;

pub const PQC_KEY_TYPE: [FwVerificationPqcKeyType; 2] = [
    FwVerificationPqcKeyType::LMS,
    FwVerificationPqcKeyType::MLDSA,
];

const ALGORITHM_TYPES: [AlgorithmType; 2] = [AlgorithmType::Ecc384, AlgorithmType::Mldsa87];

// Need hardcoded HASH for the canned FMC alias cert
const FMC_CANNED_DEVICE_INFO_DIGEST: [u8; 48] = [
    0x89, 0x17, 0x4d, 0x32, 0x32, 0x70, 0xf9, 0xd4, 0x56, 0xb0, 0x86, 0x23, 0x35, 0x94, 0x94, 0x37,
    0x95, 0x9b, 0xe8, 0xa1, 0x34, 0x45, 0x8d, 0xf8, 0x98, 0x21, 0xcb, 0x50, 0xe2, 0xac, 0x11, 0x84,
    0x3d, 0xaa, 0x5b, 0x5a, 0x5a, 0x6b, 0xac, 0xf7, 0x4e, 0xf8, 0xbd, 0xff, 0xd4, 0x22, 0xe2, 0xb,
];

const FMC_CANNED_FMC_INFO_DIGEST: [u8; 48] = [
    0x83, 0xff, 0xe1, 0x84, 0x76, 0x3, 0x28, 0xcf, 0x12, 0x63, 0x2, 0x6a, 0xac, 0xbc, 0x9d, 0x81,
    0xe5, 0xd1, 0x43, 0xd4, 0xfd, 0xc6, 0x25, 0x3a, 0xfc, 0xee, 0x32, 0x10, 0xf7, 0xc2, 0x5b, 0xfc,
    0xad, 0x4c, 0xae, 0x40, 0x5b, 0x8b, 0x28, 0x11, 0x40, 0x3b, 0xb3, 0xf1, 0xe3, 0xe8, 0x5c, 0x19,
];

#[track_caller]
fn assert_output_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "Expected substring in output not found: {needle}"
    );
}

fn get_idevid_pubkey_ecc() -> openssl::pkey::PKey<openssl::pkey::Public> {
    let csr = openssl::x509::X509Req::from_der(include_bytes!("smoke_testdata/idevid_csr_ecc.der"))
        .unwrap();
    csr.public_key().unwrap()
}

fn get_idevid_pubkey_mldsa() -> openssl::pkey::PKey<openssl::pkey::Public> {
    let csr =
        openssl::x509::X509Req::from_der(include_bytes!("smoke_testdata/idevid_csr_mldsa.der"))
            .unwrap();
    csr.public_key().unwrap()
}

#[test]
fn fake_boot_test() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        for algorithm_type in ALGORITHM_TYPES.iter() {
            let idevid_pubkey = match algorithm_type {
                AlgorithmType::Ecc384 => get_idevid_pubkey_ecc(),
                AlgorithmType::Mldsa87 => get_idevid_pubkey_mldsa(),
            };

            let rom = caliptra_builder::build_firmware_rom(&ROM_FAKE_WITH_UART).unwrap();
            let image = caliptra_builder::build_and_sign_image(
                &FMC_FAKE_WITH_UART,
                &APP_WITH_UART,
                ImageOptions {
                    fw_svn: 9,
                    pqc_key_type: *pqc_key_type,
                    ..Default::default()
                },
            )
            .unwrap();

            let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

            let canned_cert_security_state = *SecurityState::default()
                .set_debug_locked(true)
                .set_device_lifecycle(DeviceLifecycle::Production);

            let mut hw = caliptra_hw_model::new(
                InitParams {
                    fuses: Fuses {
                        vendor_pk_hash: vendor_pk_desc_hash,
                        owner_pk_hash,
                        fw_svn: [0x7F, 0, 0, 0], // Equals 7
                        fuse_pqc_key_type: *pqc_key_type as u32,
                        ..Default::default()
                    },
                    rom: &rom,
                    security_state: canned_cert_security_state,
                    ..Default::default()
                },
                BootParams {
                    fw_image: Some(&image.to_bytes().unwrap()),
                    initial_dbg_manuf_service_reg: (1 << 30),
                    ..Default::default()
                },
            )
            .unwrap();
            let mut output = vec![];

            hw.step_until_output_contains("[rt] RT listening for mailbox commands...\n")
                .unwrap();
            output
                .write_all(hw.output().take(usize::MAX).as_bytes())
                .unwrap();

            let output = String::from_utf8_lossy(&output);
            assert_output_contains(&output, "Running Caliptra ROM");
            assert_output_contains(&output, "[fake-rom-cold-reset]");
            assert_output_contains(&output, "Running Caliptra FMC");
            assert_output_contains(&output, "Caliptra RT");

            let ldev_cert_resp = match algorithm_type {
                AlgorithmType::Ecc384 => hw
                    .mailbox_execute_req(GetLdevEcc384CertReq::default())
                    .unwrap(),
                AlgorithmType::Mldsa87 => hw
                    .mailbox_execute_req(GetLdevMldsa87CertReq::default())
                    .unwrap(),
            };

            // Extract the certificate from the response
            let ldev_cert_der = &ldev_cert_resp.data().unwrap();
            let ldev_cert = openssl::x509::X509::from_der(ldev_cert_der).unwrap();
            let ldev_cert_txt = String::from_utf8(ldev_cert.to_text().unwrap()).unwrap();

            match algorithm_type {
                AlgorithmType::Ecc384 => {
                    // To update the ldev cert testdata:
                    // std::fs::write("tests/caliptra_integration_tests/smoke_testdata/ldevid_cert_ecc.txt", &ldev_cert_txt).unwrap();
                    // std::fs::write("tests/caliptra_integration_tests/smoke_testdata/ldevid_cert_ecc.der", ldev_cert_der).unwrap();

                    assert_eq!(
                        ldev_cert_txt.as_str(),
                        include_str!("smoke_testdata/ldevid_cert_ecc.txt")
                    );
                    assert_eq!(
                        ldev_cert_der,
                        include_bytes!("smoke_testdata/ldevid_cert_ecc.der")
                    );
                }
                AlgorithmType::Mldsa87 => {
                    // To update the ldev cert testdata:
                    // std::fs::write("tests/caliptra_integration_tests/smoke_testdata/ldevid_cert_mldsa.txt", &ldev_cert_txt).unwrap();
                    // std::fs::write("tests/caliptra_integration_tests/smoke_testdata/ldevid_cert_mldsa.der", ldev_cert_der).unwrap();

                    assert_eq!(
                        ldev_cert_txt.as_str(),
                        include_str!("smoke_testdata/ldevid_cert_mldsa.txt")
                    );
                    assert_eq!(
                        ldev_cert_der,
                        include_bytes!("smoke_testdata/ldevid_cert_mldsa.der")
                    );
                }
            }

            assert!(
                ldev_cert.verify(&idevid_pubkey).unwrap(),
                "ldev cert failed to validate with idev pubkey"
            );

            let ldev_pubkey = ldev_cert.public_key().unwrap();

            let expected_ldevid_key = LDevId::derive(&DoeOutput::generate(&DoeInput::default()));

            // Check that the LDevID key has all the field entropy input mixed into it
            // If a firmware change causes this assertion to fail, it is likely that the
            // logic in the ROM that derives LDevID has changed. Ensure this is
            // intentional, and then make the same change to
            // caliptra_test::LDevId::derive().
            match algorithm_type {
                AlgorithmType::Ecc384 => {
                    assert!(expected_ldevid_key
                        .derive_ecc_public_key()
                        .public_eq(&ldev_pubkey));
                }
                AlgorithmType::Mldsa87 => {
                    assert!(expected_ldevid_key
                        .derive_mldsa_public_key()
                        .public_eq(&ldev_pubkey));
                }
            }

            println!("ldev-cert: {}", ldev_cert_txt);

            let fmc_alias_cert_resp = match algorithm_type {
                AlgorithmType::Ecc384 => hw
                    .mailbox_execute_req(GetFmcAliasEcc384CertReq::default())
                    .unwrap(),
                AlgorithmType::Mldsa87 => hw
                    .mailbox_execute_req(GetFmcAliasMlDsa87CertReq::default())
                    .unwrap(),
            };

            // Extract the certificate from the response
            let fmc_alias_cert_der = fmc_alias_cert_resp.data().unwrap();
            let mut fmc_alias_cert = openssl::x509::X509::from_der(fmc_alias_cert_der).unwrap();

            if *algorithm_type == AlgorithmType::Mldsa87 {
                fmc_alias_cert = openssl::x509::X509::from_der(include_bytes!(
                    "smoke_testdata/fmc_alias_cert_mldsa.der"
                ))
                .unwrap();
                assert_eq!(
                    fmc_alias_cert_der,
                    include_bytes!("smoke_testdata/fmc_alias_cert_mldsa.der")
                )
            }

            println!(
                "fmc-alias cert: {}",
                String::from_utf8_lossy(&fmc_alias_cert.to_text().unwrap())
            );

            let dice_tcb_info = DiceTcbInfo::find_multiple_in_cert(fmc_alias_cert_der).unwrap();
            assert_eq!(
                dice_tcb_info,
                [
                    DiceTcbInfo {
                        vendor: None,
                        model: None,
                        // This is from the SVN in the fuses (7 bits set)
                        svn: Some(0x107),
                        fwids: vec![DiceFwid {
                            hash_alg: asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2),
                            digest: FMC_CANNED_DEVICE_INFO_DIGEST.to_vec(),
                        },],

                        flags: Some(0x00000001),
                        ty: Some(b"DEVICE_INFO".to_vec()),
                        ..Default::default()
                    },
                    DiceTcbInfo {
                        vendor: None,
                        model: None,
                        // This is from the SVN in the image (9)
                        svn: Some(0x109),
                        fwids: vec![DiceFwid {
                            // FMC
                            hash_alg: asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2),
                            digest: FMC_CANNED_FMC_INFO_DIGEST.to_vec(),
                        },],
                        ty: Some(b"FMC_INFO".to_vec()),
                        ..Default::default()
                    },
                ]
            );

            // TODO: re-enable when it's easier to update the canned responses
            // Need to use production for the canned certs to match the LDEV cert in testdata
            /*
            let canned_cert_security_state = *SecurityState::default()
                .set_debug_locked(true)
                .set_device_lifecycle(DeviceLifecycle::Production);

            let expected_fmc_alias_key = FmcAliasKey::derive(
                &Pcr0::derive(&Pcr0Input {
                    security_state: canned_cert_security_state,
                    fuse_anti_rollback_disable: false,
                    vendor_pub_key_hash: vendor_pk_desc_hash,
                    owner_pub_key_hash: owner_pk_hash,
                    owner_pub_key_hash_from_fuses: true,
                    ecc_vendor_pub_key_index: image.manifest.preamble.vendor_ecc_pub_key_idx,
                    fmc_digest: image.manifest.fmc.digest,
                    cold_boot_fw_svn: image.manifest.header.svn,
                    // This is from the SVN in the fuses (7 bits set)
                    fw_fuse_svn: 7,
                    pqc_vendor_pub_key_index: image.manifest.header.vendor_pqc_pub_key_idx,
                    pqc_key_type: 1 as u32, // MLDSA
                }),
                &expected_ldevid_key,
            );

            // Check that the fmc-alias key has all the pcr0 input above mixed into it
            // If a firmware change causes this assertion to fail, it is likely that the
            // logic in the ROM that update PCR0 has changed. Ensure this is
            // intentional, and then make the same change to
            // caliptra_test::Pcr0Input::derive_pcr0().
            assert!(expected_fmc_alias_key
                .derive_public_key()
                .public_eq(&fmc_alias_cert.public_key().unwrap()));
            */
            assert!(
                fmc_alias_cert.verify(&ldev_pubkey).unwrap(),
                "fmc_alias cert failed to validate with ldev pubkey"
            );

            // TODO: Validate the rest of the fmc_alias certificate fields
        }
    }
}

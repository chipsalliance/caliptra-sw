// Licensed under the Apache-2.0 license

use caliptra_builder::{firmware, ImageOptions};
use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{
    CommandId, FipsVersionResp, GetLdevCertResp, MailboxReqHeader, MailboxRespHeader,
    TestGetFmcAliasCertResp,
};
use caliptra_hw_model::{BootParams, HwModel, InitParams, ModelError, SecurityState};
use caliptra_hw_model_types::{DeviceLifecycle, Fuses};
use caliptra_test::{
    derive::{DoeInput, DoeOutput, FmcAliasKey, IDevId, LDevId, Pcr0, Pcr0Input},
    swap_word_bytes, swap_word_bytes_inplace,
    x509::{DiceFwid, DiceTcbInfo},
};
use openssl::sha::{sha384, Sha384};
use std::{io::Write, mem};
use zerocopy::{AsBytes, FromBytes};

#[track_caller]
fn assert_output_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "Expected substring in output not found: {needle}"
    );
}

#[test]
fn retrieve_csr_test() {
    const GENERATE_IDEVID_CSR: u32 = 1;
    let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: *SecurityState::default().set_debug_locked(true),
            ..Default::default()
        },
        initial_dbg_manuf_service_reg: GENERATE_IDEVID_CSR,
        ..Default::default()
    })
    .unwrap();

    let mut txn = hw.wait_for_mailbox_receive().unwrap();
    let csr_der = mem::take(&mut txn.req.data);
    txn.respond_success();

    let csr = openssl::x509::X509Req::from_der(&csr_der).unwrap();
    let csr_txt = String::from_utf8(csr.to_text().unwrap()).unwrap();

    // To update the CSR testdata:
    // std::fs::write("tests/smoke_testdata/idevid_csr.txt", &csr_txt).unwrap();
    // std::fs::write("tests/smoke_testdata/idevid_csr.der", &csr_der).unwrap();

    println!("csr: {}", csr_txt);

    assert_eq!(
        csr_txt.as_str(),
        include_str!("smoke_testdata/idevid_csr.txt")
    );
    assert_eq!(csr_der, include_bytes!("smoke_testdata/idevid_csr.der"));

    assert!(
        csr.verify(&csr.public_key().unwrap()).unwrap(),
        "CSR's self signature failed to validate"
    );
}

fn get_idevid_pubkey() -> openssl::pkey::PKey<openssl::pkey::Public> {
    let csr =
        openssl::x509::X509Req::from_der(include_bytes!("smoke_testdata/idevid_csr.der")).unwrap();
    csr.public_key().unwrap()
}

fn get_ldevid_pubkey() -> openssl::pkey::PKey<openssl::pkey::Public> {
    let cert =
        openssl::x509::X509::from_der(include_bytes!("smoke_testdata/ldevid_cert.der")).unwrap();
    cert.public_key().unwrap()
}

#[test]
fn test_golden_idevid_pubkey_matches_generated() {
    let idevid_pubkey = get_idevid_pubkey();

    let doe_out = DoeOutput::generate(&DoeInput::default());
    let generated_idevid = IDevId::derive(&doe_out);
    assert_eq!(
        generated_idevid.cdi,
        [
            0x4443b819, 0x8ca0984a, 0x2d566eed, 0x40f94074, 0x0c7cc63b, 0x85f939ac, 0xa2df92bf,
            0xb00f2f3e, 0x1e70ec47, 0x6736c596, 0x58a8a450, 0xeeac2f20,
        ]
    );
    assert!(generated_idevid
        .derive_public_key()
        .public_eq(&idevid_pubkey));
}

#[test]
fn test_golden_ldevid_pubkey_matches_generated() {
    let ldevid_pubkey = get_ldevid_pubkey();

    let doe_out = DoeOutput::generate(&DoeInput::default());
    let generated_ldevid = LDevId::derive(&doe_out);
    assert_eq!(
        generated_ldevid.cdi,
        [
            0xf226cb0f, 0x1b527a8d, 0x9abeb5eb, 0xf407069a, 0xeda6909b, 0xad434d1d, 0x5f3586ff,
            0xa4729b8c, 0xd9e34ef9, 0xcb4317aa, 0x596674e5, 0x7f3c0f5b,
        ]
    );
    assert!(generated_ldevid
        .derive_public_key()
        .public_eq(&ldevid_pubkey));
}

fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

#[test]
fn smoke_test() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);
    let idevid_pubkey = get_idevid_pubkey();

    let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::APP_WITH_UART,
        ImageOptions {
            fmc_min_svn: 5,
            fmc_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();
    let vendor_pk_hash = sha384(image.manifest.preamble.vendor_pub_keys.as_bytes());
    let owner_pk_hash = sha384(image.manifest.preamble.owner_pub_keys.as_bytes());
    let vendor_pk_hash_words = bytes_to_be_words_48(&vendor_pk_hash);
    let owner_pk_hash_words = bytes_to_be_words_48(&owner_pk_hash);

    let fuses = Fuses {
        key_manifest_pk_hash: vendor_pk_hash_words,
        owner_pk_hash: owner_pk_hash_words,
        fmc_key_manifest_svn: 0b1111111,
        lms_verify: true,
        ..Default::default()
    };
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        fuses,
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();
    let mut output = vec![];

    hw.step_until_output_contains("Caliptra RT listening for mailbox commands...\n")
        .unwrap();
    output
        .write_all(hw.output().take(usize::MAX).as_bytes())
        .unwrap();

    let output = String::from_utf8_lossy(&output);
    assert_output_contains(&output, "Running Caliptra ROM");
    assert_output_contains(&output, "[cold-reset]");
    // Confirm KAT is running.
    assert_output_contains(&output, "[kat] ++");
    assert_output_contains(&output, "[kat] sha1");
    assert_output_contains(&output, "[kat] SHA2-256");
    assert_output_contains(&output, "[kat] SHA2-384");
    assert_output_contains(&output, "[kat] SHA2-384-ACC");
    assert_output_contains(&output, "[kat] HMAC-384");
    assert_output_contains(&output, "[kat] LMS");
    assert_output_contains(&output, "[kat] --");
    assert_output_contains(&output, "Running Caliptra FMC");
    assert_output_contains(
        &output,
        r#"
 / ___|__ _| (_)_ __ | |_ _ __ __ _  |  _ \_   _|
| |   / _` | | | '_ \| __| '__/ _` | | |_) || |
| |__| (_| | | | |_) | |_| | | (_| | |  _ < | |
 \____\__,_|_|_| .__/ \__|_|  \__,_| |_| \_\|_|"#,
    );

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::TEST_ONLY_GET_LDEV_CERT),
            &[],
        ),
    };

    // Execute the command
    let ldev_cert_resp = hw
        .mailbox_execute(
            u32::from(CommandId::TEST_ONLY_GET_LDEV_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();

    let ldev_cert_resp = GetLdevCertResp::read_from(ldev_cert_resp.as_bytes()).unwrap();

    // Verify checksum and FIPS approval
    assert!(caliptra_common::checksum::verify_checksum(
        ldev_cert_resp.hdr.chksum,
        0x0,
        &ldev_cert_resp.as_bytes()[core::mem::size_of_val(&ldev_cert_resp.hdr.chksum)..],
    ));
    assert_eq!(
        ldev_cert_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Extract the certificate from the response
    let ldev_cert_der = &ldev_cert_resp.data[..(ldev_cert_resp.data_size as usize)];
    let ldev_cert = openssl::x509::X509::from_der(ldev_cert_der).unwrap();
    let ldev_cert_txt = String::from_utf8(ldev_cert.to_text().unwrap()).unwrap();

    // To update the ldev cert testdata:
    // std::fs::write("tests/smoke_testdata/ldevid_cert.txt", &ldev_cert_txt).unwrap();
    // std::fs::write("tests/smoke_testdata/ldevid_cert.der", ldev_cert_der).unwrap();

    assert_eq!(
        ldev_cert_txt.as_str(),
        include_str!("smoke_testdata/ldevid_cert.txt")
    );
    assert_eq!(
        ldev_cert_der,
        include_bytes!("smoke_testdata/ldevid_cert.der")
    );

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
    assert!(expected_ldevid_key
        .derive_public_key()
        .public_eq(&ldev_pubkey));

    println!("ldev-cert: {}", ldev_cert_txt);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT),
            &[],
        ),
    };

    // Execute command
    let fmc_alias_cert_resp = hw
        .mailbox_execute(
            u32::from(CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();

    let fmc_alias_cert_resp =
        TestGetFmcAliasCertResp::read_from(fmc_alias_cert_resp.as_bytes()).unwrap();

    // Verify checksum and FIPS approval
    assert!(caliptra_common::checksum::verify_checksum(
        fmc_alias_cert_resp.hdr.chksum,
        0x0,
        &fmc_alias_cert_resp.as_bytes()[core::mem::size_of_val(&fmc_alias_cert_resp.hdr.chksum)..],
    ));
    assert_eq!(
        fmc_alias_cert_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Extract the certificate from the response
    let fmc_alias_cert_der = &fmc_alias_cert_resp.data[..(fmc_alias_cert_resp.data_size as usize)];
    let fmc_alias_cert = openssl::x509::X509::from_der(fmc_alias_cert_der).unwrap();

    println!(
        "fmc-alias cert: {}",
        String::from_utf8_lossy(&fmc_alias_cert.to_text().unwrap())
    );

    let mut hasher = Sha384::new();
    hasher.update(&[security_state.device_lifecycle() as u8]);
    hasher.update(&[security_state.debug_locked() as u8]);
    hasher.update(&[fuses.anti_rollback_disable as u8]);
    hasher.update(/*ecc_vendor_pk_index=*/ &[0u8]); // No keys are revoked
    hasher.update(&[image.manifest.header.vendor_lms_pub_key_idx as u8]);
    hasher.update(&[fuses.lms_verify as u8]);
    hasher.update(&[true as u8]);
    hasher.update(&vendor_pk_hash);
    hasher.update(&owner_pk_hash);
    let device_info_hash = hasher.finish();

    let dice_tcb_info = DiceTcbInfo::find_multiple_in_cert(fmc_alias_cert_der).unwrap();
    assert_eq!(
        dice_tcb_info,
        [
            DiceTcbInfo {
                vendor: Some("Caliptra".into()),
                model: Some("Device".into()),
                // This is from the SVN in the fuses (7 bits set)
                svn: Some(0x107),
                fwids: vec![DiceFwid {
                    hash_alg: asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: device_info_hash.to_vec(),
                },],

                flags: Some(0x80000000),
                ty: Some(b"DEVICE_INFO".to_vec()),
                ..Default::default()
            },
            DiceTcbInfo {
                vendor: Some("Caliptra".into()),
                model: Some("FMC".into()),
                // This is from the SVN in the image (9)
                svn: Some(0x109),
                fwids: vec![DiceFwid {
                    // FMC
                    hash_alg: asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: swap_word_bytes(&image.manifest.fmc.digest)
                        .as_bytes()
                        .to_vec(),
                },],
                ty: Some(b"FMC_INFO".to_vec()),
                ..Default::default()
            },
        ]
    );

    let expected_fmc_alias_key = FmcAliasKey::derive(
        &Pcr0::derive(&Pcr0Input {
            security_state,
            fuse_anti_rollback_disable: false,
            vendor_pub_key_hash: vendor_pk_hash_words,
            owner_pub_key_hash: owner_pk_hash_words,
            owner_pub_key_hash_from_fuses: true,
            ecc_vendor_pub_key_index: image.manifest.preamble.vendor_ecc_pub_key_idx,
            fmc_digest: image.manifest.fmc.digest,
            fmc_svn: image.manifest.fmc.svn,
            // This is from the SVN in the fuses (7 bits set)
            fmc_fuse_svn: 7,
            lms_vendor_pub_key_index: image.manifest.header.vendor_lms_pub_key_idx,
            rom_verify_config: 1, // RomVerifyConfig::EcdsaAndLms
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

    assert!(
        fmc_alias_cert.verify(&ldev_pubkey).unwrap(),
        "fmc_alias cert failed to validate with ldev pubkey"
    );

    // TODO: Validate the rest of the fmc_alias certificate fields
}

fn test_fips<T: HwModel>(hw: &mut T, fmc_version: u32, app_version: u32) {
    // VERSION
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };

    let fips_version_resp = hw
        .mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes())
        .unwrap()
        .unwrap();

    // Check command size
    let fips_version_bytes: &[u8] = fips_version_resp.as_bytes();

    // Check values against expected.
    let fips_version = FipsVersionResp::read_from(fips_version_bytes).unwrap();
    assert!(caliptra_common::checksum::verify_checksum(
        fips_version.hdr.chksum,
        0x0,
        &fips_version.as_bytes()[core::mem::size_of_val(&fips_version.hdr.chksum)..],
    ));
    assert_eq!(
        fips_version.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(fips_version.mode, FipsVersionCmd::MODE);
    assert_eq!(fips_version.fips_rev, [0x01, fmc_version, app_version]);
    let name = &fips_version.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());

    // SELF_TEST_START
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_START),
            &[],
        ),
    };

    let resp = hw
        .mailbox_execute(u32::from(CommandId::SELF_TEST_START), payload.as_bytes())
        .unwrap()
        .unwrap();

    let resp = MailboxRespHeader::read_from(resp.as_slice()).unwrap();
    // Verify checksum and FIPS status
    assert!(caliptra_common::checksum::verify_checksum(
        resp.chksum,
        0x0,
        &resp.as_bytes()[core::mem::size_of_val(&resp.chksum)..],
    ));
    assert_eq!(resp.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);

    // Confirm we can't re-start the FIPS self test while it is in progress.
    let _resp = hw
        .mailbox_execute(u32::from(CommandId::SELF_TEST_START), payload.as_bytes())
        .unwrap_err();

    // SELF_TEST_GET_RESULTS
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            &[],
        ),
    };

    loop {
        // Get self test results
        match hw.mailbox_execute(
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            payload.as_bytes(),
        ) {
            Ok(Some(resp)) => {
                let resp = MailboxRespHeader::read_from(resp.as_slice()).unwrap();
                // Verify checksum and FIPS status
                assert!(caliptra_common::checksum::verify_checksum(
                    resp.chksum,
                    0x0,
                    &resp.as_bytes()[core::mem::size_of_val(&resp.chksum)..],
                ));
                if resp.fips_status == MailboxRespHeader::FIPS_STATUS_APPROVED {
                    break;
                }
            }
            _ => {
                // Give FW time to run
                let mut cycle_count = 10000;
                hw.step_until(|_| -> bool {
                    cycle_count -= 1;
                    cycle_count == 0
                });
            }
        }
    }

    // SHUTDOWN
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };

    let resp = hw.mailbox_execute(u32::from(CommandId::SHUTDOWN), payload.as_bytes());
    assert!(resp.is_ok());

    assert_eq!(
        hw.mailbox_execute(
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            payload.as_bytes()
        ),
        Err(ModelError::MailboxCmdFailed(0x000E0008))
    );

    // Check we are rejecting additional commands.
    assert_eq!(
        hw.mailbox_execute(u32::from(CommandId::SHUTDOWN), payload.as_bytes()),
        Err(ModelError::MailboxCmdFailed(0x000E0008))
    );
    assert_eq!(
        hw.mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes()),
        Err(ModelError::MailboxCmdFailed(0x000E0008))
    );
}

#[test]
fn fips_cmd_test_rom() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        fuses: Fuses {
            fmc_key_manifest_svn: 0b1111111,
            ..Default::default()
        },
        fw_image: None,
        ..Default::default()
    })
    .unwrap();

    // Wait for rom to be ready for firmware
    while !hw.ready_for_fw() {
        hw.step();
    }

    test_fips(&mut hw, 0, 0);
}

#[test]
fn fips_cmd_test_rt() {
    const FMC_VERSION: u32 = 0xFEFEFEFE;
    const APP_VERSION: u32 = 0xCECECECE;

    let security_state = *SecurityState::default()
        .set_debug_locked(false)
        .set_device_lifecycle(DeviceLifecycle::Unprovisioned);

    let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::APP_WITH_UART,
        ImageOptions {
            fmc_version: FMC_VERSION,
            fmc_min_svn: 5,
            fmc_svn: 9,
            app_version: APP_VERSION,
            ..Default::default()
        },
    )
    .unwrap();
    let vendor_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.vendor_pub_keys.as_bytes()));
    let owner_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.owner_pub_keys.as_bytes()));

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        fuses: Fuses {
            key_manifest_pk_hash: vendor_pk_hash,
            owner_pk_hash,
            fmc_key_manifest_svn: 0b1111111,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }

    test_fips(&mut hw, FMC_VERSION, APP_VERSION);
}

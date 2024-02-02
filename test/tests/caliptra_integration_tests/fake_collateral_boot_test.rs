// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_FAKE_WITH_UART, ROM_FAKE_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    CommandId, GetFmcAliasCertResp, GetLdevCertResp, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use caliptra_hw_model_types::Fuses;
use caliptra_test::{
    derive::{DoeInput, DoeOutput, LDevId},
    swap_word_bytes, swap_word_bytes_inplace,
    x509::{DiceFwid, DiceTcbInfo},
};
use openssl::sha::sha384;
use std::io::Write;
use zerocopy::AsBytes;

const RT_READY_FOR_COMMANDS: u32 = 0x600;

// Need hardcoded HASH for the canned FMC alias cert
const FMC_CANNED_DIGEST: [u32; 12] = [
    0x06d8f354, 0x3ad268d8, 0xcbb42207, 0x04ec47c9, 0x3301fed8, 0xcbae2740, 0xbf944b0b, 0x84882c0c,
    0xf2db4f76, 0x5b671453, 0xa256de5d, 0xa490d7c8,
];

#[track_caller]
fn assert_output_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "Expected substring in output not found: {needle}"
    );
}

fn get_idevid_pubkey() -> openssl::pkey::PKey<openssl::pkey::Public> {
    let csr =
        openssl::x509::X509Req::from_der(include_bytes!("smoke_testdata/idevid_csr.der")).unwrap();
    csr.public_key().unwrap()
}

fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

#[test]
fn fake_boot_test() {
    let idevid_pubkey = get_idevid_pubkey();

    let rom = caliptra_builder::build_firmware_rom(&ROM_FAKE_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_FAKE_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fmc_svn: 9,
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
    let mut output = vec![];

    hw.step_until_boot_status(RT_READY_FOR_COMMANDS, true);
    output
        .write_all(hw.output().take(usize::MAX).as_bytes())
        .unwrap();

    let output = String::from_utf8_lossy(&output);
    assert_output_contains(&output, "Running Caliptra ROM");
    assert_output_contains(&output, "[fake-rom-cold-reset]");
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
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_LDEV_CERT), &[]),
    };

    // Execute the command
    let resp = hw
        .mailbox_execute(u32::from(CommandId::GET_LDEV_CERT), payload.as_bytes())
        .unwrap()
        .unwrap();

    assert!(resp.len() <= std::mem::size_of::<GetLdevCertResp>());
    let mut ldev_cert_resp = GetLdevCertResp::default();
    ldev_cert_resp.as_bytes_mut()[..resp.len()].copy_from_slice(&resp);

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
            u32::from(CommandId::GET_FMC_ALIAS_CERT),
            &[],
        ),
    };

    // Execute command
    let resp = hw
        .mailbox_execute(u32::from(CommandId::GET_FMC_ALIAS_CERT), payload.as_bytes())
        .unwrap()
        .unwrap();

    assert!(resp.len() <= std::mem::size_of::<GetFmcAliasCertResp>());
    let mut fmc_alias_cert_resp = GetFmcAliasCertResp::default();
    fmc_alias_cert_resp.as_bytes_mut()[..resp.len()].copy_from_slice(&resp);

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

    let dice_tcb_info = DiceTcbInfo::find_multiple_in_cert(fmc_alias_cert_der).unwrap();
    assert_eq!(
        dice_tcb_info,
        [
            DiceTcbInfo {
                vendor: Some("Caliptra".into()),
                model: Some("Device".into()),
                // This is from the SVN in the fuses (7 bits set)
                svn: Some(0x107),

                flags: Some(0x80000000),
                ..Default::default()
            },
            DiceTcbInfo {
                vendor: Some("Caliptra".into()),
                model: Some("FMC".into()),
                // This is from the SVN in the image (9)
                svn: Some(0x109),
                fwids: vec![
                    DiceFwid {
                        // FMC
                        hash_alg: asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2),
                        digest: swap_word_bytes(&FMC_CANNED_DIGEST).as_bytes().to_vec(),
                    },
                    DiceFwid {
                        hash_alg: asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2),
                        // TODO: Compute this...
                        digest: sha384(image.manifest.preamble.owner_pub_keys.as_bytes()).to_vec(),
                    },
                ],
                ..Default::default()
            },
        ]
    );

    // TODO: re-enable when it's easier to update the canned responses
    /*
    // Need to use production for the canned certs to match the LDEV cert in testdata
    let canned_cert_security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let expected_fmc_alias_key = FmcAliasKey::derive(
        &Pcr0::derive(&Pcr0Input {
            security_state: canned_cert_security_state,
            fuse_anti_rollback_disable: false,
            vendor_pub_key_hash: vendor_pk_hash,
            owner_pub_key_hash: owner_pk_hash,
            owner_pub_key_from_fuses: true,
            ecc_vendor_pub_key_index: image.manifest.preamble.vendor_ecc_pub_key_idx,
            fmc_digest: FMC_CANNED_DIGEST,
            fmc_svn: image.manifest.fmc.svn,
            // This is from the SVN in the fuses (7 bits set)
            fmc_fuse_svn: 7,
            lms_vendor_pub_key_index: u32::MAX,
            rom_verify_config: 0, // RomVerifyConfig::EcdsaOnly
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
        .public_eq(&fmc_alias_cert.public_key().unwrap()));*/

    assert!(
        fmc_alias_cert.verify(&ldev_pubkey).unwrap(),
        "fmc_alias cert failed to validate with ldev pubkey"
    );

    // TODO: Validate the rest of the fmc_alias certificate fields
}

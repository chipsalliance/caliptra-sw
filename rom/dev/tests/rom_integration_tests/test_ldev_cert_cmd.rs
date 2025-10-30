// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::GetLdevCertResp;
use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_hw_model::{DefaultHwModel, Fuses, HwModel};
use caliptra_image_types::FwVerificationPqcKeyType;
use openssl::x509::X509;
use zerocopy::IntoBytes;

use crate::helpers;

const RT_READY_FOR_COMMANDS: u32 = 0x600;

fn get_ldev_ecc_cert(model: &mut DefaultHwModel) -> GetLdevCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_LDEV_ECC384_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_LDEV_ECC384_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetLdevCertResp>());
    let mut ldev_resp = GetLdevCertResp::default();
    ldev_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    ldev_resp
}

fn get_ldev_mldsa_cert(model: &mut DefaultHwModel) -> GetLdevCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_LDEV_MLDSA87_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_LDEV_MLDSA87_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetLdevCertResp>());
    let mut ldev_resp = GetLdevCertResp::default();
    ldev_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    ldev_resp
}

#[test]
fn test_ldev_ecc384_cert() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    // Step till we are ready for mailbox processing
    hw.step_until(|m| {
        m.soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing()
    });

    // Get LDev ECC384 cert from ROM
    let ldev_resp = get_ldev_ecc_cert(&mut hw);
    let ldev_cert_rom: X509 =
        X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    // Step till RT is ready for commands
    helpers::test_upload_firmware(
        &mut hw,
        &image_bundle.to_bytes().unwrap(),
        FwVerificationPqcKeyType::MLDSA,
    );
    hw.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    // Get the LDev ECC384 cert from RT
    let ldev_resp = get_ldev_ecc_cert(&mut hw);
    let ldev_cert_rt: X509 =
        X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    // Compare the two certs
    assert_eq!(
        ldev_cert_rom.to_der().unwrap(),
        ldev_cert_rt.to_der().unwrap()
    );
}

#[test]
fn test_ldev_mldsa87_cert() {
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    // Step till we are ready for mailbox processing
    hw.step_until(|m| {
        m.soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing()
    });

    // Get LDev MLDSA87 cert from ROM
    let ldev_resp = get_ldev_mldsa_cert(&mut hw);
    let ldev_cert_rom: X509 =
        X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    // Step till RT is ready for commands
    helpers::test_upload_firmware(
        &mut hw,
        &image_bundle.to_bytes().unwrap(),
        FwVerificationPqcKeyType::MLDSA,
    );
    hw.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    // Get the LDev MLDSA87 cert from RT
    let ldev_resp = get_ldev_mldsa_cert(&mut hw);
    let ldev_cert_rt: X509 =
        X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    // Compare the two certs
    assert_eq!(
        ldev_cert_rom.to_der().unwrap(),
        ldev_cert_rt.to_der().unwrap()
    );
}

// Licensed under the Apache-2.0 license.
pub mod common;

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART};
use caliptra_drivers::Ecc384PubKey;
use caliptra_hw_model::{HwModel, ModelError, ShaAccMode};
use caliptra_runtime::{
    CommandId, EcdsaVerifyReq, FipsVersionCmd, FipsVersionResp, FwInfoResp, MailboxReqHeader,
    MailboxRespHeader,
};
use common::{run_rom_test, run_rt_test};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    x509::X509,
};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

#[test]
fn test_standard() {
    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None);

    model
        .step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();
}

#[test]
fn test_update() {
    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None);

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // Make image to update to
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();

    model
        .step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();
}

#[test]
fn test_boot() {
    let mut model = run_rt_test(Some("boot"));

    model.step_until_exit_success().unwrap();
}

#[test]
fn test_rom_certs() {
    let mut model = run_rt_test(Some("cert"));

    // Get certs over the mailbox
    let ldev_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let ldevid: &[u8] = ldev_resp.as_bytes();

    let fmc_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let fmc: &[u8] = fmc_resp.as_bytes();

    // Ensure certs are valid X.509
    let ldev_cert: X509 = X509::from_der(ldevid).unwrap();
    let fmc_cert: X509 = X509::from_der(fmc).unwrap();

    let idev_resp = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    let idev_pub = Ecc384PubKey::read_from(idev_resp.as_bytes()).unwrap();

    // Check the FMC is signed by LDevID
    assert!(fmc_cert.verify(&ldev_cert.public_key().unwrap()).unwrap());

    // Check the LDevID is signed by IDevID
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let x_bytes: [u8; 48] = idev_pub.x.into();
    let y_bytes: [u8; 48] = idev_pub.y.into();
    let idev_x = &BigNum::from_slice(&x_bytes).unwrap();
    let idev_y = &BigNum::from_slice(&y_bytes).unwrap();

    let idev_ec_key = EcKey::from_public_key_affine_coordinates(&group, idev_x, idev_y).unwrap();
    assert!(ldev_cert
        .verify(&PKey::from_ec_key(idev_ec_key).unwrap())
        .unwrap());
}

#[test]
fn test_fw_info() {
    let mut model = run_rt_test(None);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();

    let info = FwInfoResp::read_from(resp.as_slice()).unwrap();
    // Verify checksum and FIPS status
    assert!(caliptra_common::checksum::verify_checksum(
        info.hdr.chksum,
        0x0,
        &info.as_bytes()[core::mem::size_of_val(&info.hdr.chksum)..],
    ));
    assert_eq!(
        info.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    // Verify FW info
    assert_eq!(info.pl0_pauser, 0xFFFF0000);
}

#[test]
fn test_verify_cmd() {
    let mut model = run_rom_test("mbox");

    model.step_until(|m| {
        m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle()
            && m.soc_ifc().cptra_boot_status().read() == 1
    });

    // Message to hash
    let msg: &[u8] = &[
        0x9d, 0xd7, 0x89, 0xea, 0x25, 0xc0, 0x47, 0x45, 0xd5, 0x7a, 0x38, 0x1f, 0x22, 0xde, 0x01,
        0xfb, 0x0a, 0xbd, 0x3c, 0x72, 0xdb, 0xde, 0xfd, 0x44, 0xe4, 0x32, 0x13, 0xc1, 0x89, 0x58,
        0x3e, 0xef, 0x85, 0xba, 0x66, 0x20, 0x44, 0xda, 0x3d, 0xe2, 0xdd, 0x86, 0x70, 0xe6, 0x32,
        0x51, 0x54, 0x48, 0x01, 0x55, 0xbb, 0xee, 0xbb, 0x70, 0x2c, 0x75, 0x78, 0x1a, 0xc3, 0x2e,
        0x13, 0x94, 0x18, 0x60, 0xcb, 0x57, 0x6f, 0xe3, 0x7a, 0x05, 0xb7, 0x57, 0xda, 0x5b, 0x5b,
        0x41, 0x8f, 0x6d, 0xd7, 0xc3, 0x0b, 0x04, 0x2e, 0x40, 0xf4, 0x39, 0x5a, 0x34, 0x2a, 0xe4,
        0xdc, 0xe0, 0x56, 0x34, 0xc3, 0x36, 0x25, 0xe2, 0xbc, 0x52, 0x43, 0x45, 0x48, 0x1f, 0x7e,
        0x25, 0x3d, 0x95, 0x51, 0x26, 0x68, 0x23, 0x77, 0x1b, 0x25, 0x17, 0x05, 0xb4, 0xa8, 0x51,
        0x66, 0x02, 0x2a, 0x37, 0xac, 0x28, 0xf1, 0xbd,
    ];

    // Stream to SHA ACC
    model
        .compute_sha512_acc_digest(msg, ShaAccMode::Sha384Stream)
        .unwrap();

    // ECDSAVS NIST test vector
    let cmd = EcdsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key_x: [
            0xcb, 0x90, 0x8b, 0x1f, 0xd5, 0x16, 0xa5, 0x7b, 0x8e, 0xe1, 0xe1, 0x43, 0x83, 0x57,
            0x9b, 0x33, 0xcb, 0x15, 0x4f, 0xec, 0xe2, 0x0c, 0x50, 0x35, 0xe2, 0xb3, 0x76, 0x51,
            0x95, 0xd1, 0x95, 0x1d, 0x75, 0xbd, 0x78, 0xfb, 0x23, 0xe0, 0x0f, 0xef, 0x37, 0xd7,
            0xd0, 0x64, 0xfd, 0x9a, 0xf1, 0x44,
        ],
        pub_key_y: [
            0xcd, 0x99, 0xc4, 0x6b, 0x58, 0x57, 0x40, 0x1d, 0xdc, 0xff, 0x2c, 0xf7, 0xcf, 0x82,
            0x21, 0x21, 0xfa, 0xf1, 0xcb, 0xad, 0x9a, 0x01, 0x1b, 0xed, 0x8c, 0x55, 0x1f, 0x6f,
            0x59, 0xb2, 0xc3, 0x60, 0xf7, 0x9b, 0xfb, 0xe3, 0x2a, 0xdb, 0xca, 0xa0, 0x95, 0x83,
            0xbd, 0xfd, 0xf7, 0xc3, 0x74, 0xbb,
        ],
        signature_r: [
            0x33, 0xf6, 0x4f, 0xb6, 0x5c, 0xd6, 0xa8, 0x91, 0x85, 0x23, 0xf2, 0x3a, 0xea, 0x0b,
            0xbc, 0xf5, 0x6b, 0xba, 0x1d, 0xac, 0xa7, 0xaf, 0xf8, 0x17, 0xc8, 0x79, 0x1d, 0xc9,
            0x24, 0x28, 0xd6, 0x05, 0xac, 0x62, 0x9d, 0xe2, 0xe8, 0x47, 0xd4, 0x3c, 0xee, 0x55,
            0xba, 0x9e, 0x4a, 0x0e, 0x83, 0xba,
        ],
        signature_s: [
            0x44, 0x28, 0xbb, 0x47, 0x8a, 0x43, 0xac, 0x73, 0xec, 0xd6, 0xde, 0x51, 0xdd, 0xf7,
            0xc2, 0x8f, 0xf3, 0xc2, 0x44, 0x16, 0x25, 0xa0, 0x81, 0x71, 0x43, 0x37, 0xdd, 0x44,
            0xfe, 0xa8, 0x01, 0x1b, 0xae, 0x71, 0x95, 0x9a, 0x10, 0x94, 0x7b, 0x6e, 0xa3, 0x3f,
            0x77, 0xe1, 0x28, 0xd3, 0xc6, 0xae,
        ],
    };

    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::ECDSA384_VERIFY),
        &cmd.as_bytes()[4..],
    );

    let cmd = EcdsaVerifyReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..cmd
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::ECDSA384_VERIFY), cmd.as_bytes())
        .unwrap()
        .expect("We should have received a response");

    let resp_hdr: &MailboxRespHeader =
        LayoutVerified::<&[u8], MailboxRespHeader>::new(resp.as_bytes())
            .unwrap()
            .into_ref();

    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    // Checksum is just going to be 0 because FIPS_STATUS_APPROVED is 0
    assert_eq!(resp_hdr.chksum, 0);
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);

    // Test with a bad reqest chksum
    let cmd = EcdsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        ..cmd
    };

    // Make sure the command execution fails.
    let resp = model
        .mailbox_execute(u32::from(CommandId::ECDSA384_VERIFY), cmd.as_bytes())
        .unwrap_err();
    if let ModelError::MailboxCmdFailed(code) = resp {
        assert_eq!(
            code,
            caliptra_drivers::CaliptraError::RUNTIME_INVALID_CHECKSUM.into()
        );
    }
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        caliptra_drivers::CaliptraError::RUNTIME_INVALID_CHECKSUM.into()
    );
}

#[test]
fn test_fips_cmd_api() {
    let mut model = run_rom_test("mbox");

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // VERSION
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };

    let fips_version_resp = model
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
    assert_eq!(fips_version.fips_rev, [0x01, 0x00, 0x00]);
    let name = &fips_version.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());

    // SELF_TEST
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SELF_TEST), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::SELF_TEST), payload.as_bytes())
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

    // SHUTDOWN
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };

    let resp = model.mailbox_execute(u32::from(CommandId::SHUTDOWN), payload.as_bytes());
    assert!(resp.is_ok());

    // Check we are rejecting additional commands with the shutdown error code.
    let expected_err = Err(ModelError::MailboxCmdFailed(0x000E0008));
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };
    let resp = model.mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes());
    assert_eq!(resp, expected_err);
}

#[test]
fn test_unimplemented_cmds() {
    let mut model = run_rom_test("mbox");

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let expected_err = Err(ModelError::MailboxCmdFailed(0xe0002));

    // GET_IDEV_CSR
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_CSR), &[]),
    };

    let mut resp = model.mailbox_execute(u32::from(CommandId::GET_IDEV_CSR), payload.as_bytes());
    assert_eq!(resp, expected_err);

    // GET_LDEV_CERT
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_LDEV_CERT), &[]),
    };

    resp = model.mailbox_execute(u32::from(CommandId::GET_LDEV_CERT), payload.as_bytes());
    assert_eq!(resp, expected_err);

    // STASH_MEASUREMENT
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::STASH_MEASUREMENT),
            &[],
        ),
    };

    resp = model.mailbox_execute(u32::from(CommandId::STASH_MEASUREMENT), payload.as_bytes());
    assert_eq!(resp, expected_err);

    // INVOKE_DPE
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::INVOKE_DPE), &[]),
    };

    resp = model.mailbox_execute(u32::from(CommandId::INVOKE_DPE), payload.as_bytes());
    assert_eq!(resp, expected_err);

    // Send something that is not a valid RT command.
    let expected_err = Err(ModelError::MailboxCmdFailed(0xe0002));
    const INVALID_CMD: u32 = 0xAABBCCDD;
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(INVALID_CMD, &[]),
    };

    let resp = model.mailbox_execute(INVALID_CMD, payload.as_bytes());
    assert_eq!(resp, expected_err);
}

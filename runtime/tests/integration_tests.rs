// Licensed under the Apache-2.0 license.

use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_drivers::Ecc384PubKey;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams, ModelError, ShaAccMode};
use caliptra_runtime::{CommandId, EcdsaVerifyCmd, FipsModuleApi};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    x509::X509,
};
use zerocopy::{AsBytes, FromBytes};

// Run test_bin as a ROM image. The is used for faster tests that can run
// against verilator
fn run_rom_test(test_bin_name: &'static str) -> DefaultHwModel {
    static FEATURES: &[&str] = &["emu", "riscv"];

    let runtime_fwid = FwId {
        crate_name: "caliptra-runtime-test-bin",
        bin_name: test_bin_name,
        features: FEATURES,
        ..Default::default()
    };

    let rom = caliptra_builder::build_firmware_rom(&runtime_fwid).unwrap();

    caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap()
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
fn run_rt_test(test_bin_name: Option<&'static str>) -> DefaultHwModel {
    let runtime_fwid = match test_bin_name {
        Some(bin) => FwId {
            crate_name: "caliptra-runtime-test-bin",
            bin_name: bin,
            features: &["emu", "riscv", "runtime"],
            ..Default::default()
        },
        None => APP_WITH_UART,
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &runtime_fwid,
        ImageOptions::default(),
    )
    .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    model
}

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
    let cmd = EcdsaVerifyCmd {
        chksum: 0,
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

    let cmd = EcdsaVerifyCmd {
        chksum: checksum,
        ..cmd
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::ECDSA384_VERIFY), cmd.as_bytes())
        .unwrap();
    assert!(resp.is_none());
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);

    let cmd = EcdsaVerifyCmd { chksum: 0, ..cmd };

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
    let expected_err = Err(ModelError::MailboxCmdFailed(0x000E0006));

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let cmd = [0u8; 4];

    let resp = model.mailbox_execute(u32::from(FipsModuleApi::VERSION), &cmd);
    assert_eq!(resp, expected_err);

    let resp = model.mailbox_execute(u32::from(FipsModuleApi::SHUTDOWN), &cmd);
    assert_eq!(resp, expected_err);

    let resp = model.mailbox_execute(u32::from(FipsModuleApi::SELF_TEST), &cmd);
    assert_eq!(resp, expected_err);

    let expected_err = Err(ModelError::MailboxCmdFailed(0xe0002));
    // Send something that is not a valid RT command.
    let resp = model.mailbox_execute(0xBABEFACE, &cmd);
    assert_eq!(resp, expected_err);
}

#[test]
fn test_unimplemented_cmds() {
    let mut model = run_rom_test("mbox");

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let cmd = [0u8; 4];

    let expected_err = Err(ModelError::MailboxCmdFailed(0xe0002));

    let mut resp = model.mailbox_execute(u32::from(CommandId::GET_IDEV_CSR), &cmd);
    assert_eq!(resp, expected_err);

    resp = model.mailbox_execute(u32::from(CommandId::GET_LDEV_CERT), &cmd);
    assert_eq!(resp, expected_err);

    resp = model.mailbox_execute(u32::from(CommandId::STASH_MEASUREMENT), &cmd);
    assert_eq!(resp, expected_err);

    resp = model.mailbox_execute(u32::from(CommandId::INVOKE_DPE), &cmd);
    assert_eq!(resp, expected_err);
}

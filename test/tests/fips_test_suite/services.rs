// Licensed under the Apache-2.0 license
use crate::common;

use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::*;
use caliptra_hw_model::{BootParams, HwModel, ShaAccMode};
use caliptra_image_types::ImageManifest;
use common::*;
use zerocopy::{AsBytes, FromBytes};

pub fn exec_cmd_version<T: HwModel>(hw: &mut T, fmc_version: u16, app_version: u32) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };
    let version_resp = mbx_send_and_check_resp_hdr::<_, FipsVersionResp>(
        hw,
        u32::from(CommandId::VERSION),
        payload.as_bytes(),
    )
    .unwrap();

    // Verify command-specific response data
    assert_eq!(version_resp.mode, FipsVersionCmd::MODE);
    let fw_version_0_expected =
        ((fmc_version as u32) << 16) | (RomExpVals::get().rom_version as u32);
    assert_eq!(
        version_resp.fips_rev,
        [
            HwExpVals::get().hw_revision,
            fw_version_0_expected,
            app_version
        ]
    );
    let name = &version_resp.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());
}

pub fn exec_cmd_self_test_start<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_START),
            &[],
        ),
    };

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::SELF_TEST_START),
        payload.as_bytes(),
    )
    .unwrap();
}

pub fn exec_cmd_self_test_get_results<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            &[],
        ),
    };

    // Attempt get_results in a loop until we get a response
    loop {
        // Get self test results
        match mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
            hw,
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            payload.as_bytes(),
        ) {
            // Nothing extra to do once we see success
            Ok(_resp) => break,
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
}

pub fn exec_cmd_get_idev_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_CERT), &[]),
    };

    let cert_resp = mbx_send_and_check_resp_hdr::<_, GetIdevCertResp>(
        hw,
        u32::from(CommandId::GET_IDEV_CERT),
        payload.as_bytes(),
    )
    .unwrap();

    // Make sure we got some cert data (not verifying contents)
    assert!(cert_resp.cert_size > 0);

    // Verify we have something in the data field
    assert!(contains_some_data(
        &cert_resp.cert[..cert_resp.cert_size as usize]
    ));
}

pub fn exec_cmd_get_idev_info<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_INFO), &[]),
    };

    let resp = mbx_send_and_check_resp_hdr::<_, GetIdevInfoResp>(
        hw,
        u32::from(CommandId::GET_IDEV_INFO),
        payload.as_bytes(),
    )
    .unwrap();

    // Verify we have something in the data fields
    assert!(contains_some_data(&resp.idev_pub_x));
    assert!(contains_some_data(&resp.idev_pub_y));
}

pub fn exec_cmd_populate_idev_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::POPULATE_IDEV_CERT),
            &[],
        ),
    };

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::POPULATE_IDEV_CERT),
        payload.as_bytes(),
    )
    .unwrap();
}

pub fn exec_cmd_get_ldev_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_LDEV_CERT), &[]),
    };

    let ldev_cert_resp = mbx_send_and_check_resp_hdr::<_, GetLdevCertResp>(
        hw,
        u32::from(CommandId::GET_LDEV_CERT),
        payload.as_bytes(),
    )
    .unwrap();

    // Make sure we got some cert data (not verifying contents)
    assert!(ldev_cert_resp.data_size > 0);

    // Verify we have something in the data field
    assert!(contains_some_data(
        &ldev_cert_resp.data[..ldev_cert_resp.data_size as usize]
    ));
}

pub fn exec_cmd_get_fmc_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_CERT),
            &[],
        ),
    };

    let cert_resp = mbx_send_and_check_resp_hdr::<_, GetFmcAliasCertResp>(
        hw,
        u32::from(CommandId::GET_FMC_ALIAS_CERT),
        payload.as_bytes(),
    )
    .unwrap();

    // Make sure we got some cert data (not verifying contents)
    assert!(cert_resp.data_size > 0);

    // Verify we have something in the data field
    assert!(contains_some_data(
        &cert_resp.data[..cert_resp.data_size as usize]
    ));
}

pub fn exec_cmd_get_rt_cert<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_RT_ALIAS_CERT),
            &[],
        ),
    };

    let cert_resp = mbx_send_and_check_resp_hdr::<_, GetRtAliasCertResp>(
        hw,
        u32::from(CommandId::GET_RT_ALIAS_CERT),
        payload.as_bytes(),
    )
    .unwrap();

    // Make sure we got some cert data (not verifying contents)
    assert!(cert_resp.data_size > 0);

    // Verify we have something in the data field
    assert!(contains_some_data(
        &cert_resp.data[..cert_resp.data_size as usize]
    ));
}

pub fn exec_cmd_capabilities<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };
    let capabilities_resp = mbx_send_and_check_resp_hdr::<_, CapabilitiesResp>(
        hw,
        u32::from(CommandId::CAPABILITIES),
        payload.as_bytes(),
    )
    .unwrap();

    // Verify command-specific response data
    assert_eq!(
        capabilities_resp.capabilities,
        RomExpVals::get().capabilities
    );
}

pub fn exec_cmd_ecdsa_verify<T: HwModel>(hw: &mut T) {
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
    hw.compute_sha512_acc_digest(msg, ShaAccMode::Sha384Stream)
        .unwrap();

    let mut payload = MailboxReq::EcdsaVerify(EcdsaVerifyReq {
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
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::ECDSA384_VERIFY),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_stash_measurement<T: HwModel>(hw: &mut T) {
    let payload = StashMeasurementReq {
        hdr: MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(
                u32::from(CommandId::STASH_MEASUREMENT),
                &[],
            ),
        },
        ..Default::default()
    };
    let stash_measurement_resp = mbx_send_and_check_resp_hdr::<_, StashMeasurementResp>(
        hw,
        u32::from(CommandId::STASH_MEASUREMENT),
        payload.as_bytes(),
    )
    .unwrap();

    // Verify command-specific response data
    assert_eq!(stash_measurement_resp.dpe_result, 0);
}

pub fn exec_fw_info<T: HwModel>(hw: &mut T, fw_image: &Vec<u8>) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };
    let fw_info_resp = mbx_send_and_check_resp_hdr::<_, FwInfoResp>(
        hw,
        u32::from(CommandId::FW_INFO),
        payload.as_bytes(),
    )
    .unwrap();

    let manifest = ImageManifest::read_from_prefix(&**fw_image).unwrap();
    // Verify command-specific response data
    assert_eq!(fw_info_resp.fmc_revision, manifest.fmc.revision);
    assert_eq!(fw_info_resp.runtime_revision, manifest.runtime.revision);
    assert!(contains_some_data(&fw_info_resp.rom_revision));
    assert!(contains_some_data(&fw_info_resp.rom_sha256_digest));
    assert!(contains_some_data(&fw_info_resp.fmc_sha384_digest));
    assert!(contains_some_data(&fw_info_resp.runtime_sha384_digest));
}

pub fn exec_dpe_tag_tci<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: [0u8; 16],
        tag: 1,
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::DPE_TAG_TCI),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_get_taged_tci<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: 1,
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, GetTaggedTciResp>(
        hw,
        u32::from(CommandId::DPE_GET_TAGGED_TCI),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    // Verify command-specific response data
    assert!(contains_some_data(&resp.tci_cumulative));
    assert_eq!(resp.tci_current, [0u8; 48]);
}

pub fn exec_incr_pcr_rst_counter<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::IncrementPcrResetCounter(IncrementPcrResetCounterReq {
        hdr: MailboxReqHeader { chksum: 0 },
        index: 1,
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::INCREMENT_PCR_RESET_COUNTER),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_quote_pcrs<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::QuotePcrs(QuotePcrsReq {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, QuotePcrsResp>(
        hw,
        u32::from(CommandId::QUOTE_PCRS),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    // Verify command-specific response data
    assert!(contains_some_data(&resp.pcrs));
    assert!(contains_some_data(&resp.nonce));
    assert!(contains_some_data(&resp.digest));
    assert!(contains_some_data(&resp.reset_ctrs));
    assert!(contains_some_data(&resp.signature_r));
    assert!(contains_some_data(&resp.signature_s));
}

pub fn exec_cmd_extend_pcr<T: HwModel>(hw: &mut T) {
    let mut payload = MailboxReq::ExtendPcr(ExtendPcrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pcr_idx: 4,
        data: [0u8; 48],
    });
    payload.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::EXTEND_PCR),
        payload.as_bytes().unwrap(),
    )
    .unwrap();
}

pub fn exec_cmd_disable_attestation<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::DISABLE_ATTESTATION),
        payload.as_bytes(),
    )
    .unwrap();
}

pub fn exec_cmd_shutdown<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        hw,
        u32::from(CommandId::SHUTDOWN),
        payload.as_bytes(),
    )
    .unwrap();
}

#[test]
pub fn check_version_rom() {
    let mut hw = fips_test_init_to_rom(None);

    // FMC and FW version should both be 0 before loading
    exec_cmd_version(&mut hw, 0x0, 0x0);
}

#[test]
pub fn check_version_rt() {
    let mut hw = fips_test_init_to_rt(None);

    exec_cmd_version(
        &mut hw,
        RtExpVals::get().fmc_version,
        RtExpVals::get().fw_version,
    );
}

#[test]
pub fn execute_all_services_rom() {
    let mut hw = fips_test_init_to_rom(None);

    // TODO: SHA accelerator engine

    // VERSION
    // FMC and FW version should both be 0 before loading
    exec_cmd_version(&mut hw, 0x0, 0x0);

    // SELF TEST START
    exec_cmd_self_test_start(&mut hw);

    // SELF TEST GET RESULTS
    exec_cmd_self_test_get_results(&mut hw);

    // CAPABILITIES
    exec_cmd_capabilities(&mut hw);

    // STASH MEASUREMENT
    exec_cmd_stash_measurement(&mut hw);

    // SHUTDOWN
    // (Do this last)
    exec_cmd_shutdown(&mut hw);
}

#[test]
pub fn execute_all_services_rt() {
    let fw_image = fips_fw_image();
    let mut hw = fips_test_init_to_rt(Some(BootParams {
        fw_image: Some(&fw_image),
        ..Default::default()
    }));

    // TODO: SHA accelerator engine

    // VERSION
    // FMC and FW version should both be 0 before loading
    exec_cmd_version(
        &mut hw,
        RtExpVals::get().fmc_version,
        RtExpVals::get().fw_version,
    );

    // SELF TEST START
    exec_cmd_self_test_start(&mut hw);

    // SELF TEST GET RESULTS
    exec_cmd_self_test_get_results(&mut hw);

    // GET_IDEV_CERT
    exec_cmd_get_idev_cert(&mut hw);

    // GET_IDEV_INFO
    exec_cmd_get_idev_info(&mut hw);

    // POPULATE_IDEV_CERT
    exec_cmd_populate_idev_cert(&mut hw);

    // GET_LDEV_CERT
    exec_cmd_get_ldev_cert(&mut hw);

    // GET_FMC_ALIAS_CERT
    exec_cmd_get_fmc_cert(&mut hw);

    // GET_RT_ALIAS_CERT
    exec_cmd_get_rt_cert(&mut hw);

    // ECDSA384_VERIFY
    exec_cmd_ecdsa_verify(&mut hw);

    // STASH_MEASUREMENT
    exec_cmd_stash_measurement(&mut hw);

    // FW_INFO
    exec_fw_info(&mut hw, &fw_image);

    // DPE_TAG_TCI
    exec_dpe_tag_tci(&mut hw);

    // DPE_GET_TAGGED_TCI
    exec_get_taged_tci(&mut hw);

    // INCREMENT_PCR_RESET_COUNTER
    exec_incr_pcr_rst_counter(&mut hw);

    // QUOTE_PCRS
    exec_cmd_quote_pcrs(&mut hw);

    // EXTEND_PCR
    exec_cmd_extend_pcr(&mut hw);

    // INVOKE_DPE
    // TODO: Invoke all supported DPE commands

    // (Do these last)
    // DISABLE_ATTESTATION
    exec_cmd_disable_attestation(&mut hw);

    // SHUTDOWN
    // TODO: Uncomment once runtime shutdown fix is merged
    //exec_cmd_shutdown(&mut hw);
}

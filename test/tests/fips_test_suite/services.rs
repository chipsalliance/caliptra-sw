// Licensed under the Apache-2.0 license
use crate::common;

use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::*;
use caliptra_hw_model::HwModel;
use common::*;
use zerocopy::AsBytes;

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
    let mut hw = fips_test_init_to_rt(None);

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

    // GET_IDEV_INFO

    // POPULATE_IDEV_CERT

    // GET_LDEV_CERT
    exec_cmd_get_ldev_cert(&mut hw);

    // GET_FMC_ALIAS_CERT

    // GET_RT_ALIAS_CERT

    // ECDSA384_VERIFY

    // STASH_MEASUREMENT
    exec_cmd_stash_measurement(&mut hw);

    // FW_INFO

    // DPE_TAG_TCI

    // DPE_GET_TAGGED_TCI

    // INCREMENT_PCR_RESET_COUNTER

    // QUOTE_PCRS

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

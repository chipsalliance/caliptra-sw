// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, OcpLockReportHekMetadataReq,
    OcpLockReportHekMetadataResp, OcpLockReportHekMetadataRespFlags,
};
use caliptra_builder::firmware::runtime_tests;
use caliptra_drivers::HekSeedState;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_image_types::FwVerificationPqcKeyType;
use dpe::U8Bool;
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

mod test_get_algorithms;

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_hek_metadata_never_reported() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&runtime_tests::MBOX_FPGA),
        // This test assumes OCP LOCK is always enabled.
        ocp_lock_en: true,
        key_type: Some(FwVerificationPqcKeyType::MLDSA),
        ..Default::default()
    });

    let expected_val = U8Bool::new(false);
    // HEK can NEVER be valid if MCU ROM never reported the HEK metadata.
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_hek_available() {
    let mut cmd = MailboxReq::OcpLockReportHekMetadata(OcpLockReportHekMetadataReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed_state: HekSeedState::Programmed.into(),
        ..Default::default()
    });

    cmd.populate_chksum().unwrap();

    let rom_callback = move |model: &mut DefaultHwModel| {
        let response = model
            .mailbox_execute(
                CommandId::OCP_LOCK_REPORT_HEK_METADATA.into(),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .unwrap();

        let response = OcpLockReportHekMetadataResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert!(response
            .flags
            .contains(OcpLockReportHekMetadataRespFlags::HEK_AVAILABLE));
    };

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&runtime_tests::MBOX_FPGA),
        // This test assumes OCP LOCK is always enabled.
        ocp_lock_en: true,
        key_type: Some(FwVerificationPqcKeyType::MLDSA),
        rom_callback: Some(Box::new(rom_callback)),
        ..Default::default()
    });

    // We reported HEK metadata so it should be available.
    let expected_val = U8Bool::new(true);
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}

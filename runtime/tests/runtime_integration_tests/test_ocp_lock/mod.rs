// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, OcpLockReportHekMetadataReq,
    OcpLockReportHekMetadataResp, OcpLockReportHekMetadataRespFlags,
};
use caliptra_builder::{firmware::runtime_tests, FwId};
use caliptra_drivers::HekSeedState;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelCallback};
use caliptra_image_types::FwVerificationPqcKeyType;
use dpe::U8Bool;
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

mod test_get_algorithms;
mod test_initialize_mek_secret;

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_hek_metadata_never_reported() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        // This test assumes OCP LOCK is always enabled.
        force_ocp_lock_en: true,
        rt_fw_id: Some(&runtime_tests::MBOX_FPGA),
        ..Default::default()
    });

    // HEK can NEVER be valid if MCU ROM never reported the HEK metadata.
    let expected_val = U8Bool::new(false);
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_hek_available() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        rt_fw_id: Some(&runtime_tests::MBOX_FPGA),
        ..Default::default()
    });

    // We reported HEK metadata so it should be available.
    let expected_val = U8Bool::new(true);
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}

#[derive(Default)]
struct OcpLockBootParams {
    hek_available: bool,
    force_ocp_lock_en: bool,
    rt_fw_id: Option<&'static FwId<'static>>,
    // The linter doesn't like using Default when all params are set.
    _private: (),
}

fn boot_ocp_lock_runtime(params: OcpLockBootParams) -> DefaultHwModel {
    let mut cmd = MailboxReq::OcpLockReportHekMetadata(OcpLockReportHekMetadataReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed_state: HekSeedState::Programmed.into(),
        ..Default::default()
    });

    cmd.populate_chksum().unwrap();

    let cb = move |model: &mut DefaultHwModel| {
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

    let rom_callback: Option<ModelCallback> = if params.hek_available {
        Some(Box::new(cb))
    } else {
        None
    };

    run_rt_test(RuntimeTestArgs {
        test_fwid: params.rt_fw_id,
        ocp_lock_en: params.force_ocp_lock_en,
        key_type: Some(FwVerificationPqcKeyType::MLDSA),
        rom_callback,
        ..Default::default()
    })
}

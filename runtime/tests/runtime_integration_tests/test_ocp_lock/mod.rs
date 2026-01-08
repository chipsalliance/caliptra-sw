// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{
        CapabilitiesResp, CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader,
        OcpLockInitializeMekSecretReq, OcpLockReportHekMetadataReq, OcpLockReportHekMetadataResp,
        OcpLockReportHekMetadataRespFlags,
    },
    Capabilities,
};
use caliptra_builder::{firmware::runtime_tests, FwId};
use caliptra_drivers::HekSeedState;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    DefaultHwModel, HwModel, ModelCallback, ModelError, OcpLockState, SecurityState,
};
use caliptra_image_types::FwVerificationPqcKeyType;
use dpe::U8Bool;
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

mod test_derive_mek;
mod test_enumerate_hpke_handles;
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

struct InitializeMekSecretParams {
    sek: [u8; 32],
    dpk: [u8; 32],
}

#[derive(Default)]
struct OcpLockBootParams {
    hek_available: bool,
    init_mek_secret_params: Option<InitializeMekSecretParams>,
    force_ocp_lock_en: bool,
    rt_fw_id: Option<&'static FwId<'static>>,
    security_state: Option<SecurityState>,
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

    // A common operation is to report the HEK metadata.
    // The HEK is not available without this step.
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

    let security_state = params.security_state.unwrap_or(
        *SecurityState::default()
            .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
            .set_debug_locked(true),
    );

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: params.rt_fw_id,
        ocp_lock_en: params.force_ocp_lock_en,
        key_type: Some(FwVerificationPqcKeyType::MLDSA),
        rom_callback,
        security_state: Some(security_state),
        ..Default::default()
    });

    // Another common operation is to seed the MEK secret.
    // Many commands, e.g. `DERIVE_MEK` will not work until this happens.
    if let Some(params) = params.init_mek_secret_params {
        // Initialize MEK Secret Seed
        let mut cmd = MailboxReq::OcpLockInitializeMekSecret(OcpLockInitializeMekSecretReq {
            hdr: MailboxReqHeader { chksum: 0 },
            reserved: 0,
            sek: params.sek,
            dpk: params.dpk,
        });
        cmd.populate_chksum().unwrap();
        let response = model.mailbox_execute(
            CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET.into(),
            cmd.as_bytes().unwrap(),
        );
        validate_ocp_lock_response(&mut model, response, |response, _| {
            response.unwrap().unwrap();
        });
    }
    model
}

fn ocp_lock_supported(model: &mut DefaultHwModel) -> bool {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };

    let response = model
        .mailbox_execute(u32::from(CommandId::CAPABILITIES), payload.as_bytes())
        .unwrap()
        .unwrap();

    let capabilities_resp = CapabilitiesResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(caliptra_common::checksum::verify_checksum(
        capabilities_resp.hdr.chksum,
        0x0,
        &capabilities_resp.as_bytes()[core::mem::size_of_val(&capabilities_resp.hdr.chksum)..],
    ));
    assert_eq!(
        capabilities_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let caps = Capabilities::try_from(capabilities_resp.capabilities.as_bytes()).unwrap();
    assert!(caps.contains(Capabilities::RT_BASE));

    caps.contains(Capabilities::RT_OCP_LOCK)
}

fn validate_ocp_lock_response(
    model: &mut DefaultHwModel,
    response: std::result::Result<Option<Vec<u8>>, ModelError>,
    check_callback: impl FnOnce(std::result::Result<Option<Vec<u8>>, ModelError>, OcpLockState),
) {
    if ocp_lock_supported(model) {
        let state = model.ocp_lock_state().unwrap();
        check_callback(response, state);
    } else {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND.into(),
            )
        );
    }
}

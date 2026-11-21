// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_api::{
    mailbox::{CapabilitiesResp, CommandId, MailboxReqHeader, MailboxRespHeader},
    Capabilities,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;

use crate::common::{run_rt_test, RuntimeTestArgs};

use zerocopy::{FromBytes, IntoBytes};

pub fn get_capabilities(model: &mut DefaultHwModel) -> Capabilities {
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };

    let response = model
        .mailbox_execute(u32::from(CommandId::CAPABILITIES), payload.as_bytes())
        .unwrap()
        .unwrap();

    let capabilities_resp = CapabilitiesResp::ref_from_bytes(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        capabilities_resp.hdr.chksum,
        0x0,
        &capabilities_resp.as_bytes()[core::mem::size_of_val(&capabilities_resp.hdr.chksum)..],
    ));
    // Verify FIPS status
    assert_eq!(
        capabilities_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    Capabilities::try_from(capabilities_resp.capabilities.as_bytes()).unwrap()
}

#[test]
fn test_capabilities() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let caps = get_capabilities(&mut model);
    assert!(caps.contains(Capabilities::RT_BASE));

    if model.subsystem_mode() && model.supports_ocp_lock() {
        assert!(caps.contains(Capabilities::RT_OCP_LOCK));
    } else {
        assert!(!caps.contains(Capabilities::RT_OCP_LOCK));
    }
    assert_eq!(
        caps.contains(Capabilities::RT_SHA_DMA),
        model.subsystem_mode()
    );
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_capabilities_subsystem_mode() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    let caps = get_capabilities(&mut model);
    assert!(caps.contains(Capabilities::RT_BASE));
    assert!(caps.contains(Capabilities::RT_SHA_DMA));
}

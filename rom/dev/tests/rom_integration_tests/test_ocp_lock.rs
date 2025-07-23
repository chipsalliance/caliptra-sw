// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{CapabilitiesResp, CommandId, MailboxReqHeader, MailboxRespHeader};
use caliptra_api::Capabilities;
use caliptra_builder::firmware::ROM_WITH_UART_OCP_LOCK;
use caliptra_hw_model::HwModel;
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_ocp_lock_enabled() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART_OCP_LOCK).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };

    let response = hw
        .mailbox_execute(CommandId::CAPABILITIES.into(), payload.as_bytes())
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
    assert!(caps.contains(Capabilities::ROM_BASE));
    assert!(caps.contains(Capabilities::ROM_OCP_LOCK));
}

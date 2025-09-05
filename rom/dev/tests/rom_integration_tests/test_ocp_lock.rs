// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::CapabilitiesResp;
use caliptra_api::Capabilities;
use caliptra_builder::firmware::ROM_FPGA_WITH_UART_OCP_LOCK;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
use caliptra_hw_model::{Fuses, HwModel};
use zerocopy::{FromBytes, IntoBytes};

/// NOTE: This test assumes that `ss_ocp_lock_en` is set to true in the Caliptra bitstream.
#[test]
fn test_ocp_lock_supported() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FPGA_WITH_UART_OCP_LOCK).unwrap();

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
    let caps = Capabilities::try_from(capabilities_resp.capabilities.as_bytes()).unwrap();
    assert!(caps.contains(Capabilities::ROM_OCP_LOCK));
}

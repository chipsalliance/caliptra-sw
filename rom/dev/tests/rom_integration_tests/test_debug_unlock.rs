// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{CommandId, MailboxReqHeader, ManufDebugUnlockTokenReq};
use caliptra_api::SocManager;
use caliptra_builder::firmware::ROM_WITH_UART;
use caliptra_hw_model::{DbgManufServiceRegReq, DeviceLifecycle, HwModel, SecurityState};
use zerocopy::AsBytes;

#[test]
fn test_dbg_unlock_manuf() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Manufacturing);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_manuf_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            debug_intent: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let token = ManufDebugUnlockTokenReq {
        token: caliptra_hw_model_types::DEFAULT_MANUF_DEBUG_UNLOCK_TOKEN
            .as_bytes()
            .try_into()
            .unwrap(),
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN),
        &token.as_bytes()[4..],
    );
    let token = ManufDebugUnlockTokenReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..token
    };
    hw.mailbox_execute(
        CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN.into(),
        token.as_bytes(),
    )
    .unwrap();

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        resp.manuf_dbg_unlock_success()
    });
}

// [TODO][CAP2] write unit test for production

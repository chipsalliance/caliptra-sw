// Licensed under the Apache-2.0 license.

#![cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]

use crate::common::{rom_for_fw_integration_tests, run_rt_test, RuntimeTestArgs};
use caliptra_api::{
    mailbox::{
        CommandId, MailboxReqHeader, ZeroizeUdsFeReq, ZEROIZE_FE0_FLAG, ZEROIZE_FE1_FLAG,
        ZEROIZE_FE2_FLAG, ZEROIZE_FE3_FLAG, ZEROIZE_UDS_FLAG,
    },
    SocManager,
};
use caliptra_builder::{firmware::APP_WITH_UART, ImageOptions};
use caliptra_common::checksum::calc_checksum;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    DefaultHwModel, DeviceLifecycle, HwModel, InitParams, ModelError, SecurityState,
    SubsystemInitParams,
};
use zerocopy::IntoBytes;

const ALL_FLAGS: u32 =
    ZEROIZE_UDS_FLAG | ZEROIZE_FE0_FLAG | ZEROIZE_FE1_FLAG | ZEROIZE_FE2_FLAG | ZEROIZE_FE3_FLAG;
const PARTITIONS: [(u32, usize); 5] = [
    (ZEROIZE_UDS_FLAG, (64 + 8 + 8) / 4),
    (ZEROIZE_FE0_FLAG, (8 + 8 + 8) / 4),
    (ZEROIZE_FE1_FLAG, (8 + 8 + 8) / 4),
    (ZEROIZE_FE2_FLAG, (8 + 8 + 8) / 4),
    (ZEROIZE_FE3_FLAG, (8 + 8 + 8) / 4),
];

fn runtime_model(
    uds_fuse_row_granularity_64: bool,
    subsystem_mode: bool,
    pl0_pauser: Option<u32>,
) -> DefaultHwModel {
    let rom = rom_for_fw_integration_tests().unwrap();
    let mut image_options = ImageOptions::default();
    image_options.vendor_config.pl0_pauser = pl0_pauser;

    run_rt_test(RuntimeTestArgs {
        init_params: Some(InitParams {
            rom: &rom,
            security_state: *SecurityState::default()
                .set_device_lifecycle(DeviceLifecycle::Production),
            subsystem_mode,
            uds_fuse_row_granularity_64,
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: subsystem_mode,
                ..Default::default()
            },
            ..Default::default()
        }),
        test_fwid: Some(&APP_WITH_UART),
        test_image_options: Some(image_options),
        subsystem_mode,
        ..Default::default()
    })
}

fn assert_shutdown(model: &mut DefaultHwModel) {
    let request = MailboxReqHeader {
        chksum: calc_checksum(CommandId::VERSION.into(), &[]),
    };
    assert_eq!(
        model.mailbox_execute(CommandId::VERSION.into(), request.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_SHUTDOWN.into()
        ))
    );
    assert_eq!(
        model.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::RUNTIME_SHUTDOWN)
    );
}

fn assert_selected_partitions(model: &DefaultHwModel, before: &[u32], flags: u32) {
    let after = model.otp_fuse_bank();
    let mut offset = 0;
    for (flag, word_count) in PARTITIONS {
        for word in offset..offset + word_count {
            let expected = if flags & flag != 0 {
                u32::MAX
            } else {
                before[word]
            };
            assert_eq!(after[word], expected, "OTP word {word}, flags {flags:#x}");
        }
        offset += word_count;
    }
    assert_eq!(after.len(), offset);
    assert_eq!(before.len(), offset);
}

fn assert_zeroization(flags: u32, uds_fuse_row_granularity_64: bool) {
    let mut model = runtime_model(uds_fuse_row_granularity_64, true, Some(1));
    let before = model.otp_fuse_bank().to_vec();
    assert!(before.iter().all(|word| *word != u32::MAX));

    let response = model
        .mailbox_execute_req(ZeroizeUdsFeReq {
            flags,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(response.dpe_result, 0);
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
    assert_selected_partitions(&model, &before, flags);
    assert_shutdown(&mut model);
}

fn request_bytes(payload: &[u8]) -> Vec<u8> {
    let header = MailboxReqHeader {
        chksum: calc_checksum(CommandId::ZEROIZE_UDS_FE.into(), payload),
    };
    let mut request = header.as_bytes().to_vec();
    request.extend_from_slice(payload);
    request
}

fn assert_rejected_without_side_effects(
    model: &mut DefaultHwModel,
    request: &[u8],
    expected_error: CaliptraError,
) {
    let before = model.otp_fuse_bank().to_vec();
    assert_eq!(
        model.mailbox_execute(CommandId::ZEROIZE_UDS_FE.into(), request),
        Err(ModelError::MailboxCmdFailed(expected_error.into()))
    );
    assert_eq!(model.otp_fuse_bank(), before);
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
    let header = MailboxReqHeader {
        chksum: calc_checksum(CommandId::VERSION.into(), &[]),
    };
    model
        .mailbox_execute(CommandId::VERSION.into(), header.as_bytes())
        .unwrap()
        .expect("Runtime must remain available after rejecting the request");
}

#[test]
fn test_zeroize_uds_fe_all_partitions_64bit() {
    assert_zeroization(ALL_FLAGS, true);
}

#[test]
fn test_zeroize_uds_fe_all_partitions_32bit() {
    assert_zeroization(ALL_FLAGS, false);
}

#[test]
fn test_zeroize_uds_fe_selected_partition_64bit() {
    for (flag, _) in PARTITIONS {
        assert_zeroization(flag, true);
    }
}

#[test]
fn test_zeroize_uds_fe_selected_partition_32bit() {
    for (flag, _) in PARTITIONS {
        assert_zeroization(flag, false);
    }
}

#[test]
fn test_zeroize_uds_fe_rejects_invalid_flags() {
    let mut model = runtime_model(true, true, Some(1));
    for flags in [0u32, 1 << 5, ZEROIZE_UDS_FLAG | (1 << 31)] {
        assert_rejected_without_side_effects(
            &mut model,
            &request_bytes(&flags.to_le_bytes()),
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        );
    }
}

#[test]
fn test_zeroize_uds_fe_rejects_invalid_lengths() {
    let mut model = runtime_model(true, true, Some(1));
    for payload_len in [0, 3, 5, 8] {
        let mut payload = ALL_FLAGS.to_le_bytes().to_vec();
        payload.resize(payload_len, 0);
        assert_rejected_without_side_effects(
            &mut model,
            &request_bytes(&payload),
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        );
    }
}

#[test]
fn test_zeroize_uds_fe_rejects_invalid_checksum() {
    let mut model = runtime_model(true, true, Some(1));
    let mut request = request_bytes(&ALL_FLAGS.to_le_bytes());
    request[0] ^= 1;
    assert_rejected_without_side_effects(
        &mut model,
        &request,
        CaliptraError::RUNTIME_INVALID_CHECKSUM,
    );
}

#[test]
fn test_zeroize_uds_fe_rejects_pl1() {
    let mut model = runtime_model(true, true, None);
    assert_rejected_without_side_effects(
        &mut model,
        &request_bytes(&ALL_FLAGS.to_le_bytes()),
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
    );
}

#[test]
fn test_zeroize_uds_fe_rejects_passive_mode() {
    let mut model = runtime_model(true, false, Some(1));
    assert_rejected_without_side_effects(
        &mut model,
        &request_bytes(&ALL_FLAGS.to_le_bytes()),
        CaliptraError::RUNTIME_ZEROIZE_UDS_FE_NOT_SUBSYSTEM_MODE,
    );
}

#[test]
fn test_zeroize_uds_fe_reports_readback_failure_and_shuts_down() {
    let mut model = runtime_model(true, true, Some(1));
    model.set_otp_error_injection(true);

    let response = model
        .mailbox_execute_req(ZeroizeUdsFeReq {
            flags: ALL_FLAGS,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(response.dpe_result, 1);
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::UDS_FE_ZEROIZATION_MARKER_NOT_CLEARED)
    );
    assert!(model.otp_fuse_bank().iter().any(|word| *word != u32::MAX));
    assert_shutdown(&mut model);
}

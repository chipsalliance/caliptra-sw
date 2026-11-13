// Licensed under the Apache-2.0 license

use crate::common::{assert_error, run_rt_test, run_rt_test_return_fw, RuntimeTestArgs};
use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    CommandId, ExternalMailboxCmdReq, FirmwareVerifyResp, FirmwareVerifyResult, MailboxReq,
    MailboxReqHeader, MAX_REQ_SIZE, SUBSYSTEM_MAILBOX_SIZE_LIMIT,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use zerocopy::{FromBytes, IntoBytes};

pub(super) fn external_request(command: u32, size: u32, address: u64) -> MailboxReq {
    let mut request = MailboxReq::ExternalMailboxCmd(ExternalMailboxCmdReq {
        command_id: command,
        command_size: size,
        axi_address_start_low: address as u32,
        axi_address_start_high: (address >> 32) as u32,
        ..Default::default()
    });
    request.populate_chksum().unwrap();
    request
}

#[test]
fn test_external_mailbox_small_command() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    let command = u32::from(CommandId::VERSION);
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(command, &[]),
    };
    let direct = model.mailbox_execute(command, payload.as_bytes()).unwrap();
    let address = model
        .write_payload_to_ss_staging_area(payload.as_bytes(), 256)
        .unwrap();
    let request = external_request(command, size_of::<MailboxReqHeader>() as u32, address);
    let external = model
        .mailbox_execute(
            CommandId::EXTERNAL_MAILBOX_CMD.into(),
            request.as_bytes().unwrap(),
        )
        .unwrap();
    assert_eq!(external, direct);
}

#[test]
fn test_external_mailbox_invalid_dma_inputs() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    // Unlike DMA, direct mailbox commands preserve byte-granular lengths.
    // Use an otherwise valid VERSION checksum: previously size 5..=7 was
    // truncated to this four-byte request and silently accepted.
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(CommandId::VERSION.into(), &[]),
    };
    let address = model
        .write_payload_to_ss_staging_area(payload.as_bytes(), 256)
        .unwrap();
    for command in [
        CommandId::VERSION,
        CommandId::FIRMWARE_LOAD,
        CommandId::FIRMWARE_VERIFY,
    ] {
        let command = u32::from(command);
        for size in [0, 1, 2, 3, 5, 6, 7] {
            let request = external_request(command, size, address);
            let error = model
                .mailbox_execute(
                    CommandId::EXTERNAL_MAILBOX_CMD.into(),
                    request.as_bytes().unwrap(),
                )
                .unwrap_err();
            assert_error(
                &mut model,
                CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
                error,
            );
        }
        for offset in 1..=3 {
            let request = external_request(command, 4, address + offset);
            let error = model
                .mailbox_execute(
                    CommandId::EXTERNAL_MAILBOX_CMD.into(),
                    request.as_bytes().unwrap(),
                )
                .unwrap_err();
            assert_error(
                &mut model,
                CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
                error,
            );
        }
    }
}

#[test]
fn test_external_mailbox_size_limit() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    let command = 0xaabbccdd;
    let mut payload = vec![0; MAX_REQ_SIZE];
    let checksum = caliptra_common::checksum::calc_checksum(command, &payload[4..]);
    payload[..4].copy_from_slice(&checksum.to_le_bytes());
    let address = model.write_payload_to_ss_staging_area(&payload, 0).unwrap();
    for (size, expected_error) in [
        (
            MAX_REQ_SIZE as u32,
            CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND,
        ),
        (
            MAX_REQ_SIZE as u32 + 4,
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        ),
    ] {
        let request = external_request(command, size, address);
        let error = model
            .mailbox_execute(
                CommandId::EXTERNAL_MAILBOX_CMD.into(),
                request.as_bytes().unwrap(),
            )
            .unwrap_err();
        assert_error(&mut model, expected_error, error);
    }
}

#[test]
fn test_external_mailbox_threshold() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    for size in [
        SUBSYSTEM_MAILBOX_SIZE_LIMIT,
        SUBSYSTEM_MAILBOX_SIZE_LIMIT + 4,
    ] {
        let mut payload = vec![0; size];
        let checksum =
            caliptra_common::checksum::calc_checksum(CommandId::VERSION.into(), &payload[4..]);
        payload[..4].copy_from_slice(&checksum.to_le_bytes());
        model
            .start_mailbox_execute(CommandId::VERSION.into(), &payload)
            .unwrap();
        let expected_command = if size == SUBSYSTEM_MAILBOX_SIZE_LIMIT {
            CommandId::VERSION
        } else {
            CommandId::EXTERNAL_MAILBOX_CMD
        };
        assert_eq!(model.soc_mbox().cmd().read(), u32::from(expected_command));
        model.finish_mailbox_execute().unwrap().unwrap();
    }
}

#[test]
fn test_external_mailbox_inner_checksum() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    let command = u32::from(CommandId::VERSION);
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(command, &[]) ^ 1,
    };
    let address = model
        .write_payload_to_ss_staging_area(payload.as_bytes(), 0)
        .unwrap();
    let request = external_request(command, 4, address);
    let error = model
        .mailbox_execute(
            CommandId::EXTERNAL_MAILBOX_CMD.into(),
            request.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_INVALID_CHECKSUM, error);
}

#[test]
fn test_external_mailbox_nested_command() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    let inner = external_request(CommandId::VERSION.into(), 4, 0);
    let payload = inner.as_bytes().unwrap();
    let address = model.write_payload_to_ss_staging_area(payload, 0).unwrap();
    let request = external_request(
        CommandId::EXTERNAL_MAILBOX_CMD.into(),
        payload.len() as u32,
        address,
    );
    let error = model
        .mailbox_execute(
            CommandId::EXTERNAL_MAILBOX_CMD.into(),
            request.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND,
        error,
    );
}

#[test]
fn test_external_firmware_verify() {
    let (mut model, image_bundle) = run_rt_test_return_fw(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    let image = image_bundle.to_bytes().unwrap();
    let address = model
        .write_payload_to_ss_staging_area(&image, 4096)
        .unwrap();
    let request = external_request(
        CommandId::FIRMWARE_VERIFY.into(),
        image.len() as u32,
        address,
    );
    let response = model
        .mailbox_execute(
            CommandId::EXTERNAL_MAILBOX_CMD.into(),
            request.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let response = FirmwareVerifyResp::read_from_bytes(&response).unwrap();
    assert_eq!(response.verify_result, FirmwareVerifyResult::Success as u32);

    // A declared image smaller than the manifest must be rejected before DMA,
    // even when valid manifest bytes happen to exist at that address.
    let request = external_request(CommandId::FIRMWARE_VERIFY.into(), 4, address);
    let error = model
        .mailbox_execute(
            CommandId::EXTERNAL_MAILBOX_CMD.into(),
            request.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH,
        error,
    );
}

#[test]
fn test_external_firmware_load() {
    let (mut model, image_bundle) = run_rt_test_return_fw(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    let image = image_bundle.to_bytes().unwrap();
    let address = model
        .write_payload_to_ss_staging_area(&image, 4096)
        .unwrap();
    let request = external_request(CommandId::FIRMWARE_LOAD.into(), image.len() as u32, address);
    assert_eq!(
        model
            .mailbox_execute(
                CommandId::EXTERNAL_MAILBOX_CMD.into(),
                request.as_bytes().unwrap(),
            )
            .unwrap(),
        None
    );
    model.step_until_ready_for_runtime();
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
}

#[test]
#[cfg(not(feature = "fpga_subsystem"))]
fn test_external_mailbox_requires_subsystem_mode() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: false,
        ..Default::default()
    });
    let request = external_request(CommandId::VERSION.into(), 4, 0);
    let error = model
        .mailbox_execute(
            CommandId::EXTERNAL_MAILBOX_CMD.into(),
            request.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND,
        error,
    );
}

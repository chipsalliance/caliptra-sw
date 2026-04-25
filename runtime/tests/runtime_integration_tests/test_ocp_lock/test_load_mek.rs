// Licensed under the Apache-2.0 license

use crate::test_update_reset::update_fw;
use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, OcpLockGenerateMekReq,
    OcpLockGenerateMekResp, OcpLockInitializeMekSecretReq, OcpLockLoadMekReq, OcpLockLoadMekResp,
    WrappedKey, OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE, OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE,
};
use caliptra_builder::{firmware::APP_WITH_UART_OCP_LOCK_FPGA, ImageOptions};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_test::derive::{DoeInput, DoeOutput, Mek, OcpLockKeyLadderBuilder};

use zerocopy::{FromBytes, IntoBytes};

use super::{
    boot_ocp_lock_runtime, validate_ocp_lock_response, InitializeMekSecretParams, OcpLockBootParams,
};

const TEST_METADATA: [u8; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE] =
    [0xDE; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE];

const TEST_AUX: [u8; OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE] =
    [0xFE; OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE];

fn generate_test_mek() -> (Mek, WrappedKey) {
    let doe_out = DoeOutput::generate(&DoeInput::default());
    OcpLockKeyLadderBuilder::new(doe_out)
        .add_mdk()
        .add_hek([0xABDEu32; 8])
        .add_intermediate_mek_secret([0xAB; 32], [0xCD; 32])
        .generate_and_wrap_mek()
}

fn validate_failure_response(
    model: &mut DefaultHwModel,
    response: std::result::Result<Option<Vec<u8>>, ModelError>,
    expected_error: CaliptraError,
) {
    validate_ocp_lock_response(model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(expected_error.into())
        );
    });
}

fn initialize_mek_secret(model: &mut DefaultHwModel) {
    let mut cmd = MailboxReq::OcpLockInitializeMekSecret(OcpLockInitializeMekSecretReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        sek: [0xAB; 32],
        dpk: [0xCD; 32],
    });
    cmd.populate_chksum().unwrap();
    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(model, response, |response, _| {
        response.unwrap().unwrap();
    });
}

fn validate_success_response(
    model: &mut DefaultHwModel,
    response: std::result::Result<Option<Vec<u8>>, ModelError>,
    expected_mek: Option<&Mek>,
) {
    validate_ocp_lock_response(model, response, |response, actual_mek| {
        let response = response.unwrap().unwrap();
        let response = OcpLockLoadMekResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(caliptra_common::checksum::verify_checksum(
            response.hdr.chksum,
            0x0,
            &response.as_bytes()[core::mem::size_of_val(&response.hdr.chksum)..],
        ));

        // Verify FIPS status
        assert_eq!(
            response.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );

        // Check loaded MEK
        if let Some(x) = expected_mek {
            assert_eq!(actual_mek.unwrap().mek, x.mek);
        };
    });
}

fn update_reset(model: &mut DefaultHwModel) {
    update_fw(model, &APP_WITH_UART_OCP_LOCK_FPGA, ImageOptions::default());
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_timeout() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (_, wrapped_mek) = generate_test_mek();

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_failure_response(&mut model, response, CaliptraError::OCP_LOCK_ENGINE_TIMEOUT);
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_command_success_with_fresh_wrapped_mek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    // Generate a new MEK
    let mut cmd = MailboxReq::OcpLockGenerateMek(OcpLockGenerateMekReq::default());
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    let wrapped_mek = validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        response.wrapped_mek.clone()
    })
    .unwrap();

    // Initialize MEK Secret Seed
    initialize_mek_secret(&mut model);

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    // expected mek cannot be checked in this case as it is generated with GENERATE_MEK command
    validate_success_response(&mut model, response, None);
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_command_success_with_stored_wrapped_mek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (expected_mek, wrapped_mek) = generate_test_mek();

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_success_response(&mut model, response, Some(&expected_mek));
}

#[test]
fn test_load_mek_truncated_request() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (_, wrapped_mek) = generate_test_mek();

    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let payload = cmd.as_bytes().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_LOAD_MEK.into(),
        &payload[..payload.len() - 4],
    );

    validate_failure_response(
        &mut model,
        response,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
    );
}

#[test]
fn test_load_mek_request_with_trailing_zero() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (_, wrapped_mek) = generate_test_mek();

    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let mut payload = [0u8; size_of::<OcpLockLoadMekReq>() + 4];
    payload[..size_of::<OcpLockLoadMekReq>()].copy_from_slice(cmd.as_bytes().unwrap());

    let response = model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), &payload);

    validate_failure_response(
        &mut model,
        response,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
    );
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_invalid_tag() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (_, mut wrapped_mek) = generate_test_mek();
    wrapped_mek.ciphertext_and_auth_tag[0] ^= 0xFF;

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_failure_response(
        &mut model,
        response,
        CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG,
    );
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_without_init_mek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let (_, wrapped_mek) = generate_test_mek();

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_failure_response(
        &mut model,
        response,
        CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED,
    );
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_command_success_after_warm_reset() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (expected_mek, wrapped_mek) = generate_test_mek();

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_success_response(&mut model, response, Some(&expected_mek));

    // Warm reset
    model.warm_reset_flow().unwrap();

    // Initialize MEK Secret Seed
    initialize_mek_secret(&mut model);

    // Load MEK
    if let MailboxReq::OcpLockLoadMek(ref mut x) = cmd {
        x.metadata[0] ^= 0xFF;
    };
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_success_response(&mut model, response, Some(&expected_mek));
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_command_impersistent_mek_secret_across_warm_reset() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (expected_mek, wrapped_mek) = generate_test_mek();

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_success_response(&mut model, response, Some(&expected_mek));

    // Initialize MEK Secret Seed
    initialize_mek_secret(&mut model);

    // Warm reset
    model.warm_reset_flow().unwrap();

    // Load MEK
    if let MailboxReq::OcpLockLoadMek(ref mut x) = cmd {
        x.metadata[0] ^= 0xFF;
    };
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_failure_response(
        &mut model,
        response,
        CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED,
    );
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_command_success_after_update_reset() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (expected_mek, wrapped_mek) = generate_test_mek();

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_success_response(&mut model, response, Some(&expected_mek));

    // update reset
    update_reset(&mut model);

    // Initialize MEK Secret Seed
    initialize_mek_secret(&mut model);

    // Load MEK
    if let MailboxReq::OcpLockLoadMek(ref mut x) = cmd {
        x.metadata[0] ^= 0xFF;
    };
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_success_response(&mut model, response, Some(&expected_mek));
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_load_mek_command_impersistent_mek_secret_across_update_reset() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let (expected_mek, wrapped_mek) = generate_test_mek();

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_success_response(&mut model, response, Some(&expected_mek));

    // Initialize MEK Secret Seed
    initialize_mek_secret(&mut model);

    // update reset
    update_reset(&mut model);

    // Load MEK
    if let MailboxReq::OcpLockLoadMek(ref mut x) = cmd {
        x.metadata[0] ^= 0xFF;
    };
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_failure_response(
        &mut model,
        response,
        CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED,
    );
}

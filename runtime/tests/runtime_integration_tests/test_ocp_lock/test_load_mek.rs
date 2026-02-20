// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, OcpLockGenerateMekReq,
    OcpLockGenerateMekResp, OcpLockInitializeMekSecretReq, OcpLockLoadMekReq, OcpLockLoadMekResp,
    WrappedKey, OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE, OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use zerocopy::{FromBytes, IntoBytes};

use super::{
    boot_ocp_lock_runtime, validate_ocp_lock_response, InitializeMekSecretParams, OcpLockBootParams,
};

const TEST_METADATA: [u8; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE] =
    [0xDE; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE];

const TEST_AUX: [u8; OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE] =
    [0xFE; OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE];

const TEST_WRAPPED_KEY: WrappedKey = WrappedKey {
    key_type: 3,
    reserved: 0,
    salt: [30, 214, 237, 164, 200, 69, 3, 203, 175, 13, 69, 75],
    metadata_len: 0,
    key_len: 64,
    iv: [24, 237, 129, 52, 72, 158, 66, 92, 114, 211, 133, 181],
    metadata: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    ciphertext_and_auth_tag: [
        146, 117, 182, 89, 151, 228, 221, 161, 9, 160, 226, 73, 204, 228, 125, 119, 199, 51, 81,
        61, 121, 103, 52, 0, 1, 118, 212, 103, 110, 163, 171, 120, 223, 245, 19, 109, 227, 61, 252,
        254, 200, 28, 150, 176, 118, 167, 91, 183, 171, 149, 232, 229, 80, 213, 133, 214, 46, 93,
        11, 210, 29, 185, 222, 112, 73, 2, 82, 145, 201, 174, 173, 156, 173, 219, 81, 56, 253, 204,
        26, 177,
    ],
};

const TEST_EXPECTED_KEY: [u8; 64] = [
    241, 133, 218, 224, 96, 170, 19, 63, 28, 233, 192, 236, 234, 173, 171, 241, 75, 249, 228, 4,
    252, 249, 55, 149, 15, 245, 43, 224, 124, 242, 118, 215, 189, 182, 181, 148, 114, 124, 93, 102,
    223, 65, 35, 119, 85, 90, 113, 236, 123, 241, 231, 180, 191, 33, 20, 22, 188, 129, 156, 182,
    129, 139, 91, 156,
];

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
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

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek: TEST_WRAPPED_KEY,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::OCP_LOCK_ENGINE_TIMEOUT.into())
        );
    });
}

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
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

    validate_ocp_lock_response(&mut model, response, |response, _| {
        response.unwrap().unwrap();
    });

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

    validate_ocp_lock_response(&mut model, response, |response, _| {
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
    });
}

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
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

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek: TEST_WRAPPED_KEY,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_ocp_lock_response(&mut model, response, |response, actual_mek| {
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
        assert_eq!(actual_mek.unwrap().mek, TEST_EXPECTED_KEY);
    });
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

    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek: TEST_WRAPPED_KEY,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let payload = cmd.as_bytes().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_LOAD_MEK.into(),
        &payload[..payload.len() - 4],
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS.into())
        );
    });
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

    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek: TEST_WRAPPED_KEY,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let mut payload = [0u8; size_of::<OcpLockLoadMekReq>() + 4];
    payload[..size_of::<OcpLockLoadMekReq>()].copy_from_slice(cmd.as_bytes().unwrap());

    let response = model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), &payload);

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS.into())
        );
    });
}

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
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

    let mut wrapped_mek = TEST_WRAPPED_KEY.clone();
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

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG.into())
        );
    });
}

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
#[test]
fn test_load_mek_without_init_mek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    // Load MEK
    let mut cmd = MailboxReq::OcpLockLoadMek(OcpLockLoadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        wrapped_mek: TEST_WRAPPED_KEY,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_LOAD_MEK.into(), cmd.as_bytes().unwrap());

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into()
            )
        );
    });
}

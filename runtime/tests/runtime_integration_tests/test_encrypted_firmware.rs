// Licensed under the Apache-2.0 license

//! Tests for encrypted firmware flow using RI_DOWNLOAD_ENCRYPTED_FIRMWARE and CM_AES_GCM_DECRYPT_DMA

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use aes_gcm::{aead::AeadMutInPlace, Key, KeyInit};
use caliptra_api::mailbox::{
    CmAesGcmDecryptDmaReq, CmAesGcmDecryptDmaResp, CmImportReq, CmImportResp, CmKeyUsage,
    CommandId, MailboxReq, CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE,
};
use caliptra_auth_man_types::{AuthManifestImageMetadata, ImageMetadataFlags};
use caliptra_drivers::CaliptraError;
#[cfg(not(feature = "fpga_subsystem"))]
use caliptra_emu_bus::{Device, Event, EventData, RecoveryCommandCode};
#[cfg(not(feature = "fpga_subsystem"))]
use caliptra_hw_model::DefaultHwModel;
use caliptra_hw_model::{HwModel, InitParams, SubsystemInitParams, MCU_TEST_AES_KEY, MCU_TEST_IV};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::from_hw_format;
use caliptra_image_gen::ImageGeneratorCrypto;
use zerocopy::{FromBytes, IntoBytes};

const RT_READY_FOR_COMMANDS: u32 = 0x600;

#[cfg(not(feature = "fpga_subsystem"))]
fn read_recovery_register(
    model: &mut DefaultHwModel,
    command_code: RecoveryCommandCode,
) -> Vec<u8> {
    model
        .events_to_caliptra()
        .send(Event::new(
            Device::BMC,
            Device::CaliptraCore,
            EventData::RecoveryBlockReadRequest {
                source_addr: 0,
                target_addr: 0,
                command_code,
            },
        ))
        .unwrap();

    loop {
        model.step();
        for event in model.events_from_caliptra() {
            if let EventData::RecoveryBlockReadResponse {
                command_code: response_command_code,
                payload,
                ..
            } = event.event
            {
                if response_command_code == command_code {
                    return payload;
                }
            }
        }
    }
}

/// Encrypt data using AES-256-GCM, returning `ciphertext || 16-byte tag`.
fn aes_gcm_encrypt(key: &[u8; 32], iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key: &Key<aes_gcm::Aes256Gcm> = key.into();
    let mut cipher = aes_gcm::Aes256Gcm::new(key);
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(iv.into(), aad, &mut ciphertext)
        .expect("Encryption failed");
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

/// Test that the encrypted firmware boot flow works end-to-end:
/// 1. Encrypt MCU firmware with the test AES key / IV
/// 2. Boot with RI_DOWNLOAD_ENCRYPTED_FIRMWARE — the hw-model automatically
///    simulates MCU ROM decryption (CM_IMPORT + CM_AES_GCM_DECRYPT_DMA)
/// 3. Verify the decrypted firmware in SRAM matches the original plaintext
#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime",), ignore)]
#[test]
fn test_encrypted_firmware_decrypt_dma() {
    // The plaintext MCU firmware (240 bytes so that ciphertext+tag = 256,
    // a multiple of the FPGA BMC's 256-byte recovery FIFO block size).
    let mcu_fw_plaintext: Vec<u8> = (0..240).map(|i| i as u8).collect();

    // Encrypt with the well-known test key/IV (ciphertext || tag)
    let aad: [u8; 0] = [];
    let mcu_fw_image = aes_gcm_encrypt(&MCU_TEST_AES_KEY, &MCU_TEST_IV, &aad, &mcu_fw_plaintext);

    // Auth manifest digest must match what the recovery interface delivers,
    // which is the full image (ciphertext || tag).
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    // exec_bit 2 = MCU image. Caliptra runtime requires this to be set in
    // the manifest so ACTIVATE_FIRMWARE knows which FW_EXEC_CTRL bit to
    // publish for the MCU image during the post-decrypt activation step.
    flags.set_exec_bit(2);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw_image).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest_bytes = soc_manifest.as_bytes();

    // Boot with encrypted_boot — boot() handles the MCU ROM decrypt simulation.
    let rom = crate::common::rom_for_fw_integration_tests().unwrap();
    let args = RuntimeTestArgs {
        init_params: Some(InitParams {
            rom: &rom,
            subsystem_mode: true,
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: true,
                ..Default::default()
            },
            ..Default::default()
        }),
        soc_manifest: Some(soc_manifest_bytes),
        mcu_fw_image: Some(&mcu_fw_image),
        encrypted_boot: true,
        ..Default::default()
    };

    let mut model = run_rt_test(args);

    // boot() already waited for RT_READY_FOR_COMMANDS and decrypted;
    // this is a no-op but kept for clarity.
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    // Read back the decrypted firmware from MCU SRAM and verify.
    let decrypted_fw = model
        .read_payload_from_ss_staging_area(mcu_fw_plaintext.len(), 0)
        .unwrap();

    assert_eq!(
        decrypted_fw, mcu_fw_plaintext,
        "Decrypted firmware does not match original plaintext"
    );

    #[cfg(not(feature = "fpga_subsystem"))]
    {
        let device_status = read_recovery_register(&mut model, RecoveryCommandCode::DeviceStatus);
        assert_eq!(
            u32::from_le_bytes(device_status[..4].try_into().unwrap()),
            0x1
        );

        let recovery_status =
            read_recovery_register(&mut model, RecoveryCommandCode::RecoveryStatus);
        assert_eq!(
            u16::from_le_bytes(recovery_status[..2].try_into().unwrap()),
            0x3
        );
    }
}

#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_decrypt_dma_invalid_transfer() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    // Invalid transfer parameters must be rejected before key validation or DMA.
    for (address, length) in [
        (0, 0),
        (0, 1),
        (0, 2),
        (0, 3),
        (0, 4),
        (0, 8),
        (0, 12),
        (0, 20),
        (0, 28),
        (1, 16),
        (2, 16),
        (3, 16),
    ] {
        let mut request = MailboxReq::CmAesGcmDecryptDma(CmAesGcmDecryptDmaReq {
            axi_addr_lo: address,
            length,
            ..Default::default()
        });
        request.populate_chksum().unwrap();
        let error = model
            .mailbox_execute(
                CommandId::CM_AES_GCM_DECRYPT_DMA.into(),
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

#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_decrypt_dma_authentication() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    let mut input = [0; 64];
    input[..32].copy_from_slice(&MCU_TEST_AES_KEY);
    let mut import = MailboxReq::CmImport(CmImportReq {
        key_usage: CmKeyUsage::Aes.into(),
        input_size: 32,
        input,
        ..Default::default()
    });
    import.populate_chksum().unwrap();
    let imported = model
        .mailbox_execute(CommandId::CM_IMPORT.into(), import.as_bytes().unwrap())
        .unwrap()
        .unwrap();
    let cmk = CmImportResp::read_from_bytes(&imported).unwrap().cmk;
    // Ciphertext consists of full AES blocks; AAD remains byte-granular.
    let plaintext = [0x5a; 32];
    let aad = [1, 2, 3];
    let encrypted = aes_gcm_encrypt(&MCU_TEST_AES_KEY, &MCU_TEST_IV, &aad, &plaintext);
    let (ciphertext, tag) = encrypted.split_at(plaintext.len());
    let hash = openssl::sha::sha384(ciphertext);
    for case in [
        "partial_block",
        "bad_hash",
        "bad_aad_length",
        "bad_tag",
        "valid",
    ] {
        let address = model
            .write_payload_to_ss_staging_area(ciphertext, 256)
            .unwrap();
        let mut command = CmAesGcmDecryptDmaReq {
            cmk: cmk.clone(),
            iv: core::array::from_fn(|i| {
                u32::from_le_bytes(MCU_TEST_IV[i * 4..i * 4 + 4].try_into().unwrap())
            }),
            tag: core::array::from_fn(|i| {
                u32::from_le_bytes(tag[i * 4..i * 4 + 4].try_into().unwrap())
            }),
            encrypted_data_sha384: hash,
            axi_addr_lo: address as u32,
            axi_addr_hi: (address >> 32) as u32,
            length: ciphertext.len() as u32,
            aad_length: aad.len() as u32,
            ..Default::default()
        };
        command.aad[..aad.len()].copy_from_slice(&aad);
        let expected_error = match case {
            "partial_block" => {
                command.length = 20;
                Some(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)
            }
            "bad_hash" => {
                command.encrypted_data_sha384[0] ^= 1;
                Some(CaliptraError::RUNTIME_CMB_DMA_SHA384_MISMATCH)
            }
            "bad_aad_length" => {
                command.aad_length = CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE as u32 + 1;
                Some(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)
            }
            "bad_tag" => {
                command.tag[0] ^= 1;
                None
            }
            _ => None,
        };
        // Serialize the full request: the partial serializer rejects an
        // oversized AAD length before the firmware gets to validate it.
        command.hdr.chksum = caliptra_common::checksum::calc_checksum(
            CommandId::CM_AES_GCM_DECRYPT_DMA.into(),
            &command.as_bytes()[4..],
        );
        let response =
            model.mailbox_execute(CommandId::CM_AES_GCM_DECRYPT_DMA.into(), command.as_bytes());
        if let Some(error) = expected_error {
            assert_error(&mut model, error, response.unwrap_err());
        } else {
            let response = response.unwrap().unwrap();
            let response = CmAesGcmDecryptDmaResp::read_from_bytes(&response).unwrap();
            assert_eq!(response.tag_verified, u32::from(case == "valid"));
        }
        let data = model
            .read_payload_from_ss_staging_area(ciphertext.len(), 256)
            .unwrap();
        // Alignment/hash/AAD failures must not modify SRAM. A bad GCM tag is reported
        // after in-place decryption, so callers must not use that plaintext.
        assert_eq!(
            data,
            if expected_error.is_some() {
                ciphertext
            } else {
                &plaintext
            }
        );
    }
}

/// Test that CM_AES_GCM_DECRYPT_DMA fails when not in subsystem mode.
#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime",), ignore)]
#[test]
fn test_decrypt_dma_requires_subsystem_mode() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    if model.subsystem_mode() {
        return;
    }

    let mut cmd = MailboxReq::CmAesGcmDecryptDma(CmAesGcmDecryptDmaReq::default());
    cmd.populate_chksum().unwrap();

    let err = model
        .mailbox_execute(
            u32::from(CommandId::CM_AES_GCM_DECRYPT_DMA),
            cmd.as_bytes().unwrap(),
        )
        .expect_err("CM_AES_GCM_DECRYPT_DMA should fail outside subsystem mode");

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_CMB_DMA_NOT_SUBSYSTEM_MODE,
        err,
    );
}

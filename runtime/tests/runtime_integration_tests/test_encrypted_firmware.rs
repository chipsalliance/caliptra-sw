// Licensed under the Apache-2.0 license

//! Tests for encrypted firmware flow using RI_DOWNLOAD_ENCRYPTED_FIRMWARE and CM_AES_GCM_DECRYPT_DMA

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use aes_gcm::{aead::AeadMutInPlace, Key, KeyInit};
use caliptra_api::mailbox::{
    CmAesGcmDecryptDmaReq, CmImportReq, CmImportResp, CmKeyUsage, Cmk, CommandId, MailboxReq,
    MailboxReqHeader, MailboxRespHeader,
};
use caliptra_auth_man_types::{AuthManifestImageMetadata, ImageMetadataFlags};
use caliptra_hw_model::{HwModel, InitParams, SubsystemInitParams};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::from_hw_format;
use caliptra_image_gen::ImageGeneratorCrypto;
use zerocopy::{FromBytes, IntoBytes};

const RT_READY_FOR_COMMANDS: u32 = 0x600;

/// Import a raw AES key and return the CMK
fn import_aes_key(model: &mut caliptra_hw_model::DefaultHwModel, key: &[u8; 32]) -> Cmk {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(key);

    let mut cm_import_cmd = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_usage: CmKeyUsage::Aes.into(),
        input_size: 32,
        input,
    });
    cm_import_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CM_IMPORT),
            cm_import_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let cm_import_resp = CmImportResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        cm_import_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    cm_import_resp.cmk.clone()
}

/// Encrypt data using AES-256-GCM
fn aes_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let key: &Key<aes_gcm::Aes256Gcm> = key.into();
    let mut cipher = aes_gcm::Aes256Gcm::new(key);
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(iv.into(), aad, &mut ciphertext)
        .expect("Encryption failed");
    (ciphertext, tag.into())
}

/// Test that the encrypted firmware flow works correctly:
/// 1. Boot with RI_DOWNLOAD_ENCRYPTED_FIRMWARE (sends raw ciphertext as MCU image)
/// 2. Decrypt the MCU firmware in-place via the HwModel trait's default
///    decrypt_encrypted_mcu_firmware (CM_IMPORT + CM_AES_GCM_DECRYPT_DMA)
/// 3. Verify the decrypted firmware matches the original plaintext
#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime",), ignore)]
#[test]
fn test_encrypted_firmware_decrypt_dma() {
    // The plaintext MCU firmware
    let mcu_fw_plaintext: Vec<u8> = (0..256).map(|i| i as u8).collect();

    // AES-256 key and IV for encryption
    let aes_key: [u8; 32] = [0xaa; 32];
    let iv: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let aad: [u8; 0] = [];

    // Encrypt the MCU firmware
    let (mcu_fw_encrypted, tag) = aes_gcm_encrypt(&aes_key, &iv, &aad, &mcu_fw_plaintext);

    // The raw ciphertext is the MCU firmware image delivered via the recovery interface.
    // Caliptra RT downloads it to MCU SRAM and computes SHA384 over the delivered size.
    // The auth manifest digest must match.
    let mcu_fw_image = &mcu_fw_encrypted;

    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(mcu_fw_image).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest_bytes = soc_manifest.as_bytes();

    // Use the standard test infrastructure with encrypted_boot flag
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
        mcu_fw_image: Some(mcu_fw_image),
        encrypted_boot: true,
        ..Default::default()
    };

    let mut model = run_rt_test(args);
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    // Decrypt the encrypted MCU firmware in the staging area.
    // The default trait impl imports the AES key via CM_IMPORT, writes the ciphertext
    // to MCU SRAM at offset 0, and issues CM_AES_GCM_DECRYPT_DMA to decrypt in-place.
    model
        .decrypt_encrypted_mcu_firmware(&aes_key, &iv, &tag, &mcu_fw_encrypted)
        .expect("Failed to decrypt MCU firmware");

    // Read back the decrypted firmware from MCU SRAM offset 0.
    // decrypt_encrypted_mcu_firmware wrote the ciphertext at offset 0 and decrypted
    // it in-place, so the plaintext is at offset 0.
    let decrypted_fw = model
        .read_payload_from_ss_staging_area(mcu_fw_plaintext.len())
        .unwrap();

    // Verify the decrypted firmware matches the original plaintext
    assert_eq!(
        decrypted_fw, mcu_fw_plaintext,
        "Decrypted firmware does not match original plaintext"
    );
}

/// Test that CM_AES_GCM_DECRYPT_DMA fails when not in encrypted firmware mode
#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime",), ignore)]
#[test]
fn test_decrypt_dma_fails_in_normal_mode() {
    // Create a simple MCU firmware
    let mcu_fw = vec![1, 2, 3, 4];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest_bytes = soc_manifest.as_bytes();

    let mut args = RuntimeTestArgs::default();
    let rom = crate::common::rom_for_fw_integration_tests().unwrap();
    args.init_params = Some(InitParams {
        rom: &rom,
        subsystem_mode: true,
        ..Default::default()
    });
    args.soc_manifest = Some(soc_manifest_bytes);
    args.mcu_fw_image = Some(&mcu_fw);

    // Use normal boot (RI_DOWNLOAD_FIRMWARE, not encrypted)
    let mut model = run_rt_test(args);
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    // Import an AES key
    let aes_key: [u8; 32] = [0xaa; 32];
    let cmk = import_aes_key(&mut model, &aes_key);

    // Get MCU SRAM address
    let mcu_sram_addr = model
        .write_payload_to_ss_staging_area(&mcu_fw)
        .expect("Failed to get MCU SRAM address");

    // Try to use CM_AES_GCM_DECRYPT_DMA - should fail because we're not in encrypted firmware mode
    let decrypt_req = CmAesGcmDecryptDmaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cmk,
        iv: [0u32; 3],
        tag: [0u32; 4],
        encrypted_data_sha384: [0u8; 48],
        axi_addr_lo: mcu_sram_addr as u32,
        axi_addr_hi: (mcu_sram_addr >> 32) as u32,
        length: mcu_fw.len() as u32,
        aad_length: 0,
        aad: [0u8; caliptra_api::mailbox::CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE],
    };

    let mut decrypt_cmd = MailboxReq::CmAesGcmDecryptDma(decrypt_req);
    decrypt_cmd.populate_chksum().unwrap();

    // This should fail with RUNTIME_MAILBOX_INVALID_PARAMS because we're not in encrypted firmware mode
    let result = model.mailbox_execute(
        u32::from(CommandId::CM_AES_GCM_DECRYPT_DMA),
        decrypt_cmd.as_bytes().unwrap(),
    );
    assert!(
        result.is_err(),
        "CM_AES_GCM_DECRYPT_DMA should fail in normal boot mode"
    );
}

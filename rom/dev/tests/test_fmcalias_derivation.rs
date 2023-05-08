// Licensed under the Apache-2.0 license

use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, ROM_WITH_UART};
use caliptra_common::PcrLogEntry;
use caliptra_common::PcrLogEntryId::*;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, ModelError, SecurityState};
use caliptra_image_fake_keys::VENDOR_CONFIG_KEY_1;
use caliptra_image_gen::ImageGenerator;
use caliptra_image_openssl::OsslCrypto;
use caliptra_image_types::IMAGE_BYTE_SIZE;
use zerocopy::{AsBytes, FromBytes};

pub mod helpers;

// [TODO] Use the error codes from the common library.
const INVALID_IMAGE_SIZE: u32 = 0x01020003;

#[test]
fn test_zero_firmware_size() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Zero-sized firmware.
    assert_eq!(
        hw.upload_firmware(&[]).unwrap_err(),
        ModelError::MailboxCmdFailed(0x01020003)
    );
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        INVALID_IMAGE_SIZE
    );
}

#[test]
fn test_firmware_gt_max_size() {
    const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

    // Firmware size > 128 KB.

    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Manually put the oversize data in the mailbox because
    // HwModel::upload_firmware won't let us.
    assert!(!hw.soc_mbox().lock().read().lock());
    hw.soc_mbox().cmd().write(|_| FW_LOAD_CMD_OPCODE);
    hw.soc_mbox().dlen().write(|_| (IMAGE_BYTE_SIZE + 1) as u32);
    for i in 0..((IMAGE_BYTE_SIZE + 1 + 3) / 4) {
        hw.soc_mbox().datain().write(|_| i as u32);
    }
    hw.soc_mbox().execute().write(|w| w.execute(true));
    while hw.soc_mbox().status().read().status().cmd_busy() {
        hw.step();
    }
    hw.soc_mbox().execute().write(|w| w.execute(false));

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        INVALID_IMAGE_SIZE
    );
}

#[test]
fn test_pcr_log() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let mut vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let mut owner_pubkey_digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
    };

    let fuses = Fuses {
        anti_rollback_disable: true,
        key_manifest_pk_hash: vendor_pubkey_digest,
        owner_pk_hash: owner_pubkey_digest,
        ..Default::default()
    };
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        fw_image: None,
    })
    .unwrap();

    const FMC_SVN: u32 = 1;
    let image_options = ImageOptions {
        vendor_config: VENDOR_CONFIG_KEY_1,
        fmc_svn: FMC_SVN,
        ..Default::default()
    };
    let image_bundle =
        caliptra_builder::build_and_sign_image(&TEST_FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap();

    assert!(hw
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .is_ok());

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    let result = hw.mailbox_execute(0x1000_0000, &[]);
    assert!(result.is_ok());

    let pcr_entry_arr = result.unwrap().unwrap();
    let mut pcr_log_entry_offset = 0;
    // Check PCR entry for DeviceLifecycle.
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, DeviceLifecycle as u16);
    assert_eq!(pcr_log_entry.pcr_id, 0);
    let device_lifecycle = hw
        .soc_ifc()
        .cptra_security_state()
        .read()
        .device_lifecycle();
    assert_eq!(pcr_log_entry.pcr_data[0] as u8, device_lifecycle as u8);

    // Check PCR entry for DebugLocked
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, DebugLocked as u16);
    assert_eq!(pcr_log_entry.pcr_id, 0);
    let debug_locked = hw.soc_ifc().cptra_security_state().read().debug_locked();
    assert_eq!((pcr_log_entry.pcr_data[0] as u8) != 0, debug_locked);

    // Check PCR entry for AntiRollbackDisabled.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, AntiRollbackDisabled as u16);
    assert_eq!(pcr_log_entry.pcr_id, 0);
    let anti_rollback_disable = hw.soc_ifc().fuse_anti_rollback_disable().read().dis();
    assert_eq!(
        (pcr_log_entry.pcr_data[0] as u8) != 0,
        anti_rollback_disable
    );

    // Check PCR entry for VendorPubKeyHash.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, VendorPubKeyHash as u16);
    assert_eq!(pcr_log_entry.pcr_id, 0);
    helpers::change_dword_endianess(vendor_pubkey_digest.as_bytes_mut());
    assert_eq!(pcr_log_entry.pcr_data, vendor_pubkey_digest);

    // Check PCR entry for OwnerPubKeyHash.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, OwnerPubKeyHash as u16);
    assert_eq!(pcr_log_entry.pcr_id, 0);
    helpers::change_dword_endianess(owner_pubkey_digest.as_bytes_mut());
    assert_eq!(pcr_log_entry.pcr_data, owner_pubkey_digest);

    // Check PCR entry for VendorPubKeyIndex.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, VendorPubKeyIndex as u16);
    assert_eq!(pcr_log_entry.pcr_id, 0);
    assert_eq!(
        pcr_log_entry.pcr_data[0] as u8,
        VENDOR_CONFIG_KEY_1.ecc_key_idx as u8
    );

    // Check PCR entry for FmcTci.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, FmcTci as u16);
    assert_eq!(pcr_log_entry.pcr_id, 0);

    // Check PCR entry for FmcSvn.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, FmcSvn as u16);
    assert_eq!(pcr_log_entry.pcr_id, 0);
    assert_eq!(pcr_log_entry.pcr_data[0] as u8, FMC_SVN as u8);
}

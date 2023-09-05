// Licensed under the Apache-2.0 license

use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, ROM_WITH_UART};
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::RomBootStatus::ColdResetComplete;
use caliptra_common::RomBootStatus::*;
use caliptra_common::{FirmwareHandoffTable, FuseLogEntry, FuseLogEntryId};
use caliptra_common::{PcrLogEntry, PcrLogEntryId};
use caliptra_drivers::{ColdResetEntry4, PcrId, RomVerifyConfig};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, ModelError, SecurityState};
use caliptra_image_fake_keys::{OWNER_CONFIG, VENDOR_CONFIG_KEY_1};
use caliptra_image_gen::ImageGenerator;
use caliptra_image_openssl::OsslCrypto;
use caliptra_image_types::IMAGE_BYTE_SIZE;
use openssl::hash::{Hasher, MessageDigest};
use zerocopy::{AsBytes, FromBytes};
pub mod helpers;

#[test]
fn test_zero_firmware_size() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Zero-sized firmware.
    assert_eq!(
        hw.upload_firmware(&[]).unwrap_err(),
        ModelError::MailboxCmdFailed(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE.into())
    );
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        CaliptraError::FW_PROC_INVALID_IMAGE_SIZE.into()
    );
    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        LDevIdDerivationComplete.into()
    );
}

#[test]
fn test_firmware_gt_max_size() {
    // Firmware size > 128 KB.

    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Manually put the oversize data in the mailbox because
    // HwModel::upload_firmware won't let us.
    assert!(!hw.soc_mbox().lock().read().lock());
    hw.soc_mbox()
        .cmd()
        .write(|_| CommandId::FIRMWARE_LOAD.into());
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
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        CaliptraError::FW_PROC_INVALID_IMAGE_SIZE.into()
    );
    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        LDevIdDerivationComplete.into()
    );
}

const PCR_COUNT: usize = 32;
const PCR_ENTRY_SIZE: usize = core::mem::size_of::<PcrLogEntry>();

// Checks entries for both PCR0 and PCR1. Skips checking `data` if empty.
fn check_pcr_log_entry(
    pcr_entry_arr: &[u8],
    pcr_entry_index: usize,
    entry_id: PcrLogEntryId,
    data: &[u8],
) {
    let offset = pcr_entry_index * PCR_ENTRY_SIZE;
    let entry = PcrLogEntry::read_from_prefix(pcr_entry_arr[offset..].as_bytes()).unwrap();

    assert_eq!(entry.id, entry_id as u16);
    assert_eq!(
        entry.pcr_ids,
        (1 << PcrId::PcrId0 as u8) | (1 << PcrId::PcrId1 as u8)
    );

    if !data.is_empty() {
        assert_eq!(entry.measured_data(), data);
    }
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
        features: &["emu", "interactive_test_fmc"],
        workspace_dir: None,
    };

    let fuses = Fuses {
        anti_rollback_disable: true,
        lms_verify: true,
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
        ..Default::default()
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

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let pcr_entry_arr = hw.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();

    let device_lifecycle = hw
        .soc_ifc()
        .cptra_security_state()
        .read()
        .device_lifecycle();

    check_pcr_log_entry(
        &pcr_entry_arr,
        0,
        PcrLogEntryId::DeviceLifecycle,
        &[device_lifecycle as u8],
    );

    let debug_locked = hw.soc_ifc().cptra_security_state().read().debug_locked();

    check_pcr_log_entry(
        &pcr_entry_arr,
        1,
        PcrLogEntryId::DebugLocked,
        &[debug_locked as u8],
    );

    let anti_rollback_disable = hw.soc_ifc().fuse_anti_rollback_disable().read().dis();

    check_pcr_log_entry(
        &pcr_entry_arr,
        2,
        PcrLogEntryId::AntiRollbackDisabled,
        &[anti_rollback_disable as u8],
    );

    helpers::change_dword_endianess(vendor_pubkey_digest.as_bytes_mut());

    check_pcr_log_entry(
        &pcr_entry_arr,
        3,
        PcrLogEntryId::VendorPubKeyHash,
        vendor_pubkey_digest.as_bytes(),
    );

    helpers::change_dword_endianess(owner_pubkey_digest.as_bytes_mut());

    check_pcr_log_entry(
        &pcr_entry_arr,
        4,
        PcrLogEntryId::OwnerPubKeyHash,
        owner_pubkey_digest.as_bytes(),
    );

    check_pcr_log_entry(
        &pcr_entry_arr,
        5,
        PcrLogEntryId::EccVendorPubKeyIndex,
        &[VENDOR_CONFIG_KEY_1.ecc_key_idx as u8],
    );

    check_pcr_log_entry(&pcr_entry_arr, 6, PcrLogEntryId::FmcTci, &[]);

    check_pcr_log_entry(&pcr_entry_arr, 7, PcrLogEntryId::FmcSvn, &[FMC_SVN as u8]);

    check_pcr_log_entry(&pcr_entry_arr, 8, PcrLogEntryId::FmcFuseSvn, &[0_u8]);

    check_pcr_log_entry(
        &pcr_entry_arr,
        9,
        PcrLogEntryId::LmsVendorPubKeyIndex,
        &[VENDOR_CONFIG_KEY_1.lms_key_idx as u8],
    );

    check_pcr_log_entry(
        &pcr_entry_arr,
        10,
        PcrLogEntryId::RomVerifyConfig,
        &[RomVerifyConfig::EcdsaAndLms as u8],
    );
}

#[test]
fn test_pcr_log_fmc_fuse_svn() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let owner_pubkey_digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu", "interactive_test_fmc"],
        workspace_dir: None,
    };

    const FMC_SVN: u32 = 3;
    const FMC_FUSE_SVN: u32 = 2;

    let fuses = Fuses {
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        owner_pk_hash: owner_pubkey_digest,
        fmc_key_manifest_svn: FMC_FUSE_SVN,
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
        ..Default::default()
    })
    .unwrap();

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

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let pcr_entry_arr = hw.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();

    check_pcr_log_entry(&pcr_entry_arr, 7, PcrLogEntryId::FmcSvn, &[FMC_SVN as u8]);

    check_pcr_log_entry(
        &pcr_entry_arr,
        8,
        PcrLogEntryId::FmcFuseSvn,
        &[FMC_FUSE_SVN as u8],
    );
}

// Computes the PCR from the log.
fn hash_pcr_log_entries(initial_pcr: &[u8; 48], pcr_entry_arr: &[u8], pcr_id: PcrId) -> [u8; 48] {
    let mut offset: usize = 0;
    let mut pcr: [u8; 48] = *initial_pcr;

    assert_eq!(pcr_entry_arr.len() % PCR_ENTRY_SIZE, 0);

    loop {
        if offset == pcr_entry_arr.len() {
            break;
        }

        let entry = PcrLogEntry::read_from_prefix(pcr_entry_arr[offset..].as_bytes()).unwrap();
        offset += PCR_ENTRY_SIZE;

        if (entry.pcr_ids & (1 << pcr_id as u8)) == 0 {
            continue;
        }

        let mut hasher = Hasher::new(MessageDigest::sha384()).unwrap();
        hasher.update(&pcr).unwrap();
        hasher.update(entry.measured_data()).unwrap();
        let digest: &[u8] = &hasher.finish().unwrap();

        pcr.copy_from_slice(digest);
    }

    pcr
}

#[test]
fn test_pcr_log_across_update_reset() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let owner_pubkey_digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu", "interactive_test_fmc"],
        workspace_dir: None,
    };

    const FMC_SVN: u32 = 2;
    const FMC_FUSE_SVN: u32 = 1;

    let fuses = Fuses {
        anti_rollback_disable: false,
        fmc_key_manifest_svn: FMC_FUSE_SVN,
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
        ..Default::default()
    })
    .unwrap();

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

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let pcr_entry_arr = hw.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();

    // Fetch and validate PCR values against the log.

    let pcrs = hw.mailbox_execute(0x1000_0006, &[]).unwrap().unwrap();
    assert_eq!(pcrs.len(), PCR_COUNT * 48);

    let mut pcr0_from_hw: [u8; 48] = pcrs[0..48].try_into().unwrap();
    let mut pcr1_from_hw: [u8; 48] = pcrs[48..96].try_into().unwrap();

    helpers::change_dword_endianess(&mut pcr0_from_hw);
    helpers::change_dword_endianess(&mut pcr1_from_hw);

    let pcr0_from_log = hash_pcr_log_entries(&[0; 48], &pcr_entry_arr, PcrId::PcrId0);
    let pcr1_from_log = hash_pcr_log_entries(&[0; 48], &pcr_entry_arr, PcrId::PcrId1);

    assert_eq!(pcr0_from_log, pcr0_from_hw);
    assert_eq!(pcr1_from_log, pcr1_from_hw);

    // Ensure all other PCRs are empty.
    for i in 2..PCR_COUNT {
        let offset = i * 48;
        assert_eq!(pcrs[offset..offset + 48], [0; 48]);
    }

    // Trigger an update reset.
    hw.mailbox_execute(0x1000_0004, &[]).unwrap();
    hw.step_until_boot_status(UpdateResetStarted.into(), true);
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    hw.step_until_boot_status(UpdateResetComplete.into(), true);

    let pcr_entry_arr = hw.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();

    // Fetch and validate PCR values against the log. PCR0 should represent the
    // latest boot, while PCR1 should represent the whole journey.

    let pcrs_after_reset = hw.mailbox_execute(0x1000_0006, &[]).unwrap().unwrap();
    assert_eq!(pcrs_after_reset.len(), PCR_COUNT * 48);

    let mut new_pcr0_from_hw: [u8; 48] = pcrs_after_reset[0..48].try_into().unwrap();
    let mut new_pcr1_from_hw: [u8; 48] = pcrs_after_reset[48..96].try_into().unwrap();

    helpers::change_dword_endianess(&mut new_pcr0_from_hw);
    helpers::change_dword_endianess(&mut new_pcr1_from_hw);

    let new_pcr0_from_log = hash_pcr_log_entries(&[0; 48], &pcr_entry_arr, PcrId::PcrId0);
    let new_pcr1_from_log = hash_pcr_log_entries(&pcr1_from_log, &pcr_entry_arr, PcrId::PcrId1);

    assert_eq!(new_pcr0_from_log, new_pcr0_from_hw);
    assert_eq!(new_pcr1_from_log, new_pcr1_from_hw);

    // Also ensure PCR locks are configured correctly.
    let reset_checks = hw.mailbox_execute(0x1000_0007, &[]).unwrap().unwrap();
    assert_eq!(reset_checks, [0; 4]);

    let pcrs_after_clear = hw.mailbox_execute(0x1000_0006, &[]).unwrap().unwrap();
    assert_eq!(pcrs_after_clear, pcrs_after_reset);
}

#[test]
fn test_fuse_log() {
    const FMC_SVN: u32 = 4;
    const FMC_MIN_SVN: u32 = 2;

    let fuses = Fuses {
        anti_rollback_disable: true,
        fmc_key_manifest_svn: 0x0F,  // Value of FMC_SVN
        runtime_svn: [0xF, 0, 0, 0], // Value of RT_SVN
        lms_verify: true,
        ..Default::default()
    };

    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    let image_options = ImageOptions {
        vendor_config: VENDOR_CONFIG_KEY_1,
        owner_config: Some(OWNER_CONFIG),
        fmc_svn: FMC_SVN,
        fmc_min_svn: FMC_MIN_SVN,
        fmc_version: 0,
        app_svn: FMC_SVN,
        app_min_svn: FMC_MIN_SVN,
        app_version: 0,
    };
    let image_bundle =
        caliptra_builder::build_and_sign_image(&TEST_FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap();

    assert!(hw
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .is_ok());

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let result = hw.mailbox_execute(0x1000_0002, &[]);
    assert!(result.is_ok());

    let fuse_entry_arr = result.unwrap().unwrap();

    let mut fuse_log_entry_offset = 0;

    // Check entry for VendorPubKeyIndex.
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();

    assert_eq!(
        fuse_log_entry.entry_id,
        FuseLogEntryId::VendorEccPubKeyIndex as u32
    );

    assert_eq!(fuse_log_entry.log_data[0], VENDOR_CONFIG_KEY_1.ecc_key_idx);

    // Validate that the ID is VendorPubKeyRevocation
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(
        fuse_log_entry.entry_id,
        FuseLogEntryId::VendorEccPubKeyRevocation as u32
    );
    assert_eq!(fuse_log_entry.log_data[0], 0,);

    // Validate the ManifestFmcSvn
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(
        fuse_log_entry.entry_id,
        FuseLogEntryId::ManifestFmcSvn as u32
    );
    assert_eq!(fuse_log_entry.log_data[0], FMC_SVN);

    // Validate the ManifestFmcMinSvn
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(
        fuse_log_entry.entry_id,
        FuseLogEntryId::ManifestFmcMinSvn as u32
    );
    assert_eq!(fuse_log_entry.log_data[0], FMC_MIN_SVN);

    // Validate the FuseFmcSvn
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(fuse_log_entry.entry_id, FuseLogEntryId::FuseFmcSvn as u32);
    assert_eq!(fuse_log_entry.log_data[0], FMC_SVN);

    // Validate the ManifestRtSvn
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(
        fuse_log_entry.entry_id,
        FuseLogEntryId::ManifestRtSvn as u32
    );
    assert_eq!(fuse_log_entry.log_data[0], FMC_SVN);

    // Validate the ManifestRtMinSvn
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(
        fuse_log_entry.entry_id,
        FuseLogEntryId::ManifestRtMinSvn as u32
    );
    assert_eq!(fuse_log_entry.log_data[0], FMC_MIN_SVN);

    // Validate the FuseRtSvn
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(fuse_log_entry.entry_id, FuseLogEntryId::FuseRtSvn as u32);
    assert_eq!(fuse_log_entry.log_data[0], FMC_SVN);

    // Validate the VendorLmsPubKeyIndex
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(
        fuse_log_entry.entry_id,
        FuseLogEntryId::VendorLmsPubKeyIndex as u32
    );
    assert_eq!(fuse_log_entry.log_data[0], VENDOR_CONFIG_KEY_1.lms_key_idx);

    // Validate that the ID is VendorPubKeyRevocation
    fuse_log_entry_offset += core::mem::size_of::<FuseLogEntry>();
    let fuse_log_entry =
        FuseLogEntry::read_from_prefix(fuse_entry_arr[fuse_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(
        fuse_log_entry.entry_id,
        FuseLogEntryId::VendorLmsPubKeyRevocation as u32
    );
    assert_eq!(fuse_log_entry.log_data[0], 0,);
}

#[test]
fn test_fht_info() {
    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fuses: Fuses::default(),
        ..Default::default()
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    assert!(hw
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .is_ok());

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let result = hw.mailbox_execute(0x1000_0003, &[]);
    assert!(result.is_ok());

    let data = result.unwrap().unwrap();
    let fht = FirmwareHandoffTable::read_from_prefix(data.as_bytes()).unwrap();
    assert_eq!(fht.ldevid_tbs_size, 533);
    assert_eq!(fht.fmcalias_tbs_size, 745);
    assert_eq!(fht.ldevid_tbs_addr, 0x50003800);
    assert_eq!(fht.fmcalias_tbs_addr, 0x50003C00);
    assert_eq!(fht.pcr_log_addr, 0x50004400);
    assert_eq!(fht.fuse_log_addr, 0x50004800);
}

#[test]
fn test_check_no_lms_info_in_datavault_on_lms_unavailable() {
    let (_hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };

    let fuses = Fuses {
        lms_verify: false,
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
        ..Default::default()
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    assert!(hw
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .is_ok());

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let result = hw.mailbox_execute(0x1000_0005, &[]);
    assert!(result.is_ok());

    let coldresetentry4_array = result.unwrap().unwrap();
    let mut coldresetentry4_offset = core::mem::size_of::<u32>() * 8; // Skip first 4 entries

    // Check LmsVendorPubKeyIndex datavault value.
    let coldresetentry4_id =
        u32::read_from_prefix(coldresetentry4_array[coldresetentry4_offset..].as_bytes()).unwrap();
    assert_eq!(
        coldresetentry4_id,
        ColdResetEntry4::LmsVendorPubKeyIndex as u32
    );
    coldresetentry4_offset += core::mem::size_of::<u32>();
    let coldresetentry4_value =
        u32::read_from_prefix(coldresetentry4_array[coldresetentry4_offset..].as_bytes()).unwrap();
    assert_eq!(coldresetentry4_value, u32::MAX);
}

#[test]
fn test_check_rom_cold_boot_status_reg() {
    let (_hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };

    let fuses = Fuses {
        lms_verify: false,
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
        ..Default::default()
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    assert!(hw
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .is_ok());

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let result = hw.mailbox_execute(0x1000_0005, &[]);
    assert!(result.is_ok());

    let coldresetentry4_array = result.unwrap().unwrap();
    let mut coldresetentry4_offset = core::mem::size_of::<u32>() * 2; // Skip first entry

    // Check RomColdBootStatus datavault value.
    let coldresetentry4_id =
        u32::read_from_prefix(coldresetentry4_array[coldresetentry4_offset..].as_bytes()).unwrap();
    assert_eq!(
        coldresetentry4_id,
        ColdResetEntry4::RomColdBootStatus as u32
    );
    coldresetentry4_offset += core::mem::size_of::<u32>();
    let coldresetentry4_value =
        u32::read_from_prefix(coldresetentry4_array[coldresetentry4_offset..].as_bytes()).unwrap();
    assert_eq!(coldresetentry4_value, ColdResetComplete.into());
}

// Licensed under the Apache-2.0 license
use caliptra_builder::{FwId, ImageOptions, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_drivers::{
    pcr_log::{PcrLogEntry, PcrLogEntryId},
    FirmwareHandoffTable, PcrId,
};
use caliptra_hw_model::{BootParams, HwModel, InitParams};

use zerocopy::{AsBytes, FromBytes};

use openssl::hash::{Hasher, MessageDigest};

const TEST_CMD_READ_PCR_LOG: u32 = 0x1000_0000;
const TEST_CMD_READ_FHT: u32 = 0x1000_0001;

const RT_ALIAS_MEASUREMENT_COMPLETE: u32 = 0x400;
const RT_ALIAS_DERIVED_CDI_COMPLETE: u32 = 0x401;
const RT_ALIAS_KEY_PAIR_DERIVATION_COMPLETE: u32 = 0x402;
const RT_ALIAS_SUBJ_ID_SN_GENERATION_COMPLETE: u32 = 0x403;
const RT_ALIAS_SUBJ_KEY_ID_GENERATION_COMPLETE: u32 = 0x404;
const RT_ALIAS_CERT_SIG_GENERATION_COMPLETE: u32 = 0x405;
const RT_ALIAS_DERIVATION_COMPLETE: u32 = 0x406;

const PCR_COUNT: usize = 32;
const PCR_ENTRY_SIZE: usize = core::mem::size_of::<PcrLogEntry>();

#[test]
fn test_boot_status_reporting() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    pub const MOCK_RT_WITH_UART: FwId = FwId {
        crate_name: "caliptra-fmc-mock-rt",
        bin_name: "caliptra-fmc-mock-rt",
        features: &["emu"],
        workspace_dir: None,
    };

    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MOCK_RT_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    hw.step_until_boot_status(RT_ALIAS_MEASUREMENT_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_DERIVED_CDI_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_KEY_PAIR_DERIVATION_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_SUBJ_ID_SN_GENERATION_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_SUBJ_KEY_ID_GENERATION_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_CERT_SIG_GENERATION_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_DERIVATION_COMPLETE, true);
}

#[test]
fn test_fht_info() {
    pub const MOCK_RT_WITH_UART: FwId = FwId {
        crate_name: "caliptra-fmc-mock-rt",
        bin_name: "caliptra-fmc-mock-rt",
        features: &["emu", "interactive_test"],
        workspace_dir: None,
    };
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MOCK_RT_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    let result = hw.mailbox_execute(TEST_CMD_READ_FHT, &[]);
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
fn test_pcr_log() {
    pub const MOCK_RT_WITH_UART: FwId = FwId {
        crate_name: "caliptra-fmc-mock-rt",
        bin_name: "caliptra-fmc-mock-rt",
        features: &["emu", "interactive_test"],
        workspace_dir: None,
    };
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MOCK_RT_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    let result = hw.mailbox_execute(TEST_CMD_READ_FHT, &[]);
    assert!(result.is_ok());

    let data = result.unwrap().unwrap();
    let fht = FirmwareHandoffTable::read_from_prefix(data.as_bytes()).unwrap();

    let pcr_entry_arr = hw
        .mailbox_execute(TEST_CMD_READ_PCR_LOG, &[])
        .unwrap()
        .unwrap();

    // Check PCR entry for RtTci.
    let mut pcr_log_entry_offset = (fht.pcr_log_index as usize) * PCR_ENTRY_SIZE;

    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, PcrLogEntryId::RtTci as u16);
    assert_eq!(
        pcr_log_entry.pcr_ids,
        1 << (caliptra_common::RT_FW_CURRENT_PCR as u8)
    );

    // Check PCR entry for Manifest digest.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, PcrLogEntryId::FwImageManifest as u16);
    assert_eq!(
        pcr_log_entry.pcr_ids,
        1 << (caliptra_common::RT_FW_CURRENT_PCR as u8)
    );

    // Check PCR entry for RtTci.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();

    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, PcrLogEntryId::RtTci as u16);
    assert_eq!(
        pcr_log_entry.pcr_ids,
        1 << (caliptra_common::RT_FW_JOURNEY_PCR as u8)
    );

    // Check PCR entry for Manifest digest.
    pcr_log_entry_offset += PCR_ENTRY_SIZE;
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, PcrLogEntryId::FwImageManifest as u16);
    assert_eq!(
        pcr_log_entry.pcr_ids,
        1 << (caliptra_common::RT_FW_JOURNEY_PCR as u8)
    );

    // Fetch and validate PCR values against the log.
    let pcrs = hw.mailbox_execute(0x1000_0002, &[]).unwrap().unwrap();
    assert_eq!(pcrs.len(), PCR_COUNT * 48);
    let mut pcr2_from_hw: [u8; 48] = pcrs[(2 * 48)..(3 * 48)].try_into().unwrap();
    let mut pcr3_from_hw: [u8; 48] = pcrs[(3 * 48)..(4 * 48)].try_into().unwrap();

    change_dword_endianess(&mut pcr2_from_hw);
    change_dword_endianess(&mut pcr3_from_hw);

    let pcr2_from_log = hash_pcr_log_entries(&[0; 48], &pcr_entry_arr, PcrId::PcrId2);
    let pcr3_from_log = hash_pcr_log_entries(&[0; 48], &pcr_entry_arr, PcrId::PcrId3);

    assert_eq!(pcr2_from_log, pcr2_from_hw);
    assert_eq!(pcr3_from_log, pcr3_from_hw);

    hw.soc_ifc()
        .internal_fw_update_reset()
        .write(|w| w.core_rst(true));

    assert!(hw.upload_firmware(&image.to_bytes().unwrap()).is_ok());

    hw.step_until_boot_status(RT_ALIAS_DERIVATION_COMPLETE, true);

    let pcr_entry_arr = hw
        .mailbox_execute(TEST_CMD_READ_PCR_LOG, &[])
        .unwrap()
        .unwrap();

    // Check PCR entry for RtTci.
    let mut pcr_log_entry_offset =
        (fht.pcr_log_index as usize) * core::mem::size_of::<PcrLogEntry>();

    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, PcrLogEntryId::RtTci as u16);
    assert_eq!(
        pcr_log_entry.pcr_ids,
        1 << (caliptra_common::RT_FW_CURRENT_PCR as u8)
    );

    // Check PCR entry for Manifest digest.
    pcr_log_entry_offset += PCR_ENTRY_SIZE;
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, PcrLogEntryId::FwImageManifest as u16);
    assert_eq!(
        pcr_log_entry.pcr_ids,
        1 << (caliptra_common::RT_FW_CURRENT_PCR as u8)
    );

    // Check PCR entry for RtTci.
    pcr_log_entry_offset += core::mem::size_of::<PcrLogEntry>();

    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, PcrLogEntryId::RtTci as u16);
    assert_eq!(
        pcr_log_entry.pcr_ids,
        1 << (caliptra_common::RT_FW_JOURNEY_PCR as u8)
    );

    // Check PCR entry for Manifest digest.
    pcr_log_entry_offset += PCR_ENTRY_SIZE;
    let pcr_log_entry =
        PcrLogEntry::read_from_prefix(pcr_entry_arr[pcr_log_entry_offset..].as_bytes()).unwrap();
    assert_eq!(pcr_log_entry.id, PcrLogEntryId::FwImageManifest as u16);
    assert_eq!(
        pcr_log_entry.pcr_ids,
        1 << (caliptra_common::RT_FW_JOURNEY_PCR as u8)
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

pub fn change_dword_endianess(data: &mut [u8]) {
    for idx in (0..data.len()).step_by(4) {
        data.swap(idx, idx + 3);
        data.swap(idx + 1, idx + 2);
    }
}

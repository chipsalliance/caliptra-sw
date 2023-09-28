// Licensed under the Apache-2.0 license
use caliptra_builder::{
    firmware::{self, fmc_tests::MOCK_RT_INTERACTIVE, FMC_WITH_UART, ROM_WITH_UART},
    ImageOptions,
};
use caliptra_drivers::{
    pcr_log::{PcrLogEntry, PcrLogEntryId},
    FirmwareHandoffTable, PcrId,
};
use caliptra_hw_model::{BootParams, HwModel, InitParams};

use caliptra_test::swap_word_bytes;
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

const PCR2_AND_PCR3_EXTENDED_ID: u32 = (1 << PcrId::PcrId2 as u8) | (1 << PcrId::PcrId3 as u8);

#[test]
fn test_boot_status_reporting() {
    let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();

    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::fmc_tests::MOCK_RT_WITH_UART,
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
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MOCK_RT_INTERACTIVE,
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

    let data = hw.mailbox_execute(TEST_CMD_READ_FHT, &[]).unwrap().unwrap();
    let fht = FirmwareHandoffTable::read_from_prefix(data.as_bytes()).unwrap();
    assert_eq!(fht.ldevid_tbs_size, 533);
    assert_eq!(fht.fmcalias_tbs_size, 769);
    assert_eq!(fht.ldevid_tbs_addr, 0x50003C00);
    assert_eq!(fht.fmcalias_tbs_addr, 0x50004000);
    assert_eq!(fht.pcr_log_addr, 0x50004800);
    assert_eq!(fht.meas_log_addr, 0x50004C00);
    assert_eq!(fht.fuse_log_addr, 0x50005000);
}

#[test]
fn test_pcr_log() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image1 = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MOCK_RT_INTERACTIVE,
        ImageOptions {
            app_version: 1,
            ..Default::default()
        },
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image1.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    let data = hw.mailbox_execute(TEST_CMD_READ_FHT, &[]).unwrap().unwrap();
    let fht = FirmwareHandoffTable::read_from_prefix(data.as_bytes()).unwrap();

    let pcr_entry_arr = hw
        .mailbox_execute(TEST_CMD_READ_PCR_LOG, &[])
        .unwrap()
        .unwrap();

    assert_eq!(
        pcr_entry_arr.len(),
        (fht.pcr_log_index as usize) * PCR_ENTRY_SIZE
    );

    let rt_tci1 = swap_word_bytes(&image1.manifest.runtime.digest);
    let manifest_digest1 = openssl::sha::sha384(image1.manifest.as_bytes());

    check_pcr_log_entry(
        &pcr_entry_arr,
        fht.pcr_log_index - 2,
        PcrLogEntryId::RtTci,
        PCR2_AND_PCR3_EXTENDED_ID,
        rt_tci1.as_bytes(),
    );

    check_pcr_log_entry(
        &pcr_entry_arr,
        fht.pcr_log_index - 1,
        PcrLogEntryId::FwImageManifest,
        PCR2_AND_PCR3_EXTENDED_ID,
        &manifest_digest1,
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

    let image2 = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MOCK_RT_INTERACTIVE,
        ImageOptions {
            app_version: 2,
            ..Default::default()
        },
    )
    .unwrap();

    assert!(hw.upload_firmware(&image2.to_bytes().unwrap()).is_ok());

    hw.step_until_boot_status(RT_ALIAS_DERIVATION_COMPLETE, true);

    let pcr_entry_arr = hw
        .mailbox_execute(TEST_CMD_READ_PCR_LOG, &[])
        .unwrap()
        .unwrap();

    assert_eq!(
        pcr_entry_arr.len(),
        (fht.pcr_log_index as usize) * PCR_ENTRY_SIZE
    );

    let rt_tci2 = swap_word_bytes(&image2.manifest.runtime.digest);
    let manifest_digest2 = openssl::sha::sha384(image2.manifest.as_bytes());

    check_pcr_log_entry(
        &pcr_entry_arr,
        fht.pcr_log_index - 2,
        PcrLogEntryId::RtTci,
        PCR2_AND_PCR3_EXTENDED_ID,
        rt_tci2.as_bytes(),
    );

    check_pcr_log_entry(
        &pcr_entry_arr,
        fht.pcr_log_index - 1,
        PcrLogEntryId::FwImageManifest,
        PCR2_AND_PCR3_EXTENDED_ID,
        &manifest_digest2,
    );

    let pcr2_from_log = hash_pcr_log_entries(&[0; 48], &pcr_entry_arr, PcrId::PcrId2);
    let pcr3_from_log = hash_pcr_log_entries(&pcr3_from_log, &pcr_entry_arr, PcrId::PcrId3);

    // Fetch and validate PCR values against the log.
    let pcrs = hw.mailbox_execute(0x1000_0002, &[]).unwrap().unwrap();
    assert_eq!(pcrs.len(), PCR_COUNT * 48);
    let mut pcr2_from_hw: [u8; 48] = pcrs[(2 * 48)..(3 * 48)].try_into().unwrap();
    let mut pcr3_from_hw: [u8; 48] = pcrs[(3 * 48)..(4 * 48)].try_into().unwrap();

    change_dword_endianess(&mut pcr2_from_hw);
    change_dword_endianess(&mut pcr3_from_hw);

    assert_eq!(pcr2_from_log, pcr2_from_hw);
    assert_eq!(pcr3_from_log, pcr3_from_hw);
}

fn check_pcr_log_entry(
    pcr_entry_arr: &[u8],
    pcr_entry_index: u32,
    entry_id: PcrLogEntryId,
    pcr_ids: u32,
    pcr_data: &[u8],
) {
    let offset = pcr_entry_index as usize * PCR_ENTRY_SIZE;
    let entry = PcrLogEntry::read_from_prefix(pcr_entry_arr[offset..].as_bytes()).unwrap();

    assert_eq!(entry.id, entry_id as u16);
    assert_eq!(entry.pcr_ids, pcr_ids);
    assert_eq!(entry.measured_data(), pcr_data);
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

fn change_dword_endianess(data: &mut [u8]) {
    for idx in (0..data.len()).step_by(4) {
        data.swap(idx, idx + 3);
        data.swap(idx + 1, idx + 2);
    }
}

// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    firmware::{self, runtime_tests::MBOX, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{CommandId, FwInfoResp, MailboxReqHeader, MailboxRespHeader};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState,
};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::ImageGenerator;
use caliptra_image_types::RomInfo;
use caliptra_test::image_pk_desc_hash;
use dpe::DPE_PROFILE;
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_rt_journey_pcr_validation() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            ..Default::default()
        },
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let _ = model
        .mailbox_execute(0xD000_0000, &[0u8; DPE_PROFILE.get_tci_size()])
        .unwrap()
        .unwrap();

    // Perform warm reset
    model.warm_reset_flow(&boot_params).unwrap();

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED)
    });

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
}

// TODO: https://github.com/chipsalliance/caliptra-sw/issues/2225
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_mbox_busy_during_warm_reset() {
    // This test uses the mailbox responder binary to set the mailbox_flow_done register to
    // false.
    // A warm reset is then performed, since the mailbox responder binary never sets mailbox_flow_done
    // to true, we verify that the mailbox_flow_done register remains false through the warm reset.
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MBOX,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            ..Default::default()
        },
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    // 0xE000_0000 == OPCODE_HOLD_COMMAND_BUSY
    model.mailbox_execute(0xE000_0000, &[]).unwrap();

    assert!(!model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .mailbox_flow_done());

    // Perform warm reset
    model.warm_reset_flow(&boot_params).unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET)
    );
}

// TODO: https://github.com/chipsalliance/caliptra-sw/issues/2225
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_mbox_idle_during_warm_reset() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            fw_svn: [0b1111111, 0, 0, 0],
            ..Default::default()
        },
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    // Perform warm reset
    model.warm_reset_flow(&boot_params).unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    assert_ne!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET)
    );
}

fn get_fw_info(model: &mut DefaultHwModel) -> FwInfoResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();

    let info = FwInfoResp::read_from_bytes(resp.as_slice()).unwrap();

    // Verify checksum
    assert!(caliptra_common::checksum::verify_checksum(
        info.hdr.chksum,
        0x0,
        &info.as_bytes()[core::mem::size_of_val(&info.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(
        info.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    info
}

fn find_rom_info(rom: &[u8]) -> Option<RomInfo> {
    // RomInfo is 64-byte aligned and the last data in the ROM bin
    // Iterate backwards by 64-byte increments (assumes rom size will always be 64 byte aligned)
    for i in (0..rom.len() - 63).rev().step_by(64) {
        let chunk = &rom[i..i + 64];

        // Check if the chunk contains non-zero data
        if chunk.iter().any(|&byte| byte != 0) {
            // Found non-zero data, return RomInfo constructed from the data
            if let Ok(rom_info) = RomInfo::read_from_bytes(&rom[i..i + size_of::<RomInfo>()]) {
                return Some(rom_info);
            }
        }
    }

    // No non-zero data found
    None
}

#[inline]
fn sha384_words_to_bytes(words: &[u32; 12]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

#[inline]
fn sha256_words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

trait Sha384Bytes {
    fn to_sha384_bytes(&self) -> [u8; 48];
}
trait Sha256Bytes {
    fn to_sha256_bytes(&self) -> [u8; 32];
}

impl Sha384Bytes for [u8; 48] {
    #[inline]
    fn to_sha384_bytes(&self) -> [u8; 48] {
        *self
    }
}
impl Sha384Bytes for [u32; 12] {
    #[inline]
    fn to_sha384_bytes(&self) -> [u8; 48] {
        sha384_words_to_bytes(self)
    }
}
impl Sha256Bytes for [u8; 32] {
    #[inline]
    fn to_sha256_bytes(&self) -> [u8; 32] {
        *self
    }
}
impl Sha256Bytes for [u32; 8] {
    #[inline]
    fn to_sha256_bytes(&self) -> [u8; 32] {
        sha256_words_to_bytes(self)
    }
}

#[test]
fn test_fw_info_after_warm_reset() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let fmc_version = 3u32;
    let app_version = 5u32;

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fmc_version: fmc_version.try_into().unwrap(),
            app_version,
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let rom_info = find_rom_info(&rom).unwrap();
    let owner_pub_key_hash = ImageGenerator::new(Crypto::default())
        .owner_pubkey_digest(&image.manifest.preamble)
        .unwrap();

    // Fuses / boot params
    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);
    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            fw_svn: [0x7F, 0, 0, 0], // == 7
            ..Default::default()
        },
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait until runtime ready
    while !model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .ready_for_runtime()
    {
        model.step();
    }

    let info_before = get_fw_info(&mut model);

    // Scalars
    assert_eq!(info_before.pl0_pauser, 0x1);
    assert_eq!(info_before.fw_svn, 9);
    assert_eq!(info_before.min_fw_svn, 9);
    assert_eq!(info_before.cold_boot_fw_svn, 9);
    assert_eq!(info_before.attestation_disabled, 0);

    // Revisions (commit IDs)
    assert_eq!(info_before.rom_revision, rom_info.revision);
    assert_eq!(info_before.fmc_revision, image.manifest.fmc.revision);
    assert_eq!(
        info_before.runtime_revision,
        image.manifest.runtime.revision
    );

    // Digests (normalize types if needed)
    let rom_sha256_ref = Sha256Bytes::to_sha256_bytes(&rom_info.sha256_digest);
    let fmc_sha384_ref = Sha384Bytes::to_sha384_bytes(&image.manifest.fmc.digest);
    let rt_sha384_ref = Sha384Bytes::to_sha384_bytes(&image.manifest.runtime.digest);

    let rom_sha256_before = Sha256Bytes::to_sha256_bytes(&info_before.rom_sha256_digest);
    let fmc_sha384_before = Sha384Bytes::to_sha384_bytes(&info_before.fmc_sha384_digest);
    let rt_sha384_before = Sha384Bytes::to_sha384_bytes(&info_before.runtime_sha384_digest);

    assert_eq!(rom_sha256_before, rom_sha256_ref);
    assert_eq!(fmc_sha384_before, fmc_sha384_ref);
    assert_ne!(
        rt_sha384_before, [0u8; 48],
        "runtime digest before reset is zero"
    );
    assert_eq!(rt_sha384_before, rt_sha384_ref);

    // Owner key hash
    assert_eq!(info_before.owner_pub_key_hash, owner_pub_key_hash);

    // ---- Warm reset (keep same image/fuses) ----
    model.warm_reset_flow(&boot_params).unwrap();
    while !model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .ready_for_runtime()
    {
        model.step();
    }

    let info_after = get_fw_info(&mut model);

    assert_eq!(info_after.pl0_pauser, info_before.pl0_pauser);
    assert_eq!(info_after.fw_svn, info_before.fw_svn);
    assert_eq!(info_after.min_fw_svn, info_before.min_fw_svn);
    assert_eq!(info_after.cold_boot_fw_svn, info_before.cold_boot_fw_svn);
    assert_eq!(
        info_after.attestation_disabled,
        info_before.attestation_disabled
    );

    assert_eq!(info_after.rom_revision, info_before.rom_revision);
    assert_eq!(info_after.fmc_revision, info_before.fmc_revision);
    assert_eq!(info_after.runtime_revision, info_before.runtime_revision);

    let rom_sha256_after = Sha256Bytes::to_sha256_bytes(&info_after.rom_sha256_digest);
    let fmc_sha384_after = Sha384Bytes::to_sha384_bytes(&info_after.fmc_sha384_digest);
    let rt_sha384_after = Sha384Bytes::to_sha384_bytes(&info_after.runtime_sha384_digest);

    assert_eq!(rom_sha256_after, rom_sha256_ref);
    assert_eq!(fmc_sha384_after, fmc_sha384_ref);
    assert_ne!(
        rt_sha384_after, [0u8; 48],
        "runtime digest after reset is zero"
    );
    assert_eq!(rt_sha384_after, rt_sha384_ref);
    assert_eq!(
        rt_sha384_after, rt_sha384_before,
        "runtime digest changed across warm reset"
    );

    // No recent FW error
    assert_eq!(info_after.most_recent_fw_error, 0x0);
}

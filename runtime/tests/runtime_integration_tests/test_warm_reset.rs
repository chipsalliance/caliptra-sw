// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    build_and_sign_image, build_firmware_rom,
    firmware::{self, runtime_tests::MBOX, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART},
    ImageOptions,
};
use caliptra_common::{
    capabilities::Capabilities,
    checksum::{calc_checksum, verify_checksum},
    mailbox_api::{CapabilitiesResp, CommandId, MailboxReqHeader, MailboxRespHeader},
};
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

fn get_capabilities(model: &mut DefaultHwModel) -> (CapabilitiesResp, Vec<u8>) {
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::CAPABILITIES), payload.as_bytes())
        .expect("mailbox_execute failed")
        .expect("CAPABILITIES returned no data");

    assert!(!resp.is_empty(), "CAPABILITIES returned empty payload");

    let capabilities_resp =
        CapabilitiesResp::read_from_bytes(resp.as_slice()).expect("parse CapabilitiesResp failed");

    // Verify response checksum (exclude the checksum field itself).
    assert!(
        verify_checksum(
            capabilities_resp.hdr.chksum,
            0x0,
            &capabilities_resp.as_bytes()[core::mem::size_of_val(&capabilities_resp.hdr.chksum)..],
        ),
        "CAPABILITIES response checksum invalid"
    );
    assert_eq!(
        capabilities_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CAPABILITIES FIPS not APPROVED"
    );

    (capabilities_resp, resp)
}

pub struct BuildArgs {
    pub security_state: SecurityState,
    pub fmc_version: u32,
    pub app_version: u32,
    pub fw_svn: u32,
}

impl Default for BuildArgs {
    fn default() -> Self {
        let security_state = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production);
        Self {
            security_state,
            fmc_version: 3,
            app_version: 5,
            fw_svn: 9,
        }
    }
}

pub fn build_ready_runtime_model(args: BuildArgs) -> (DefaultHwModel, Vec<u8>) {
    // Security state & versions from args
    let security_state = args.security_state;
    let fmc_version = args.fmc_version;
    let app_version = args.app_version;

    // ROM & image
    let rom = build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fmc_version: fmc_version.try_into().unwrap(),
            app_version,
            fw_svn: args.fw_svn,
            ..Default::default()
        },
    )
    .unwrap();

    // compute rom_info + owner_pub_key_hash
    let _rom_info = find_rom_info(&rom).unwrap();
    let _owner_pub_key_hash = ImageGenerator::new(Crypto::default())
        .owner_pubkey_digest(&image.manifest.preamble)
        .unwrap();

    // Fuses / boot params
    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);
    let image_bytes = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            fw_svn: [0x7F, 0, 0, 0],
            ..Default::default()
        },
        fw_image: Some(&image_bytes),
        ..Default::default()
    };

    // Model
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
    wait_runtime_ready(&mut model);
    (model, image_bytes)
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

pub fn wait_runtime_ready(model: &mut DefaultHwModel) {
    while !model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .ready_for_runtime()
    {
        model.step();
    }
}

#[test]
fn test_capabilities_after_warm_reset() {
    let (mut model, _image_bytes) = build_ready_runtime_model(BuildArgs::default());

    // --- Before warm reset ---
    let (cap_resp_before, raw_resp_before) = get_capabilities(&mut model);
    let capabilities_before =
        Capabilities::try_from(&cap_resp_before.capabilities[..]).expect("decode caps");
    assert!(capabilities_before.contains(Capabilities::RT_BASE));

    // --- Warm reset ---
    model.warm_reset();
    wait_runtime_ready(&mut model);
    println!("finish wait_runtime_ready");

    // --- After warm reset ---
    let (cap_resp_after, raw_resp_after) = get_capabilities(&mut model);

    println!("get_capabilities");

    let capabilities_after =
        Capabilities::try_from(&cap_resp_after.capabilities[..]).expect("decode caps");

    assert!(capabilities_after.contains(Capabilities::RT_BASE));

    assert_eq!(
        raw_resp_before, raw_resp_after,
        "Raw CAPABILITIES changed across warm reset"
    );
    assert_eq!(
        cap_resp_before.as_bytes(),
        cap_resp_after.as_bytes(),
        "Typed CAPABILITIES bytes changed across warm reset"
    );
    assert_eq!(
        capabilities_before.to_bytes(),
        capabilities_after.to_bytes(),
        "Capability bitflags changed across warm reset"
    ); //
}

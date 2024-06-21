// Licensed under the Apache-2.0 license.

use crate::common::run_rt_test;
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::{
    capabilities::Capabilities,
    mailbox_api::{
        CapabilitiesResp, CommandId, FwInfoResp, GetIdevInfoResp, MailboxReqHeader,
        MailboxRespHeader,
    },
};
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};
use caliptra_image_types::RomInfo;
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

const RT_READY_FOR_COMMANDS: u32 = 0x600;

fn find_rom_info(rom: &[u8]) -> Option<RomInfo> {
    // RomInfo is 64-byte aligned and the last data in the ROM bin
    // Iterate backwards by 64-byte increments (assumes rom size will always be 64 byte aligned)
    for i in (0..rom.len() - 63).rev().step_by(64) {
        let chunk = &rom[i..i + 64];

        // Check if the chunk contains non-zero data
        if chunk.iter().any(|&byte| byte != 0) {
            // Found non-zero data, return RomInfo constructed from the data
            let rom_info = RomInfo::read_from(&rom[i..i + size_of::<RomInfo>()])?;
            return Some(rom_info);
        }
    }

    // No non-zero data found
    None
}

#[test]
fn test_fw_info() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = Some(0x1);
    image_opts.fmc_version = 0xaaaa;
    image_opts.app_version = 0xbbbbbbbb;
    image_opts.fmc_svn = 5;

    let mut image_opts10 = image_opts.clone();
    image_opts10.app_svn = 10;

    // Cannot use run_rt_test since we need the rom and image to verify info
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let init_params = InitParams {
        rom: &rom,
        ..Default::default()
    };

    let image =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_opts10)
            .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params,
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    let rom_info = find_rom_info(&rom).unwrap();

    let get_fwinfo = |model: &mut DefaultHwModel| {
        let payload = MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
        };

        let resp = model
            .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
            .unwrap()
            .unwrap();

        let info = FwInfoResp::read_from(resp.as_slice()).unwrap();

        // Verify checksum and FIPS status
        assert!(caliptra_common::checksum::verify_checksum(
            info.hdr.chksum,
            0x0,
            &info.as_bytes()[core::mem::size_of_val(&info.hdr.chksum)..],
        ));
        assert_eq!(
            info.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
        assert_eq!(info.attestation_disabled, 0);
        info
    };

    let update_to = |model: &mut DefaultHwModel, image: &[u8]| {
        model
            .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), image)
            .unwrap();

        model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);
    };

    let info = get_fwinfo(&mut model);
    // Verify FW info
    assert_eq!(info.pl0_pauser, 0x1);
    assert_eq!(info.fmc_manifest_svn, 5);
    assert_eq!(info.runtime_svn, 10);
    assert_eq!(info.min_runtime_svn, 10);
    // Verify revision (Commit ID) and digest of each component
    assert_eq!(info.rom_revision, rom_info.revision);
    assert_eq!(info.fmc_revision, image.manifest.fmc.revision);
    assert_eq!(info.runtime_revision, image.manifest.runtime.revision);
    assert_eq!(info.rom_sha256_digest, rom_info.sha256_digest);
    assert_eq!(info.fmc_sha384_digest, image.manifest.fmc.digest);
    assert_eq!(info.runtime_sha384_digest, image.manifest.runtime.digest);

    // Make image with newer SVN.
    let mut image_opts20 = image_opts.clone();
    image_opts20.app_svn = 20;

    let image20 =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_opts20)
            .unwrap()
            .to_bytes()
            .unwrap();

    // Trigger an update reset.
    update_to(&mut model, &image20);

    let info = get_fwinfo(&mut model);
    assert_eq!(info.runtime_svn, 20);
    assert_eq!(info.min_runtime_svn, 10);

    // Make image with older SVN.
    let mut image_opts5 = image_opts;
    image_opts5.app_svn = 5;

    let image5 =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_opts5)
            .unwrap()
            .to_bytes()
            .unwrap();

    update_to(&mut model, &image5);
    let info = get_fwinfo(&mut model);
    assert_eq!(info.runtime_svn, 5);
    assert_eq!(info.min_runtime_svn, 5);

    // Go back to SVN 20
    update_to(&mut model, &image20);
    let info = get_fwinfo(&mut model);
    assert_eq!(info.runtime_svn, 20);
    assert_eq!(info.min_runtime_svn, 5);
}

#[test]
fn test_idev_id_info() {
    let mut model = run_rt_test(None, None, None);
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_IDEV_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    GetIdevInfoResp::read_from(resp.as_slice()).unwrap();
}

#[test]
fn test_capabilities() {
    let mut model = run_rt_test(None, None, None);
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::CAPABILITIES), payload.as_bytes())
        .unwrap()
        .unwrap();
    let capabilities_resp = CapabilitiesResp::read_from(resp.as_slice()).unwrap();
    let capabilities = Capabilities::try_from(capabilities_resp.capabilities.as_bytes()).unwrap();
    assert!(capabilities.contains(Capabilities::RT_BASE));
}

// Licensed under the Apache-2.0 license
use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use caliptra_api::mailbox::{ActivateFirmwareFlags, ActivateFirmwareReq};
use caliptra_api::SocManager;
use caliptra_auth_man_types::AuthManifestImageMetadata;
use caliptra_auth_man_types::{Addr64, ImageMetadataFlags};
use caliptra_common::checksum::calc_checksum;
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, ImageHashSource, MailboxReq,
    MailboxReqHeader,
};
use caliptra_hw_model::{DefaultHwModel, HwModel, InitParams, ModelError};
use caliptra_kat::CaliptraError;
use caliptra_runtime::IMAGE_AUTHORIZED;
use sha2::{Digest, Sha384};
use zerocopy::{FromBytes, IntoBytes};

pub const TEST_SRAM_SIZE: usize = 64 * 1024; // 64 KB

#[cfg(feature = "fpga_subsystem")]
const MCI_BASE: u32 = 0xA8000000;
#[cfg(feature = "fpga_subsystem")]
const MCU_MBOX_SRAM_BASE: u32 = MCI_BASE + 0x400000;
#[cfg(feature = "fpga_subsystem")]
pub const TEST_SRAM_BASE: Addr64 = Addr64 {
    lo: MCU_MBOX_SRAM_BASE,
    hi: 0x0000_0000,
};

#[cfg(not(any(feature = "fpga_subsystem")))]
pub const TEST_SRAM_BASE: Addr64 = Addr64 {
    lo: 0x0050_0000,
    hi: 0x0000_0000,
};

pub const MCU_FW_ID_1: u32 = 0x2;
pub const SOC_FW_ID_1: u32 = 0x3;
pub const INVALID_FW_ID: u32 = 128;

pub const MCU_LOAD_OFFSET: usize = 0x000;

pub const MCU_STAGING_OFFSET: usize = 0x200;

pub const SOC_LOAD_OFFSET: usize = 0x200;

pub const SOC_STAGING_OFFSET: usize = 0x500;

// Must be > 0x100 so the firmware covers the MCU ROM entry point at
// MCU_SRAM + 0x100. On FPGA, MCU ROM jumps to that offset after a
// hitless-update reset.
pub const MCU_FW_SIZE: usize = 0x200;
pub const SOC_FW_SIZE: usize = 256;

/// Create a valid RISC-V firmware image that won't crash with an illegal
/// instruction exception on real FPGA hardware. Uses `0x37` repeated, which
/// encodes as `LUI x6, 0x37373` — a valid, harmless RISC-V instruction.
/// The single-byte pattern is byte-swap invariant, which is required because
/// `write_payload_to_mcu_sram` applies a BE byte swap when writing to MCU
/// SRAM via the MCI MMIO window.
fn mcu_test_firmware() -> Vec<u8> {
    vec![0x37u8; MCU_FW_SIZE]
}

#[derive(Debug, Clone)]
struct Image {
    pub fw_id: u32,
    pub staging_offset: usize,
    pub load_offset: usize,
    pub exec_bit: u8,
    pub contents: Vec<u8>,
}

fn load_and_authorize_fw(images: &[Image]) -> DefaultHwModel {
    let staging_addr = caliptra_hw_model::new_unbooted(InitParams {
        subsystem_mode: true,
        ..Default::default()
    })
    .unwrap()
    .staging_physical_address()
    .unwrap();

    let mut image_metadata = Vec::new();
    for image in images {
        let mut flags = ImageMetadataFlags(0);
        flags.set_ignore_auth_check(false);
        flags.set_image_source(ImageHashSource::StagingAddress as u32);
        flags.set_exec_bit(image.exec_bit as u32);

        let mut hasher = Sha384::new();
        hasher.update(&image.contents);
        let fw_digest = hasher.finalize();

        let image_staging_address = Addr64 {
            lo: staging_addr as u32 + image.staging_offset as u32,
            hi: (staging_addr >> 32) as u32,
        };

        let image_load_address = Addr64 {
            lo: staging_addr as u32 + image.load_offset as u32,
            hi: (staging_addr >> 32) as u32,
        };

        image_metadata.push(AuthManifestImageMetadata {
            fw_id: image.fw_id,
            flags: flags.0,
            digest: fw_digest.into(),
            image_staging_address,
            image_load_address,
            ..Default::default()
        });
    }

    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let runtime_args = RuntimeTestArgs {
        subsystem_mode: true,
        test_image_options: Some(caliptra_builder::ImageOptions::default()),
        soc_manifest: Some(auth_manifest.as_bytes()),
        mcu_fw_image: Some(&images[0].contents),
        ..Default::default()
    };
    let mut model = run_rt_test(runtime_args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read()
            == u32::from(caliptra_runtime::RtBootStatus::RtReadyForCommands)
    });

    let mut set_auth_manifest_cmd =
        MailboxReq::SetAuthManifest(caliptra_common::mailbox_api::SetAuthManifestReq {
            hdr: MailboxReqHeader { chksum: 0 },
            manifest_size: auth_manifest.as_bytes().len() as u32,
            manifest: {
                let mut slice =
                    [0u8; caliptra_common::mailbox_api::SetAuthManifestReq::MAX_MAN_SIZE];
                slice[..auth_manifest.as_bytes().len()].copy_from_slice(auth_manifest.as_bytes());
                slice
            },
        });
    set_auth_manifest_cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::SET_AUTH_MANIFEST),
            set_auth_manifest_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    for image in images {
        model
            .write_payload_to_ss_staging_area(&image.contents, image.staging_offset)
            .unwrap();
        let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
            hdr: MailboxReqHeader { chksum: 0 },
            fw_id: image.fw_id.to_le_bytes(),
            measurement: [0; 48],
            source: ImageHashSource::StagingAddress as u32,
            flags: 1, // Skip stash
            image_size: image.contents.len() as u32,
            ..Default::default()
        });

        authorize_and_stash_cmd.populate_chksum().unwrap();

        let resp = model
            .mailbox_execute(
                u32::from(CommandId::AUTHORIZE_AND_STASH),
                authorize_and_stash_cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");

        let authorize_and_stash_resp =
            AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
        assert_eq!(authorize_and_stash_resp.auth_req_result, IMAGE_AUTHORIZED);
    }
    model
}

fn send_activate_firmware_cmd(
    model: &mut DefaultHwModel,
    activate_cmd: MailboxReq,
    reset_expected: bool,
) -> std::result::Result<Option<Vec<u8>>, ModelError> {
    model
        .start_mailbox_execute(
            u32::from(CommandId::ACTIVATE_FIRMWARE),
            activate_cmd.as_bytes().unwrap(),
        )
        .unwrap();
    if reset_expected {
        #[cfg(feature = "fpga_subsystem")]
        {
            let clear_interrupt = |model: &mut DefaultHwModel| {
                let mut retry_count = 10;
                loop {
                    let intr_status = model.mci().intr_block_rf().notif0_internal_intr_r().read();
                    if intr_status.notif_cptra_mcu_reset_req_sts() {
                        break;
                    }
                    retry_count -= 1;
                    if retry_count == 0 {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                model
                    .mci()
                    .intr_block_rf()
                    .notif0_internal_intr_r()
                    .modify(|r| r.notif_cptra_mcu_reset_req_sts(true));
                model.mci().reset_request().modify(|r| r.mcu_req(true));
            };
            clear_interrupt(model);
        }
        #[cfg(all(
            not(feature = "verilator"),
            not(feature = "fpga_realtime"),
            not(feature = "fpga_subsystem")
        ))]
        {
            model.step_until(|m| {
                let intr_status = m.mci().intr_block_rf().notif0_internal_intr_r().read();
                intr_status.notif_cptra_mcu_reset_req_sts()
            });
            model
                .mci()
                .intr_block_rf()
                .notif0_internal_intr_r()
                .modify(|r| r.notif_cptra_mcu_reset_req_sts(false));
            model.mci().reset_request().modify(|r| r.mcu_req(true));
        }
    }
    model.finish_mailbox_execute()
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_mcu_fw_success() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let mut model = load_and_authorize_fw(&[mcu_image]);

    // Send ActivateFirmware command
    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = MCU_FW_ID_1;
            arr
        },
        flags: 0,
    });
    activate_cmd.populate_chksum().unwrap();
    send_activate_firmware_cmd(&mut model, activate_cmd, true)
        .unwrap()
        .expect("We should have received a response");
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_mcu_soc_fw_success() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_offset: SOC_STAGING_OFFSET,
        load_offset: SOC_LOAD_OFFSET,
        contents: [0xAAu8; SOC_FW_SIZE].to_vec(),
        exec_bit: 3,
    };

    let mut model = load_and_authorize_fw(&[mcu_image, soc_image]);

    // Send ActivateFirmware command
    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 2,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = MCU_FW_ID_1;
            arr[1] = SOC_FW_ID_1;
            arr
        },
        flags: 0,
    });
    activate_cmd.populate_chksum().unwrap();

    send_activate_firmware_cmd(&mut model, activate_cmd, true)
        .unwrap()
        .expect("We should have received a response");
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_soc_fw_success() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_offset: SOC_STAGING_OFFSET,
        load_offset: SOC_LOAD_OFFSET,
        contents: [0xAAu8; SOC_FW_SIZE].to_vec(),
        exec_bit: 3,
    };

    let mut model = load_and_authorize_fw(&[mcu_image, soc_image]);

    // Send ActivateFirmware command
    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = SOC_FW_ID_1;
            arr
        },
        flags: 0,
    });
    activate_cmd.populate_chksum().unwrap();

    send_activate_firmware_cmd(&mut model, activate_cmd, false)
        .unwrap()
        .expect("We should have received a response");
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_invalid_fw_id() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_offset: SOC_STAGING_OFFSET,
        load_offset: SOC_LOAD_OFFSET,
        contents: [0xAAu8; SOC_FW_SIZE].to_vec(),
        exec_bit: 3,
    };

    let mut model = load_and_authorize_fw(&[mcu_image, soc_image]);

    // Send ActivateFirmware command
    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = INVALID_FW_ID;
            arr
        },
        flags: 0,
    });
    activate_cmd.populate_chksum().unwrap();

    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_fw_id_not_in_manifest() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_offset: SOC_STAGING_OFFSET,
        load_offset: SOC_LOAD_OFFSET,
        contents: [0xAAu8; SOC_FW_SIZE].to_vec(),
        exec_bit: 3,
    };

    let mut model = load_and_authorize_fw(&[mcu_image, soc_image]);

    // Send ActivateFirmware command
    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = INVALID_FW_ID;
            arr
        },
        flags: 0,
    });
    activate_cmd.populate_chksum().unwrap();

    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_invalid_exec_bit_in_manifest() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_offset: SOC_STAGING_OFFSET,
        load_offset: SOC_LOAD_OFFSET,
        contents: [0xAAu8; SOC_FW_SIZE].to_vec(),
        exec_bit: 0,
    };

    let mut model = load_and_authorize_fw(&[mcu_image, soc_image]);

    // Send ActivateFirmware command
    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = SOC_FW_ID_1;
            arr
        },
        flags: 0,
    });
    activate_cmd.populate_chksum().unwrap();

    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

/// Backward-compat: clients that pre-date the `flags` field send a request
/// truncated to `size_of::<ActivateFirmwareReq>() - 4` bytes (no `flags`
/// trailer). The runtime must treat the missing field as zero and proceed
/// with the hitless-update path that those clients expect.
#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_firmware_old_format_no_flags() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let mut model = load_and_authorize_fw(&[mcu_image]);

    // Build the request via the current `ActivateFirmwareReq` struct (which
    // includes `flags`), then truncate the trailing `flags` u32 off the wire
    // bytes so the runtime parser sees exactly what an old client would have
    // sent. Compute the checksum over the truncated bytes (excluding the
    // 4-byte `chksum` field).
    let req = ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = MCU_FW_ID_1;
            arr
        },
        flags: 0,
    };
    let full_bytes = req.as_bytes();
    let old_len = full_bytes.len() - core::mem::size_of::<u32>();
    let mut truncated = full_bytes[..old_len].to_vec();

    // Patch the checksum so it covers exactly the truncated payload.
    let chksum = calc_checksum(
        u32::from(CommandId::ACTIVATE_FIRMWARE),
        &truncated[core::mem::size_of::<u32>()..],
    );
    truncated[..core::mem::size_of::<u32>()].copy_from_slice(&chksum.to_le_bytes());

    // Send the truncated buffer directly. Mirrors the
    // `send_activate_firmware_cmd` helper but bypasses MailboxReq so we
    // control the exact wire length.
    model
        .start_mailbox_execute(u32::from(CommandId::ACTIVATE_FIRMWARE), &truncated)
        .unwrap();
    #[cfg(feature = "fpga_subsystem")]
    {
        // The MCU image is included, so simulate the MCU-reset ack handshake
        // (same as send_activate_firmware_cmd with reset_expected=true).
        let mut retry_count = 10;
        loop {
            let intr_status = model
                .mmio
                .mci()
                .unwrap()
                .regs()
                .intr_block_rf()
                .notif0_internal_intr_r()
                .read();
            if intr_status.notif_cptra_mcu_reset_req_sts() {
                break;
            }
            retry_count -= 1;
            if retry_count == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        model
            .mmio
            .mci()
            .unwrap()
            .regs()
            .intr_block_rf()
            .notif0_internal_intr_r()
            .modify(|r| r.notif_cptra_mcu_reset_req_sts(true));
        model
            .mmio
            .mci()
            .unwrap()
            .regs()
            .reset_request()
            .modify(|r| r.mcu_req(true));
    }
    #[cfg(all(
        not(feature = "verilator"),
        not(feature = "fpga_realtime"),
        not(feature = "fpga_subsystem")
    ))]
    {
        model.step_until(|m| {
            let intr_status = m.mci().intr_block_rf().notif0_internal_intr_r().read();
            intr_status.notif_cptra_mcu_reset_req_sts()
        });
        model
            .mci()
            .intr_block_rf()
            .notif0_internal_intr_r()
            .modify(|r| r.notif_cptra_mcu_reset_req_sts(false));
        model.mci().reset_request().modify(|r| r.mcu_req(true));
    }
    model
        .finish_mailbox_execute()
        .unwrap()
        .expect("ACTIVATE_FIRMWARE without flags trailer should succeed");
}

/// Reject unknown flag bits with `RUNTIME_MAILBOX_INVALID_PARAMS`. The
/// reserved high bit acts as a stand-in for any future undefined flag.
#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_firmware_unknown_flag_bit_rejected() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let mut model = load_and_authorize_fw(&[mcu_image]);

    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = MCU_FW_ID_1;
            arr
        },
        // A bit that is not part of `ActivateFirmwareFlags`.
        flags: 1 << 31,
    });
    activate_cmd.populate_chksum().unwrap();

    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

/// `INITIAL_ACTIVATE` is only honored when ROM set
/// `BootMode::EncryptedFirmware`. In the normal boot flow used by this test
/// the boot mode is `Normal`, so Caliptra must reject the request rather
/// than skip the hitless-update steps.
#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_firmware_initial_activate_wrong_boot_mode() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let mut model = load_and_authorize_fw(&[mcu_image]);

    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = MCU_FW_ID_1;
            arr
        },
        flags: ActivateFirmwareFlags::INITIAL_ACTIVATE.bits(),
    });
    activate_cmd.populate_chksum().unwrap();

    // `load_and_authorize_fw` does a normal boot, so boot_mode is Normal.
    // The flag must be rejected.
    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

/// `INITIAL_ACTIVATE` requires the MCU image bit to be in the activation
/// bitmap. Sending it with only SoC ids must be rejected.
#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_firmware_initial_activate_without_mcu_bit_rejected() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_offset: SOC_STAGING_OFFSET,
        load_offset: SOC_LOAD_OFFSET,
        contents: [0xAAu8; SOC_FW_SIZE].to_vec(),
        exec_bit: 3,
    };

    let mut model = load_and_authorize_fw(&[mcu_image, soc_image]);

    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = SOC_FW_ID_1;
            arr
        },
        flags: ActivateFirmwareFlags::INITIAL_ACTIVATE.bits(),
    });
    activate_cmd.populate_chksum().unwrap();

    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_mcu_fw_digest_mismatch() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_offset: MCU_STAGING_OFFSET,
        load_offset: MCU_LOAD_OFFSET,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let mut model = load_and_authorize_fw(&[mcu_image]);

    // Tamper with the image in the staging area so the digest won't match the manifest
    model
        .write_payload_to_ss_staging_area(&[0x75u8, 0x37u8, 0x37u8, 0x37u8], MCU_STAGING_OFFSET)
        .unwrap();

    // Send ActivateFirmware command
    let mut activate_cmd = MailboxReq::ActivateFirmware(ActivateFirmwareReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id_count: 1,
        mcu_fw_image_size: MCU_FW_SIZE as u32,
        fw_ids: {
            let mut arr = [0u32; 128];
            arr[0] = MCU_FW_ID_1;
            arr
        },
        flags: 0,
    });
    activate_cmd.populate_chksum().unwrap();

    assert_eq!(
        send_activate_firmware_cmd(&mut model, activate_cmd, true),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ACTIVATION_FAILED.into()
        ))
    );
}

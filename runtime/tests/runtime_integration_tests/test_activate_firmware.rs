// Licensed under the Apache-2.0 license
use crate::test_authorize_and_stash::set_auth_manifest_with_test_sram;
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use caliptra_api::mailbox::ActivateFirmwareReq;
use caliptra_auth_man_types::AuthManifestImageMetadata;
use caliptra_auth_man_types::{Addr64, ImageMetadataFlags};
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, GetTaggedTciReq, GetTaggedTciResp,
    ImageHashSource, MailboxReq, MailboxReqHeader, TagTciReq,
};
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_runtime::IMAGE_AUTHORIZED;
use sha2::{Digest, Sha384};
use zerocopy::FromBytes;

pub const TEST_SRAM_SIZE: usize = 0x1000;

#[cfg(feature = "fpga_subsystem")]
const MCI_BASE: u32 = 0xA8000000;
// On the FPGA subsystem the test stages firmware in MCU SRAM directly (the
// same region the production DMA in `ActivateFirmware` writes to). This way
// the post-DMA `AuthorizeAndStash(LoadAddress)` (added in #3719) reads from
// the same address Caliptra just DMA'd into, and the test never has to
// acquire the MCU mailbox SRAM lock (which would block the MCU ROM's
// hitless-update flow when MCU comes out of reset).
#[cfg(feature = "fpga_subsystem")]
const MCU_SRAM_BASE: u32 = MCI_BASE + 0xC00000;
#[cfg(feature = "fpga_subsystem")]
pub const TEST_SRAM_BASE: Addr64 = Addr64 {
    lo: MCU_SRAM_BASE,
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

pub const MCU_LOAD_ADDRESS: Addr64 = Addr64 {
    lo: TEST_SRAM_BASE.lo,
    hi: 0x0000_0000,
};

pub const MCU_STAGING_ADDRESS: Addr64 = Addr64 {
    lo: TEST_SRAM_BASE.lo + 0x300,
    hi: 0x0000_0000,
};

pub const SOC_LOAD_ADDRESS: Addr64 = Addr64 {
    lo: TEST_SRAM_BASE.lo + 0x200,
    hi: 0x0000_0000,
};

pub const SOC_STAGING_ADDRESS: Addr64 = Addr64 {
    lo: TEST_SRAM_BASE.lo + 0x500,
    hi: 0x0000_0000,
};

// Must be > 0x100 so the firmware covers the MCU ROM entry point at
// MCU_SRAM + 0x100. On FPGA, MCU ROM jumps to that offset after a
// hitless-update reset.
pub const MCU_FW_SIZE: usize = 0x200;
pub const SOC_FW_SIZE: usize = 256;
const MCU_TCI_TAG: u32 = u32::from_be_bytes(*b"MCFW");

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
    pub staging_address: Addr64,
    pub load_address: Addr64,
    pub exec_bit: u8,
    pub contents: Vec<u8>,
}

fn load_and_authorize_fw(images: &[Image]) -> DefaultHwModel {
    let mut image_metadata = Vec::new();
    let mut test_sram_contents = vec![0u8; TEST_SRAM_SIZE];
    for image in images {
        let mut flags = ImageMetadataFlags(0);
        flags.set_ignore_auth_check(false);
        flags.set_image_source(ImageHashSource::StagingAddress as u32);
        flags.set_exec_bit(image.exec_bit as u32);

        let load_memory_contents = image.contents.clone();

        let mut hasher = Sha384::new();
        hasher.update(load_memory_contents);
        let fw_digest = hasher.finalize();

        image_metadata.push(AuthManifestImageMetadata {
            fw_id: image.fw_id,
            flags: flags.0,
            digest: fw_digest.into(),
            image_staging_address: image.staging_address,
            image_load_address: image.load_address,
            ..Default::default()
        });

        // Load the firmware contents into the staging area in test SRAM
        let staging_address = image.staging_address.lo as usize - TEST_SRAM_BASE.lo as usize;
        let image_size = image.contents.len();
        assert!(staging_address + image_size <= TEST_SRAM_SIZE);
        test_sram_contents[staging_address..staging_address + image_size]
            .copy_from_slice(&image.contents);

        // On the emulator, the test SRAM (where staging lives) and MCU SRAM
        // (the DMA destination used by `ActivateFirmware`) are distinct
        // regions, so the post-DMA `AuthorizeAndStash(LoadAddress)` added in
        // #3719 would otherwise read zeros at `load_address`. Seed the test
        // SRAM at the load offset so the hash matches. On the FPGA subsystem
        // the staging area *is* MCU SRAM, so Caliptra's DMA fills the load
        // address for us and no seeding is needed.
        #[cfg(not(feature = "fpga_subsystem"))]
        {
            let load_address = image.load_address.lo as usize - TEST_SRAM_BASE.lo as usize;
            assert!(load_address + image_size <= TEST_SRAM_SIZE);
            test_sram_contents[load_address..load_address + image_size]
                .copy_from_slice(&image.contents);
        }
    }

    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest_with_test_sram(
        Some(auth_manifest),
        &test_sram_contents,
        &images[0].contents,
    );

    #[cfg(feature = "fpga_subsystem")]
    {
        write_payload_to_mcu_sram(&mut model, &test_sram_contents);
    }

    for image in images {
        let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
            hdr: MailboxReqHeader { chksum: 0 },
            fw_id: image.fw_id.to_le_bytes(),
            measurement: [0; 48],
            source: ImageHashSource::StagingAddress as u32,
            flags: 0, // Don't skip stash
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

// Write the staged test payload directly into MCU SRAM (the same region
// Caliptra's `ActivateFirmware` DMAs into). Unlike `write_mcu_mbox_sram`,
// this does not acquire the MCU mailbox SRAM lock, so the MCU ROM remains
// free to use its mailbox during the hitless-update flow that ACTF triggers.
#[cfg(feature = "fpga_subsystem")]
fn write_payload_to_mcu_sram(model: &mut DefaultHwModel, data: &[u8]) {
    assert!(data.len() % 4 == 0, "payload length must be 4-byte aligned");
    unsafe {
        let mcu_sram_ptr = model.mmio.mci().unwrap().ptr.add(0xC00000 / 4) as *mut u32;
        for (count, chunk) in data.chunks(4).enumerate() {
            // Match the byte ordering used by `write_mcu_mbox_sram` for the
            // sibling MCU mailbox SRAM region on this same MCI MMIO window.
            mcu_sram_ptr
                .add(count)
                .write_volatile(u32::from_be_bytes(chunk.try_into().unwrap()));
        }
    }
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
    #[cfg(feature = "fpga_subsystem")]
    {
        if reset_expected {
            let clear_interrupt = |model: &mut DefaultHwModel| {
                let mut retry_count = 100;
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
                        panic!("Timed out waiting for notif_cptra_mcu_reset_req_sts interrupt");
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
            };
            clear_interrupt(model);
        }
    }
    #[cfg(all(
        not(feature = "verilator"),
        not(feature = "fpga_realtime"),
        not(feature = "fpga_subsystem")
    ))]
    {
        let _ = reset_expected;
        // In emulator mode, since FW_EXEC_CTRL bit is already cleared,
        // the MCU will be already in reset state
    }
    model.finish_mailbox_execute()
}

fn tag_and_get_mcu_tci(model: &mut DefaultHwModel) -> GetTaggedTciResp {
    let mut tag_cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: [0u8; 16],
        tag: MCU_TCI_TAG,
    });
    tag_cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            u32::from(CommandId::DPE_TAG_TCI),
            tag_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    get_mcu_tci(model)
}

fn get_mcu_tci(model: &mut DefaultHwModel) -> GetTaggedTciResp {
    let mut get_cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: MCU_TCI_TAG,
    });
    get_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            get_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap()
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_mcu_fw_success() {
    let mcu_contents = mcu_test_firmware();
    let mut hasher = Sha384::new();
    hasher.update(&mcu_contents);
    let mcu_digest: [u8; 48] = hasher.finalize().into();

    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_address: MCU_STAGING_ADDRESS,
        load_address: MCU_LOAD_ADDRESS,
        contents: mcu_contents,
        exec_bit: 2,
    };

    let mut model = load_and_authorize_fw(&[mcu_image]);
    let initial_mcu_tci = tag_and_get_mcu_tci(&mut model);
    assert_eq!(initial_mcu_tci.tci_current, mcu_digest);

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
    });
    activate_cmd.populate_chksum().unwrap();
    send_activate_firmware_cmd(&mut model, activate_cmd, true)
        .unwrap()
        .expect("We should have received a response");

    #[cfg(not(feature = "fpga_subsystem"))]
    {
        let updated_mcu_tci = get_mcu_tci(&mut model);
        assert_eq!(updated_mcu_tci.tci_current, mcu_digest);

        let mut hasher = Sha384::new();
        hasher.update(initial_mcu_tci.tci_cumulative);
        hasher.update(mcu_digest);
        let expected_updated_cumulative: [u8; 48] = hasher.finalize().into();
        assert_eq!(updated_mcu_tci.tci_cumulative, expected_updated_cumulative);
    }
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_mcu_soc_fw_success() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_address: MCU_STAGING_ADDRESS,
        load_address: MCU_LOAD_ADDRESS,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_address: SOC_STAGING_ADDRESS,
        load_address: SOC_LOAD_ADDRESS,
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
        staging_address: MCU_STAGING_ADDRESS,
        load_address: MCU_LOAD_ADDRESS,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_address: SOC_STAGING_ADDRESS,
        load_address: SOC_LOAD_ADDRESS,
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
        staging_address: MCU_STAGING_ADDRESS,
        load_address: MCU_LOAD_ADDRESS,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_address: SOC_STAGING_ADDRESS,
        load_address: SOC_LOAD_ADDRESS,
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
    });
    activate_cmd.populate_chksum().unwrap();

    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_activate_fw_id_not_in_manifest() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_address: MCU_STAGING_ADDRESS,
        load_address: MCU_LOAD_ADDRESS,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_address: SOC_STAGING_ADDRESS,
        load_address: SOC_LOAD_ADDRESS,
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
    });
    activate_cmd.populate_chksum().unwrap();

    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_invalid_exec_bit_in_manifest() {
    let mcu_image = Image {
        fw_id: MCU_FW_ID_1,
        staging_address: MCU_STAGING_ADDRESS,
        load_address: MCU_LOAD_ADDRESS,
        contents: mcu_test_firmware(),
        exec_bit: 2,
    };

    let soc_image = Image {
        fw_id: SOC_FW_ID_1,
        staging_address: SOC_STAGING_ADDRESS,
        load_address: SOC_LOAD_ADDRESS,
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
    });
    activate_cmd.populate_chksum().unwrap();

    assert!(send_activate_firmware_cmd(&mut model, activate_cmd, false).is_err());
}

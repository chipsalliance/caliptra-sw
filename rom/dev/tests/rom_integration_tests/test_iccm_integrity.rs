// Licensed under the Apache-2.0 license

use crate::helpers;
use caliptra_api::SocManager;
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{
    CommandId, ExternalMailboxCmdReq, MailboxReq, MailboxReqHeader, QuotePcrsEcc384Req,
    QuotePcrsEcc384Resp,
};
use caliptra_common::{
    memory_layout::{BOOT_STATUS_ORG, DCCM_ORG, ICCM_ORG},
    RomBootStatus::{
        self, ColdResetComplete, FwProcessorLoadImageComplete, FwProcessorManifestLoadComplete,
    },
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, ModelError,
    SecurityState,
};
use caliptra_image_types::ImageBundle;
use caliptra_test::{bytes_to_be_words_48, image_pk_desc_hash};
use openssl::sha::sha384;
use zerocopy::FromBytes;

fn model_and_image(subsystem_mode: bool, debug_locked: bool) -> (DefaultHwModel, ImageBundle) {
    let image = helpers::build_image_bundle(ImageOptions::default());
    let (vendor_pk_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);
    let rom = caliptra_builder::build_firmware_rom(helpers::rom_from_env()).unwrap();
    let security_state = *SecurityState::default()
        .set_debug_locked(debug_locked)
        .set_device_lifecycle(DeviceLifecycle::Production);
    let model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            subsystem_mode,
            security_state,
            fuses: Fuses {
                vendor_pk_hash,
                owner_pk_hash,
                fuse_pqc_key_type: image.manifest.pqc_key_type as u32,
                ..Default::default()
            },
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();
    (model, image)
}

fn read_pcr(model: &mut DefaultHwModel, index: u32) -> [u8; 48] {
    model.read_pcr(u8::try_from(index).unwrap())
}

fn expected_extension(previous: [u8; 48], stream: &[u8]) -> [u8; 48] {
    let digest = sha384(stream);
    let mut extended = [0u8; 96];
    extended[..48].copy_from_slice(&previous);
    extended[48..].copy_from_slice(&digest);
    sha384(&extended)
}

fn expected_current(image: &ImageBundle) -> [u8; 48] {
    let mut stream = image.fmc.clone();
    stream.extend_from_slice(&image.runtime);
    expected_extension([0; 48], &stream)
}

fn wait_for_runtime(model: &mut DefaultHwModel) {
    model.step_until_or_timeout("Runtime entry or a boot-integrity error", 40_000_000, |m| {
        m.soc_ifc().cptra_flow_status().read().ready_for_runtime()
            || u32::from(m.soc_ifc().cptra_hw_error_fatal().read()) != 0
            || m.soc_ifc().cptra_fw_error_fatal().read() != 0
    });
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
    let hardware_error: u32 = model.soc_ifc().cptra_hw_error_fatal().read().into();
    assert_eq!(hardware_error, 0);
    assert!(model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .ready_for_runtime());
}

fn rom_status(model: &DefaultHwModel) -> u32 {
    u32::from_le_bytes(
        model
            .dccm_read(BOOT_STATUS_ORG - DCCM_ORG, 4)
            .try_into()
            .unwrap(),
    )
}

fn wait_for_rom_status(model: &mut DefaultHwModel, expected: RomBootStatus) {
    model.step_until_or_timeout("ROM load stage or fatal error", 40_000_000, |m| {
        rom_status(m) == u32::from(expected)
            || m.soc_ifc().cptra_fw_error_fatal().read() != 0
            || u32::from(m.soc_ifc().cptra_hw_error_fatal().read()) != 0
    });
    assert_eq!(rom_status(model), u32::from(expected));
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
}

fn wait_for_fresh_runtime(model: &mut DefaultHwModel) {
    model.step_until_or_timeout("Runtime re-entry or fatal error", 40_000_000, |m| {
        m.output().search_matched()
            || m.soc_ifc().cptra_fw_error_fatal().read() != 0
            || u32::from(m.soc_ifc().cptra_hw_error_fatal().read()) != 0
    });
    wait_for_runtime(model);
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_subsystem_current_and_warm_journey() {
    for debug_locked in [false, true] {
        let (mut model, image) = model_and_image(true, debug_locked);
        helpers::test_upload_firmware(
            &mut model,
            &image.to_bytes().unwrap(),
            caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
                .unwrap(),
        );
        wait_for_runtime(&mut model);
        let current = read_pcr(&mut model, 4);
        let journey = read_pcr(&mut model, 5);
        assert_eq!(current, expected_current(&image));
        assert_eq!(journey, current);

        model.warm_reset_flow().unwrap();
        wait_for_runtime(&mut model);
        assert_eq!(read_pcr(&mut model, 4), expected_extension(current, &[]));
        assert_eq!(read_pcr(&mut model, 5), expected_extension(journey, &[]));
    }
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_update_runtime_only_journey_and_larger_bounds() {
    let (mut model, mut image) = model_and_image(true, true);
    let pqc_key_type =
        caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
            .unwrap();
    helpers::test_upload_firmware(&mut model, &image.to_bytes().unwrap(), pqc_key_type);
    wait_for_runtime(&mut model);
    let previous = read_pcr(&mut model, 5);
    assert_eq!(previous, expected_current(&image));

    image.runtime.extend_from_slice(&[0xa5; 64]);
    image.manifest.runtime.size += 64;
    image.manifest.runtime.digest = bytes_to_be_words_48(&sha384(&image.runtime));
    let updated = crate::test_update_reset::rebuild_image_after_toc_change(&mut image);
    model
        .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &updated)
        .unwrap();
    assert_eq!(model.finish_mailbox_execute(), Ok(None));
    // Debug-locked firmware hides boot status; match only fresh Runtime output.
    model
        .output()
        .set_search_term("RT listening for mailbox commands...");
    model.step_until_or_timeout("Runtime re-entry after update", 40_000_000, |m| {
        m.output().search_matched()
            || u32::from(m.soc_ifc().cptra_hw_error_fatal().read()) != 0
            || m.soc_ifc().cptra_fw_error_fatal().read() != 0
    });
    wait_for_runtime(&mut model);
    let current = expected_extension([0; 48], &image.runtime);
    let journey = expected_extension(previous, &image.runtime);
    assert_eq!(read_pcr(&mut model, 4), current);
    assert_eq!(read_pcr(&mut model, 5), journey);
    assert_ne!(journey, current);

    let mut request = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0; 32],
    });
    request.populate_chksum().unwrap();
    let response = model
        .mailbox_execute(
            CommandId::QUOTE_PCRS_ECC384.into(),
            request.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let quote = QuotePcrsEcc384Resp::read_from_bytes(response.as_slice()).unwrap();
    assert_eq!(quote.pcrs[4], current);
    assert_eq!(quote.pcrs[5], journey);

    model.warm_reset_flow().unwrap();
    wait_for_runtime(&mut model);
    assert_eq!(read_pcr(&mut model, 4), expected_extension(current, &[]));
    assert_eq!(read_pcr(&mut model, 5), expected_extension(journey, &[]));
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_production_passive_cold_and_warm_boot() {
    let (mut model, image) = model_and_image(false, true);
    helpers::test_upload_firmware(
        &mut model,
        &image.to_bytes().unwrap(),
        caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
            .unwrap(),
    );
    wait_for_runtime(&mut model);
    model
        .output()
        .set_search_term("RT listening for mailbox commands...");
    model.warm_reset_flow().unwrap();
    model.step_until_or_timeout(
        "passive Runtime re-entry after warm reset",
        40_000_000,
        |m| {
            m.output().search_matched()
                || u32::from(m.soc_ifc().cptra_hw_error_fatal().read()) != 0
                || m.soc_ifc().cptra_fw_error_fatal().read() != 0
        },
    );
    wait_for_runtime(&mut model);
    assert_eq!(read_pcr(&mut model, 4), [0; 48]);
    assert_eq!(read_pcr(&mut model, 5), [0; 48]);
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_debug_passive_cold_boot() {
    let (mut model, image) = model_and_image(false, false);
    helpers::test_upload_firmware(
        &mut model,
        &image.to_bytes().unwrap(),
        caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
            .unwrap(),
    );
    model.step_until_boot_status(ColdResetComplete.into(), true);
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_passive_update_and_warm_boot() {
    for debug_locked in [false, true] {
        let (mut model, mut image) = model_and_image(false, debug_locked);
        helpers::test_upload_firmware(
            &mut model,
            &image.to_bytes().unwrap(),
            caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
                .unwrap(),
        );
        wait_for_runtime(&mut model);
        image.runtime.extend_from_slice(&[0xa5; 64]);
        image.manifest.runtime.size += 64;
        image.manifest.runtime.digest = bytes_to_be_words_48(&sha384(&image.runtime));
        let updated = crate::test_update_reset::rebuild_image_after_toc_change(&mut image);
        model
            .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &updated)
            .unwrap();
        assert_eq!(model.finish_mailbox_execute(), Ok(None));
        model
            .output()
            .set_search_term("RT listening for mailbox commands...");
        wait_for_fresh_runtime(&mut model);
        assert_eq!(
            model.iccm_read(image.manifest.fmc.load_addr - ICCM_ORG, image.fmc.len()),
            image.fmc
        );
        assert_eq!(
            model.iccm_read(
                image.manifest.runtime.load_addr - ICCM_ORG,
                image.runtime.len()
            ),
            image.runtime
        );
        model
            .output()
            .set_search_term("RT listening for mailbox commands...");
        model.warm_reset_flow().unwrap();
        wait_for_fresh_runtime(&mut model);
        assert_eq!(read_pcr(&mut model, 4), [0; 48]);
        assert_eq!(read_pcr(&mut model, 5), [0; 48]);
    }
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_cold_does_not_read_back_iccm() {
    for subsystem in [false, true] {
        for runtime in [false, true] {
            let (mut model, image) = model_and_image(subsystem, true);
            let bytes = image.to_bytes().unwrap();
            if subsystem {
                helpers::test_upload_firmware(
                    &mut model,
                    &bytes,
                    caliptra_image_types::FwVerificationPqcKeyType::from_u8(
                        image.manifest.pqc_key_type,
                    )
                    .unwrap(),
                );
            } else {
                model
                    .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &bytes)
                    .unwrap();
            }
            wait_for_rom_status(&mut model, FwProcessorLoadImageComplete);
            let entry = if runtime {
                &image.manifest.runtime
            } else {
                &image.manifest.fmc
            };
            let offset = entry.load_addr - ICCM_ORG;
            let mut word = model.iccm_read(offset, 4);
            word[0] ^= 1;
            // Inject a destination fault, then stop before the corrupted image executes.
            model.iccm_write(offset, &word);
            wait_for_rom_status(&mut model, ColdResetComplete);
            assert_eq!(model.iccm_read(offset, 4), word);
            assert_eq!(u32::from(model.soc_ifc().cptra_hw_error_fatal().read()), 0);
            if subsystem {
                assert_eq!(read_pcr(&mut model, 4), expected_current(&image));
            } else {
                assert_eq!(model.finish_mailbox_execute(), Ok(None));
            }
        }
    }
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_cold_rejects_staged_corruption() {
    for subsystem in [false, true] {
        for runtime in [false, true] {
            let (mut model, mut image) = model_and_image(subsystem, true);
            let error = if runtime {
                image.runtime[0] ^= 1;
                CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH
            } else {
                image.fmc[0] ^= 1;
                CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH
            };
            helpers::assert_fatal_fw_load(
                &mut model,
                caliptra_image_types::FwVerificationPqcKeyType::from_u8(
                    image.manifest.pqc_key_type,
                )
                .unwrap(),
                &image.to_bytes().unwrap(),
                error,
            );
            assert_eq!(
                rom_status(&model),
                u32::from(FwProcessorManifestLoadComplete)
            );
            assert_eq!(
                model.iccm_read(image.manifest.fmc.load_addr - ICCM_ORG, 4),
                [0; 4]
            );
            assert_eq!(
                model.iccm_read(image.manifest.runtime.load_addr - ICCM_ORG, 4),
                [0; 4]
            );
            assert_eq!(u32::from(model.soc_ifc().cptra_hw_error_fatal().read()), 0);
            assert!(!model
                .soc_ifc()
                .cptra_flow_status()
                .read()
                .ready_for_runtime());
        }
    }
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_update_rejects_staged_corruption() {
    for subsystem in [false, true] {
        let (mut model, mut image) = model_and_image(subsystem, true);
        helpers::test_upload_firmware(
            &mut model,
            &image.to_bytes().unwrap(),
            caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
                .unwrap(),
        );
        wait_for_runtime(&mut model);
        image.runtime[0] ^= 1;
        model
            .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &image.to_bytes().unwrap())
            .unwrap();
        let error = CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH;
        assert_eq!(
            model.finish_mailbox_execute(),
            Err(ModelError::MailboxCmdFailed(error.into()))
        );
        assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
        assert_eq!(
            model.soc_ifc().cptra_fw_error_non_fatal().read(),
            u32::from(error)
        );
        image.runtime[0] ^= 1;
        assert_eq!(
            model.iccm_read(
                image.manifest.runtime.load_addr - ICCM_ORG,
                image.runtime.len()
            ),
            image.runtime
        );
        model
            .output()
            .set_search_term("RT listening for mailbox commands...");
        wait_for_fresh_runtime(&mut model);
    }
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_rejects_partial_word_components() {
    for subsystem in [false, true] {
        for update in [false, true] {
            for runtime in [false, true] {
                let (mut model, mut image) = model_and_image(subsystem, true);
                let original_fmc = image.fmc.clone();
                let original_runtime = image.runtime.clone();
                let pqc_key_type = caliptra_image_types::FwVerificationPqcKeyType::from_u8(
                    image.manifest.pqc_key_type,
                )
                .unwrap();
                if update {
                    helpers::test_upload_firmware(
                        &mut model,
                        &image.to_bytes().unwrap(),
                        pqc_key_type,
                    );
                    wait_for_runtime(&mut model);
                }
                if runtime {
                    image.runtime.pop().unwrap();
                    image.manifest.runtime.size -= 1;
                    image.manifest.runtime.digest = bytes_to_be_words_48(&sha384(&image.runtime));
                } else {
                    image.fmc.pop().unwrap();
                    image.manifest.fmc.size -= 1;
                    image.manifest.runtime.offset -= 1;
                    image.manifest.fmc.digest = bytes_to_be_words_48(&sha384(&image.fmc));
                }
                let mut bytes =
                    crate::test_update_reset::rebuild_image_after_toc_change(&mut image);
                // Keep the transport word-aligned, but not the signed component size.
                bytes.push(0);
                let error = CaliptraError::IMAGE_VERIFIER_ERR_IMAGE_SOURCE_UNALIGNED;
                if update {
                    model
                        .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &bytes)
                        .unwrap();
                    assert_eq!(
                        model.finish_mailbox_execute(),
                        Err(ModelError::MailboxCmdFailed(error.into()))
                    );
                    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
                    assert_eq!(
                        model.soc_ifc().cptra_fw_error_non_fatal().read(),
                        u32::from(error)
                    );
                    assert_eq!(
                        model
                            .iccm_read(image.manifest.fmc.load_addr - ICCM_ORG, original_fmc.len()),
                        original_fmc
                    );
                    assert_eq!(
                        model.iccm_read(
                            image.manifest.runtime.load_addr - ICCM_ORG,
                            original_runtime.len()
                        ),
                        original_runtime
                    );
                } else {
                    helpers::assert_fatal_fw_load(&mut model, pqc_key_type, &bytes, error);
                    assert_eq!(
                        rom_status(&model),
                        u32::from(FwProcessorManifestLoadComplete)
                    );
                }
                assert_eq!(u32::from(model.soc_ifc().cptra_hw_error_fatal().read()), 0);
            }
        }
    }
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_rejects_partial_word_bundles() {
    // Recovery advertises DWORD counts, so an SS cold-boot length is already word-aligned.
    for (subsystem, update) in [(false, false), (false, true), (true, true)] {
        let (mut model, image) = model_and_image(subsystem, true);
        let pqc_key_type =
            caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
                .unwrap();
        let mut bytes = image.to_bytes().unwrap();
        if update {
            helpers::test_upload_firmware(&mut model, &bytes, pqc_key_type);
            wait_for_runtime(&mut model);
        }
        bytes.push(0);
        let error = CaliptraError::FW_PROC_INVALID_IMAGE_SIZE;
        if update {
            if subsystem {
                // Stage complete words, but advertise a non-word firmware length.
                let command_size = bytes.len() as u32;
                bytes.extend_from_slice(&[0; 3]);
                let addr = model.write_payload_to_ss_staging_area(&bytes, 0).unwrap();
                let mut request = MailboxReq::ExternalMailboxCmd(ExternalMailboxCmdReq {
                    command_id: CommandId::FIRMWARE_LOAD.into(),
                    command_size,
                    axi_address_start_low: addr as u32,
                    axi_address_start_high: (addr >> 32) as u32,
                    ..Default::default()
                });
                request.populate_chksum().unwrap();
                model
                    .start_mailbox_execute(
                        CommandId::EXTERNAL_MAILBOX_CMD.into(),
                        request.as_bytes().unwrap(),
                    )
                    .unwrap();
            } else {
                model
                    .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &bytes)
                    .unwrap();
            }
            assert_eq!(
                model.finish_mailbox_execute(),
                Err(ModelError::MailboxCmdFailed(error.into()))
            );
            assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
            assert_eq!(
                model.soc_ifc().cptra_fw_error_non_fatal().read(),
                u32::from(error)
            );
        } else {
            helpers::assert_fatal_fw_load(&mut model, pqc_key_type, &bytes, error);
        }
    }
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_update_rejects_unaligned_axi_source() {
    let (mut model, image) = model_and_image(true, true);
    let bytes = image.to_bytes().unwrap();
    helpers::test_upload_firmware(
        &mut model,
        &bytes,
        caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
            .unwrap(),
    );
    wait_for_runtime(&mut model);
    let staging_addr = model.write_payload_to_ss_staging_area(&bytes, 0).unwrap();
    assert!(staging_addr.is_multiple_of(4));
    for offset in 1..4 {
        let addr = staging_addr + offset;
        let mut request = MailboxReq::ExternalMailboxCmd(ExternalMailboxCmdReq {
            command_id: CommandId::FIRMWARE_LOAD.into(),
            command_size: bytes.len() as u32,
            axi_address_start_low: addr as u32,
            axi_address_start_high: (addr >> 32) as u32,
            ..Default::default()
        });
        request.populate_chksum().unwrap();
        model
            .start_mailbox_execute(
                CommandId::EXTERNAL_MAILBOX_CMD.into(),
                request.as_bytes().unwrap(),
            )
            .unwrap();
        let error = CaliptraError::IMAGE_VERIFIER_ERR_IMAGE_SOURCE_UNALIGNED;
        assert_eq!(
            model.finish_mailbox_execute(),
            Err(ModelError::MailboxCmdFailed(error.into()))
        );
        assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
        assert_eq!(
            model.soc_ifc().cptra_fw_error_non_fatal().read(),
            u32::from(error)
        );
        assert_eq!(
            model.iccm_read(
                image.manifest.runtime.load_addr - ICCM_ORG,
                image.runtime.len()
            ),
            image.runtime
        );
        model
            .output()
            .set_search_term("RT listening for mailbox commands...");
        wait_for_fresh_runtime(&mut model);
    }
}

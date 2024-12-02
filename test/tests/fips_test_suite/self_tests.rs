// Licensed under the Apache-2.0 license

use crate::common;
use caliptra_api::SocManager;

use caliptra_builder::firmware::{
    APP_WITH_UART_FIPS_TEST_HOOKS, FMC_WITH_UART, ROM_WITH_FIPS_TEST_HOOKS, ROM_WITH_UART,
};
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::*;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::FipsTestHook;
use caliptra_hw_model::{BootParams, HwModel, InitParams, ModelError, ShaAccMode};
use common::*;
use zerocopy::IntoBytes;

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_halt_check_no_output() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_FIPS_TEST_HOOKS).unwrap();

    let mut hw = fips_test_init_to_boot_start(
        Some(InitParams {
            rom: &rom,
            ..Default::default()
        }),
        Some(BootParams {
            initial_dbg_manuf_service_reg: (FipsTestHook::HALT_SELF_TESTS as u32)
                << HOOK_CODE_OFFSET,
            ..Default::default()
        }),
    );

    // Wait for ACK that ROM reached halt point
    hook_wait_for_complete(&mut hw);

    // Check output is inhibited
    verify_output_inhibited(&mut hw);
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn fw_load_halt_check_no_output() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_FIPS_TEST_HOOKS).unwrap();

    let mut hw = fips_test_init_to_rom(
        Some(InitParams {
            rom: &rom,
            ..Default::default()
        }),
        Some(BootParams {
            initial_dbg_manuf_service_reg: (FipsTestHook::HALT_FW_LOAD as u32) << HOOK_CODE_OFFSET,
            ..Default::default()
        }),
    );

    // Start the FW load (don't wait for a result)
    let fw_image = fips_fw_image();
    hw.start_mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &fw_image)
        .unwrap();

    // Wait for ACK that ROM reached halt point
    hook_wait_for_complete(&mut hw);

    // Check output is inhibited
    verify_mbox_output_inhibited(&mut hw);
    // NOTE: SHA engine is not locked during FW load
}

fn self_test_failure_flow_rom(hook_code: u8, exp_error_code: u32) {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_FIPS_TEST_HOOKS).unwrap();

    let mut hw = fips_test_init_to_boot_start(
        Some(InitParams {
            rom: &rom,
            ..Default::default()
        }),
        Some(BootParams {
            initial_dbg_manuf_service_reg: (hook_code as u32) << HOOK_CODE_OFFSET,
            ..Default::default()
        }),
    );

    // Wait for fatal error
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);
    // Wait for the remaining operations and cleanup from a fatal error to complete
    // (This is mainly for the SW emulator which only runs when we step)
    for _ in 0..1000 {
        hw.step();
    }

    // Verify fatal code is correct
    assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), exp_error_code);

    // Verify we cannot use the algorithm
    // We can't directly call this algorithm, so check that Caliptra will not process messages
    //     Using the Load FW message since that is what uses most of the crypto anyway
    // Check that the SHA engine is not usable
    let fw_image = fips_fw_image();
    match hw.upload_firmware(&fw_image) {
        Ok(_) => panic!("FW Load should fail at this point"),
        Err(act_error) => {
            if act_error != ModelError::MailboxCmdFailed(exp_error_code) {
                panic!("FW Load received unexpected error {}", act_error)
            }
        }
    }
    verify_sha_engine_output_inhibited(&mut hw);

    // Attempt to clear the error in an undocumented way
    // Clear the error reg and attempt output again
    // Now that we have cleared the error, we expect an error code of 0 because
    // The fatal error loop that marks all mbox messages as failed does not update the error code
    hw.soc_ifc().cptra_fw_error_fatal().write(|_| 0);
    hw.soc_ifc().cptra_fw_error_non_fatal().write(|_| 0);
    match hw.upload_firmware(&fw_image) {
        Ok(_) => panic!("FW Load should fail at this point"),
        Err(ModelError::MailboxCmdFailed(0x0)) => (),
        Err(e) => panic!("FW Load received unexpected error {}", e),
    }
    verify_sha_engine_output_inhibited(&mut hw);

    // Restart Caliptra
    if cfg!(any(feature = "verilator", feature = "fpga_realtime")) {
        hw.cold_reset();
    } else {
        hw = fips_test_init_model(Some(InitParams {
            rom: &rom,
            ..Default::default()
        }))
    }
    hw.boot(BootParams::default()).unwrap();
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    // Verify crypto operations can be performed
    // Verify the SHA engine is usable
    let message: &[u8] = &[0x0, 0x1, 0x2, 0x3];
    hw.compute_sha512_acc_digest(message, ShaAccMode::Sha384Stream)
        .unwrap();

    // Verify we can load FW
    hw.upload_firmware(&fw_image).unwrap();
}

fn self_test_failure_flow_rt(hook_code: u8, exp_error_code: u32) {
    // Build FW with test hooks and init to runtime
    let fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART_FIPS_TEST_HOOKS,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    let mut hw = fips_test_init_to_rt(
        None,
        Some(BootParams {
            fw_image: Some(&fw_image),
            ..Default::default()
        }),
    );

    // Wait for RT to be ready for commands before setting hook
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    // Set the test hook
    hw.soc_ifc()
        .cptra_dbg_manuf_service_reg()
        .write(|_| (hook_code as u32) << HOOK_CODE_OFFSET);

    // Start the self tests
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_START),
            &[],
        ),
    };
    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        &mut hw,
        u32::from(CommandId::SELF_TEST_START),
        payload.as_bytes(),
    )
    .unwrap();

    // Wait for error
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);
    // Wait for the remaining operations and cleanup from a fatal error to complete
    // (This is mainly for the SW emulator which only runs when we step)
    for _ in 0..1000 {
        hw.step();
    }

    // Verify error code is correct
    assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), exp_error_code);

    // Verify we cannot use the algorithm
    match hw.upload_firmware(&fw_image) {
        Ok(_) => panic!("FW Load should fail at this point"),
        Err(act_error) => {
            if act_error != ModelError::MailboxCmdFailed(exp_error_code) {
                panic!("FW Load received unexpected error {}", act_error)
            }
        }
    }
    // Check that the SHA engine is not usable
    verify_sha_engine_output_inhibited(&mut hw);

    // Attempt to clear the error in an undocumented way
    // Clear the error reg and attempt output again
    // Now that we have cleared the error, we expect an error code of 0 because
    // The fatal error loop that marks all mbox messages as failed does not update the error code
    hw.soc_ifc().cptra_fw_error_fatal().write(|_| 0);
    hw.soc_ifc().cptra_fw_error_non_fatal().write(|_| 0);
    match hw.upload_firmware(&fw_image) {
        Ok(_) => panic!("FW Load should fail at this point"),
        Err(ModelError::MailboxCmdFailed(0x0)) => (),
        Err(e) => panic!("FW Load received unexpected error {}", e),
    }
    verify_sha_engine_output_inhibited(&mut hw);

    // Restart Caliptra
    if cfg!(any(feature = "verilator", feature = "fpga_realtime")) {
        hw.cold_reset();
    } else {
        hw = fips_test_init_model(None)
    }
    hw.boot(BootParams::default()).unwrap();
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    // Verify crypto operations can be performed
    // Verify the SHA engine is usable
    let message: &[u8] = &[0x0, 0x1, 0x2, 0x3];
    hw.compute_sha512_acc_digest(message, ShaAccMode::Sha384Stream)
        .unwrap();

    // Verify we can load FW
    hw.upload_firmware(&fw_image).unwrap();
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha1_digest_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA1_DIGEST_FAILURE,
        u32::from(CaliptraError::KAT_SHA1_DIGEST_FAILURE),
    );
}

#[test]
pub fn kat_sha1_digest_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA1_DIGEST_FAILURE,
        u32::from(CaliptraError::KAT_SHA1_DIGEST_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha1_digest_mismatch_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA1_CORRUPT_DIGEST,
        u32::from(CaliptraError::KAT_SHA1_DIGEST_MISMATCH),
    );
}

#[test]
pub fn kat_sha1_digest_mismatch_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA1_CORRUPT_DIGEST,
        u32::from(CaliptraError::KAT_SHA1_DIGEST_MISMATCH),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha256_digest_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA256_DIGEST_FAILURE,
        u32::from(CaliptraError::KAT_SHA256_DIGEST_FAILURE),
    );
}

#[test]
pub fn kat_sha256_digest_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA256_DIGEST_FAILURE,
        u32::from(CaliptraError::KAT_SHA256_DIGEST_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha256_digest_mismatch_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA256_CORRUPT_DIGEST,
        u32::from(CaliptraError::KAT_SHA256_DIGEST_MISMATCH),
    );
}

#[test]
pub fn kat_sha256_digest_mismatch_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA256_CORRUPT_DIGEST,
        u32::from(CaliptraError::KAT_SHA256_DIGEST_MISMATCH),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha384_digest_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA384_DIGEST_FAILURE,
        u32::from(CaliptraError::KAT_SHA384_DIGEST_FAILURE),
    );
}

#[test]
pub fn kat_sha384_digest_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA384_DIGEST_FAILURE,
        u32::from(CaliptraError::KAT_SHA384_DIGEST_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha384_digest_mismatch_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA384_CORRUPT_DIGEST,
        u32::from(CaliptraError::KAT_SHA384_DIGEST_MISMATCH),
    );
}

#[test]
pub fn kat_sha384_digest_mismatch_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA384_CORRUPT_DIGEST,
        u32::from(CaliptraError::KAT_SHA384_DIGEST_MISMATCH),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha2_512_384acc_digest_start_op_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA2_512_384_ACC_START_OP_FAILURE,
        u32::from(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE),
    );
}

#[test]
pub fn kat_sha2_512_384acc_digest_start_op_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA2_512_384_ACC_START_OP_FAILURE,
        u32::from(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha2_512_384acc_digest_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA2_512_384_ACC_DIGEST_512_FAILURE,
        u32::from(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_FAILURE),
    );
}

#[test]
pub fn kat_sha2_512_384acc_digest_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA2_512_384_ACC_DIGEST_512_FAILURE,
        u32::from(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_sha2_512_384acc_digest_mismatch_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::SHA2_512_384_ACC_CORRUPT_DIGEST_512,
        u32::from(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_MISMATCH),
    );
}

#[test]
pub fn kat_sha2_512_384acc_digest_mismatch_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::SHA2_512_384_ACC_CORRUPT_DIGEST_512,
        u32::from(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_MISMATCH),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_ecc384_signature_generate_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::ECC384_SIGNATURE_GENERATE_FAILURE,
        u32::from(CaliptraError::KAT_ECC384_KEY_PAIR_GENERATE_FAILURE),
    );
}

#[test]
pub fn kat_ecc384_signature_generate_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::ECC384_SIGNATURE_GENERATE_FAILURE,
        u32::from(CaliptraError::KAT_ECC384_KEY_PAIR_GENERATE_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_ecc384_signature_verify_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::ECC384_CORRUPT_SIGNATURE,
        u32::from(CaliptraError::KAT_ECC384_SIGNATURE_MISMATCH),
    );
}

#[test]
pub fn kat_ecc384_signature_verify_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::ECC384_CORRUPT_SIGNATURE,
        u32::from(CaliptraError::KAT_ECC384_SIGNATURE_MISMATCH),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_ecc384_deterministic_key_gen_generate_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::ECC384_KEY_PAIR_GENERATE_FAILURE,
        u32::from(CaliptraError::KAT_ECC384_KEY_PAIR_GENERATE_FAILURE),
    );
}

#[test]
pub fn kat_ecc384_deterministic_key_gen_generate_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::ECC384_KEY_PAIR_GENERATE_FAILURE,
        u32::from(CaliptraError::KAT_ECC384_KEY_PAIR_GENERATE_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_ecc384_deterministic_key_gen_verify_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::ECC384_CORRUPT_KEY_PAIR,
        u32::from(CaliptraError::KAT_ECC384_KEY_PAIR_VERIFY_FAILURE),
    );
}

#[test]
pub fn kat_ecc384_deterministic_key_gen_verify_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::ECC384_CORRUPT_KEY_PAIR,
        u32::from(CaliptraError::KAT_ECC384_KEY_PAIR_VERIFY_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_hmac384_failure_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::HMAC384_FAILURE,
        u32::from(CaliptraError::KAT_HMAC384_FAILURE),
    );
}

#[test]
pub fn kat_hmac384_failure_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::HMAC384_FAILURE,
        u32::from(CaliptraError::KAT_HMAC384_FAILURE),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_hmac384_tag_mismatch_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::HMAC384_CORRUPT_TAG,
        u32::from(CaliptraError::KAT_HMAC384_TAG_MISMATCH),
    );
}

#[test]
pub fn kat_hmac384_tag_mismatch_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::HMAC384_CORRUPT_TAG,
        u32::from(CaliptraError::KAT_HMAC384_TAG_MISMATCH),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn kat_lms_digest_mismatch_rom() {
    self_test_failure_flow_rom(
        FipsTestHook::LMS_CORRUPT_INPUT,
        u32::from(CaliptraError::KAT_LMS_DIGEST_MISMATCH),
    );
}

#[test]
pub fn kat_lms_digest_mismatch_rt() {
    self_test_failure_flow_rt(
        FipsTestHook::LMS_CORRUPT_INPUT,
        u32::from(CaliptraError::KAT_LMS_DIGEST_MISMATCH),
    );
}

fn find_rom_info_offset(rom: &[u8]) -> usize {
    for i in (0..rom.len()).step_by(64).rev() {
        if rom[i..][..64] != [0u8; 64] {
            return i;
        }
    }
    panic!("Could not find RomInfo");
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn integrity_check_failure_rom() {
    // NOTE: Corruption steps from test_rom_integrity.rs
    let exp_error_code = u32::from(CaliptraError::ROM_INTEGRITY_FAILURE);
    let mut rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let rom_info_offset = find_rom_info_offset(&rom);

    // Corrupt a bit in the ROM info hash (we don't want to pick an arbitrary
    // location in the image as that might make the CPU crazy)
    rom[rom_info_offset + 9] ^= 1;

    let mut hw = fips_test_init_to_boot_start(
        Some(InitParams {
            rom: &rom,
            ..Default::default()
        }),
        None,
    );

    // Wait for fatal error
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);
    // Wait for the remaining operations and cleanup from a fatal error to complete
    // (This is mainly for the SW emulator which only runs when we step)
    for _ in 0..1000 {
        hw.step();
    }

    // Verify fatal code is correct
    assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), exp_error_code);

    // Verify we cannot send messages or use the SHA engine
    let fw_image = fips_fw_image();
    match hw.upload_firmware(&fw_image) {
        Ok(_) => panic!("FW Load should fail at this point"),
        Err(act_error) => {
            if act_error != ModelError::MailboxCmdFailed(exp_error_code) {
                panic!("FW Load received unexpected error {}", act_error)
            }
        }
    }
    verify_sha_engine_output_inhibited(&mut hw);

    // Attempt to clear the error in an undocumented way
    // Clear the error reg and attempt output again
    // Now that we have cleared the error, we expect an error code of 0 because
    // The fatal error loop that marks all mbox messages as failed does not update the error code
    hw.soc_ifc().cptra_fw_error_fatal().write(|_| 0);
    hw.soc_ifc().cptra_fw_error_non_fatal().write(|_| 0);
    match hw.upload_firmware(&fw_image) {
        Ok(_) => panic!("FW Load should fail at this point"),
        Err(ModelError::MailboxCmdFailed(0x0)) => (),
        Err(e) => panic!("FW Load received unexpected error {}", e),
    }
    verify_sha_engine_output_inhibited(&mut hw);

    // This error cannot be cleared.
}

// TODO: Enable once https://github.com/chipsalliance/caliptra-sw/issues/1598 is addressed
// Operations with invalid key pairs not supported by SW emulator
// #[test]
// #[cfg(not(feature = "test_env_immutable_rom"))]
// #[cfg(any(feature = "verilator", feature = "fpga_realtime"))]
// pub fn ecc384_pairwise_consistency_error() {
//     self_test_failure_flow_rom(
//         FipsTestHook::ECC384_PAIRWISE_CONSISTENCY_ERROR,
//         u32::from(CaliptraError::DRIVER_ECC384_KEYGEN_PAIRWISE_CONSISTENCY_FAILURE),
//     );
// }

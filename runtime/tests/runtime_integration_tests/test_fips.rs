// Licensed under the Apache-2.0 license.

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};
use caliptra_api::SocManager;
use caliptra_builder::{version, ImageOptions};
use caliptra_common::mailbox_api::{
    CommandId, FipsVersionResp, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_hw_model::HwModel;
use caliptra_runtime::FipsVersionCmd;
use zerocopy::{FromBytes, IntoBytes};

const HW_REV_ID: u32 = 0x112;

#[cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
mod autonomous {
    use super::*;
    use caliptra_builder::firmware::APP_WITH_UART_FIPS_TEST_HOOKS;
    use caliptra_common::mailbox_api::{
        populate_checksum, CmHashAlgorithm, CmShaFinalReq, CmShaFinalResp, CmShaInitReq,
        CmShaInitResp, CmShake256FinalReq, CmShake256InitReq, CmShake256InitResp, MailboxReq,
        ResponseVarSize, MAX_CMB_DATA_SIZE,
    };
    use caliptra_drivers::CaliptraError;
    use caliptra_drivers::FipsTestHook;
    use caliptra_hw_model::{DefaultHwModel, ModelError, SecurityState};
    use caliptra_runtime::RtBootStatus;
    use sha2::{Digest, Sha512};

    const MAX_TEST_CYCLES: u32 = 20_000_000;

    fn config(count: u32, scale: u32) -> u32 {
        1 | (count << 1) | (scale << 17)
    }

    fn boot(config: u32) -> DefaultHwModel {
        let mut model = run_rt_test(RuntimeTestArgs {
            rom_callback: Some(Box::new(move |m| m.set_generic_input_wires(&[0, config]))),
            security_state: Some(*SecurityState::default().set_debug_locked(true)),
            ..Default::default()
        });
        model.step_until_or_timeout("runtime mailbox idle", MAX_TEST_CYCLES, |m| {
            m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle()
        });
        model.output().take(usize::MAX);
        model
    }

    fn request(cmd: u32) -> MailboxReqHeader {
        MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(cmd, &[]),
        }
    }

    fn send(model: &mut DefaultHwModel, cmd: CommandId) {
        let cmd = u32::from(cmd);
        let bytes = model
            .mailbox_execute(cmd, request(cmd).as_bytes())
            .unwrap()
            .unwrap();
        let (header, _) = MailboxRespHeader::ref_from_prefix(bytes.as_slice()).unwrap();
        assert_eq!(header.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);
        assert!(caliptra_common::checksum::verify_checksum(
            header.chksum,
            0,
            &bytes[4..]
        ));
    }

    fn step_idle(model: &mut DefaultHwModel) {
        for _ in 0..10_000 {
            model.step();
        }
        assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
    }

    fn expect_no_test(model: &mut DefaultHwModel) {
        step_idle(model);
        assert!(!model.output().peek().contains("[kat] ++"));
    }

    fn wait_for_test(model: &mut DefaultHwModel) {
        use caliptra_drivers::memory_layout::{BOOT_STATUS_ORG, DCCM_ORG};

        model.step_until_or_timeout("autonomous self-test completion", MAX_TEST_CYCLES, |m| {
            m.cpu_halted() && m.output().peek().contains("[kat] --")
        });
        // Debug-locked devices keep boot status in DCCM, not the SoC-visible register.
        let status = model.dccm_read(BOOT_STATUS_ORG - DCCM_ORG, 4);
        assert_eq!(
            u32::from_le_bytes(status.try_into().unwrap()),
            u32::from(RtBootStatus::RtFipSelfTestComplete)
        );
        assert!(model.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());
        assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
        model.output().take(usize::MAX);
    }

    #[test]
    fn threshold_repeats_and_runtime_disable_is_ignored() {
        let mut model = boot(config(3, 0));
        model.set_generic_input_wires(&[0, 0]);

        for _ in 0..2 {
            for _ in 0..2 {
                send(&mut model, CommandId::VERSION);
                expect_no_test(&mut model);
            }
            send(&mut model, CommandId::VERSION);
            wait_for_test(&mut model);
            expect_no_test(&mut model);
        }
    }

    #[test]
    fn disabled_configuration_cannot_be_enabled_at_runtime() {
        let mut model = boot(0);
        model.set_generic_input_wires(&[0, config(1, 0)]);
        for _ in 0..4 {
            send(&mut model, CommandId::VERSION);
            expect_no_test(&mut model);
        }
    }

    #[test]
    fn warm_reset_latches_the_new_configuration() {
        let mut model = boot(config(3, 0));
        model.set_generic_input_wires(&[0, config(1, 0)]);
        send(&mut model, CommandId::VERSION);
        expect_no_test(&mut model);

        model.warm_reset_flow().unwrap();
        model.step_until_ready_for_runtime();
        model.output().take(usize::MAX);
        send(&mut model, CommandId::VERSION);
        wait_for_test(&mut model);
    }

    #[test]
    fn multiplier_changes_the_command_threshold() {
        let mut model = boot(config(1, 1));
        model.set_generic_input_wires(&[0, config(1, 0)]);
        for _ in 0..15 {
            send(&mut model, CommandId::VERSION);
            expect_no_test(&mut model);
        }
        send(&mut model, CommandId::VERSION);
        wait_for_test(&mut model);
    }

    #[test]
    fn failed_commands_count_and_autonomous_tests_do_not_create_manual_results() {
        let mut model = boot(config(2, 0));
        send(&mut model, CommandId::VERSION);
        expect_no_test(&mut model);

        let err = model
            .mailbox_execute(CommandId::VERSION.into(), &[0; 4])
            .unwrap_err();
        assert!(matches!(err, ModelError::MailboxCmdFailed(_)));
        wait_for_test(&mut model);

        let cmd = u32::from(CommandId::SELF_TEST_GET_RESULTS);
        assert_eq!(
            model
                .mailbox_execute(cmd, request(cmd).as_bytes())
                .unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED.into())
        );
    }

    #[test]
    fn unread_manual_results_do_not_block_autonomous_tests() {
        let mut model = boot(config(2, 0));
        send(&mut model, CommandId::SELF_TEST_START);
        wait_for_test(&mut model);

        for _ in 0..2 {
            send(&mut model, CommandId::VERSION);
            expect_no_test(&mut model);
            send(&mut model, CommandId::VERSION);
            wait_for_test(&mut model);
        }
        send(&mut model, CommandId::SELF_TEST_GET_RESULTS);
        let cmd = u32::from(CommandId::SELF_TEST_GET_RESULTS);
        assert_eq!(
            model
                .mailbox_execute(cmd, request(cmd).as_bytes())
                .unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED.into())
        );
        wait_for_test(&mut model);
    }

    #[test]
    fn pending_test_waits_for_response_release_without_another_command() {
        let mut model = boot(config(1, 0));
        let cmd = u32::from(CommandId::VERSION);
        model
            .start_mailbox_exec(cmd, request(cmd).as_bytes())
            .unwrap();
        model.step_until_or_timeout("VERSION response", MAX_TEST_CYCLES, |m| {
            m.soc_mbox().status().read().status().data_ready()
        });
        expect_no_test(&mut model);
        assert!(model.soc_mbox().status().read().status().data_ready());

        let mut response = [0; 64];
        model.finish_mailbox_exec(&mut response).unwrap().unwrap();
        wait_for_test(&mut model);
    }

    #[test]
    fn pending_sha_command_finishes_before_due_self_test() {
        let mut model = boot(config(2, 0));
        let mut init = MailboxReq::CmShaInit(CmShaInitReq {
            hash_algorithm: u32::from(CmHashAlgorithm::Sha512),
            ..Default::default()
        });
        init.populate_chksum().unwrap();
        let bytes = model
            .mailbox_execute(CommandId::CM_SHA_INIT.into(), init.as_bytes().unwrap())
            .unwrap()
            .unwrap();
        let context = CmShaInitResp::ref_from_bytes(bytes.as_slice())
            .unwrap()
            .context;
        expect_no_test(&mut model);

        let input = [0x5a; MAX_CMB_DATA_SIZE];
        let mut finish = MailboxReq::CmShaFinal(CmShaFinalReq {
            context,
            input_size: input.len() as u32,
            input,
            ..Default::default()
        });
        finish.populate_chksum().unwrap();

        send(&mut model, CommandId::VERSION);
        // Queue the SHA command before RT can enter idle after the threshold response.
        model
            .start_mailbox_exec(CommandId::CM_SHA_FINAL.into(), finish.as_bytes().unwrap())
            .unwrap();
        assert!(model.soc_mbox().status().read().status().cmd_busy());
        model.step_until_or_timeout("SHA command response", MAX_TEST_CYCLES, |m| {
            assert!(!m.output().peek().contains("[kat] ++"));
            m.soc_mbox().status().read().status().data_ready()
        });
        expect_no_test(&mut model);

        let mut response = [0; core::mem::size_of::<CmShaFinalResp>()];
        let bytes = model.finish_mailbox_exec(&mut response).unwrap().unwrap();
        let mut expected = CmShaFinalResp::default();
        expected.hdr.data_len = 64;
        expected.hash.copy_from_slice(&Sha512::digest(input));
        populate_checksum(expected.as_bytes_partial_mut().unwrap());
        assert_eq!(bytes, expected.as_bytes_partial().unwrap());

        wait_for_test(&mut model);
    }

    #[test]
    fn self_test_failure_is_fatal_after_the_triggering_response() {
        let mut model = run_rt_test(RuntimeTestArgs {
            test_fwid: Some(&APP_WITH_UART_FIPS_TEST_HOOKS),
            rom_callback: Some(Box::new(|m| m.set_generic_input_wires(&[0, config(1, 0)]))),
            ..Default::default()
        });
        model
            .soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| u32::from(FipsTestHook::SHA256_DIGEST_FAILURE) << 16);
        send(&mut model, CommandId::VERSION);
        model.step_until_fatal_error(
            CaliptraError::KAT_SHA256_DIGEST_FAILURE.into(),
            MAX_TEST_CYCLES,
        );
        let cmd = u32::from(CommandId::VERSION);
        assert_eq!(
            model
                .mailbox_execute(cmd, request(cmd).as_bytes())
                .unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::KAT_SHA256_DIGEST_FAILURE.into())
        );
    }

    #[test]
    fn invalid_enabled_configuration_fails_startup() {
        let mut model = run_rt_test(RuntimeTestArgs {
            rom_callback: Some(Box::new(|m| m.set_generic_input_wires(&[0, 1]))),
            successful_reach_rt: false,
            ..Default::default()
        });
        model.step_until_fatal_error(
            CaliptraError::RUNTIME_INVALID_SELF_TEST_CONFIG.into(),
            MAX_TEST_CYCLES,
        );
        assert!(!model
            .soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_runtime());
    }

    #[test]
    fn self_test_invalidates_live_shake256_context() {
        let mut model = boot(config(2, 0));
        let mut init = MailboxReq::CmShake256Init(CmShake256InitReq::default());
        init.populate_chksum().unwrap();
        let bytes = model
            .mailbox_execute(CommandId::CM_SHAKE256_INIT.into(), init.as_bytes().unwrap())
            .unwrap()
            .unwrap();
        let context = CmShake256InitResp::ref_from_bytes(bytes.as_slice())
            .unwrap()
            .context;
        expect_no_test(&mut model);
        send(&mut model, CommandId::VERSION);
        wait_for_test(&mut model);

        let mut finish = MailboxReq::CmShake256Final(CmShake256FinalReq {
            context,
            ..Default::default()
        });
        finish.populate_chksum().unwrap();
        assert_eq!(
            model
                .mailbox_execute(
                    CommandId::CM_SHAKE256_FINAL.into(),
                    finish.as_bytes().unwrap()
                )
                .unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_CM_SHAKE256_CONTEXT_MISMATCH.into()
            )
        );
    }
}

#[test]
fn test_fips_version() {
    let args = RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            fmc_version: version::get_fmc_version(),
            app_version: version::get_runtime_version(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // VERSION
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };

    let fips_version_resp = model
        .mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes())
        .unwrap()
        .unwrap();

    // Check command size
    let fips_version_bytes: &[u8] = fips_version_resp.as_bytes();

    // Check values against expected.
    let fips_version = FipsVersionResp::read_from_bytes(fips_version_bytes).unwrap();
    assert!(caliptra_common::checksum::verify_checksum(
        fips_version.hdr.chksum,
        0x0,
        &fips_version.as_bytes()[core::mem::size_of_val(&fips_version.hdr.chksum)..],
    ));
    assert_eq!(
        fips_version.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(fips_version.mode, FipsVersionCmd::MODE);
    // fw_rev[0] is FMC version at 31:16 and ROM version at 15:0
    // Ignore ROM version since this test is for runtime
    let fw_version_0_expected = (version::get_fmc_version() as u32) << 16;
    assert_eq!(
        [
            fips_version.fips_rev[0],
            fips_version.fips_rev[1] & 0xFFFF0000, // Mask out the ROM version
            fips_version.fips_rev[2],
        ],
        [
            HW_REV_ID,
            fw_version_0_expected,
            version::get_runtime_version()
        ]
    );
    let name = &fips_version.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());
}

#[test]
fn test_fips_shutdown() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    // SHUTDOWN
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::SHUTDOWN), payload.as_bytes())
        .unwrap()
        .unwrap();

    let resp = MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
    // Verify checksum and FIPS status
    assert!(caliptra_common::checksum::verify_checksum(
        resp.chksum,
        0x0,
        &resp.as_bytes()[core::mem::size_of_val(&resp.chksum)..],
    ));
    assert_eq!(resp.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);

    // Check we are rejecting additional commands with the shutdown error code.
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes())
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_SHUTDOWN,
        resp,
    );
}

#[cfg_attr(feature = "verilator", ignore)]
#[cfg_attr(feature = "fpga_realtime", ignore)]
#[cfg_attr(feature = "fpga_subsystem", ignore)]
#[test]
fn test_fips_shutdown_zeroizes_persistent_data() {
    use caliptra_drivers::{
        memory_layout, DataVault, FwPersistentData, PersistentData, RomPersistentData,
    };
    use core::mem::{offset_of, size_of};

    let persistent_data_offset = memory_layout::PERSISTENT_DATA_ORG - memory_layout::DCCM_ORG;
    let persistent_data_size = size_of::<PersistentData>();

    // Regions excluded from the byte-level zero check:
    //  - DPE state: external crate whose fieldless-enum Zeroize derives are
    //    no-ops on the discriminant byte (pre-existing upstream limitation).
    //    The DPE slot starts at the beginning of FwPersistentData; its size is
    //    the offset of the next field (ecc_rtalias_tbs).
    //  - DataVault: intentionally kept via #[zeroize(skip)].
    let dpe_slot_size = offset_of!(FwPersistentData, ecc_rtalias_tbs);
    let skip_ranges: &[(usize, usize)] = &[
        (
            offset_of!(PersistentData, fw),
            offset_of!(PersistentData, fw) + dpe_slot_size,
        ),
        (
            offset_of!(PersistentData, rom) + offset_of!(RomPersistentData, data_vault),
            offset_of!(PersistentData, rom)
                + offset_of!(RomPersistentData, data_vault)
                + size_of::<DataVault>(),
        ),
    ];

    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let nonzero = model
        .dccm_read(persistent_data_offset, persistent_data_size)
        .iter()
        .any(|b| *b != 0);
    assert!(nonzero, "The persistent data was not initialized");

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };

    model
        .mailbox_execute(u32::from(CommandId::SHUTDOWN), payload.as_bytes())
        .unwrap()
        .unwrap();

    let dccm = model.dccm_read(persistent_data_offset, persistent_data_size);
    for (offset, &byte) in dccm.iter().enumerate() {
        if skip_ranges.iter().any(|(s, e)| offset >= *s && offset < *e) {
            continue;
        }
        assert_eq!(
            byte, 0,
            "PersistentData not zeroed at offset 0x{offset:x}: got 0x{byte:02x}"
        );
    }
}

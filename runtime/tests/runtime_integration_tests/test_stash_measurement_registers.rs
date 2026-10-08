// Licensed under the Apache-2.0 license

use crate::common::{rom_for_fw_integration_tests, run_rt_test, RuntimeTestArgs};
use caliptra_api::SocManager;
use caliptra_api_types::SecurityState;
use caliptra_builder::firmware::{
    APP_WITH_UART_STASH_MEASUREMENT_REGISTERS, APP_WITH_UART_STASH_MEASUREMENT_REGISTERS_FPGA,
};
use caliptra_common::{
    mailbox_api::{
        CommandId, GetTaggedTciReq, GetTaggedTciResp, MailboxReq, MailboxReqHeader,
        QuotePcrsEcc384Req, QuotePcrsEcc384Resp, TagTciReq,
    },
    memory_layout::{ROM_ORG, ROM_SIZE, ROM_STACK_ORG, ROM_STACK_SIZE, STACK_ORG, STACK_SIZE},
    FMC_ORG, FMC_SIZE, RUNTIME_ORG, RUNTIME_SIZE,
};
use caliptra_drivers::soc_ifc::stash_measurement::{StashMeasurementData, DWORDS_PER_SLOT};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    CaliptraHwVersion, CodeRange, DefaultHwModel, HwModel, ImageInfo, InitParams, StackInfo,
    StackRange,
};
use caliptra_runtime::RtBootStatus;
use sha2::{Digest, Sha384};
use zerocopy::{FromBytes, IntoBytes};

const MAX_WAIT_CYCLES: u32 = 30_000_000;

const MEASUREMENTS: [StashMeasurementData; 2] = [
    StashMeasurementData {
        metadata: [0xa1; 4],
        measurement: [0xb1; 48],
        context: [0xc1; 48],
        svn: 0xdeadbeef,
    },
    StashMeasurementData {
        metadata: [0xa2; 4],
        measurement: [0xb2; 48],
        context: [0xc2; 48],
        svn: 0xdeadc0de,
    },
];

fn run_model(
    hw_version: CaliptraHwVersion,
    subsystem_mode: bool,
    debug_locked: bool,
) -> DefaultHwModel {
    let rom = rom_for_fw_integration_tests().unwrap();
    let image_info = vec![
        ImageInfo::with_name(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
            "caliptra-rom".to_owned(),
        ),
        ImageInfo::with_name(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
            "caliptra-fmc".to_owned(),
        ),
        ImageInfo::with_name(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
            "caliptra-runtime".to_owned(),
        ),
    ];
    let runtime_test_args = RuntimeTestArgs {
        test_fwid: Some(if cfg!(feature = "fpga_realtime") {
            &APP_WITH_UART_STASH_MEASUREMENT_REGISTERS_FPGA
        } else {
            &APP_WITH_UART_STASH_MEASUREMENT_REGISTERS
        }),
        successful_reach_rt: false,
        init_params: Some(InitParams {
            hw_version,
            rom: &rom,
            stack_info: Some(StackInfo::new(image_info)),
            subsystem_mode,
            security_state: *SecurityState::default().set_debug_locked(debug_locked),
            ..Default::default()
        }),
        ..Default::default()
    };

    run_rt_test(runtime_test_args)
}

#[test]
fn test_drain_stash_measurements() {
    let mut model = run_model(CaliptraHwVersion::V2_2, false, false);

    // SoC writes measurements.
    for (i, measurement) in MEASUREMENTS.iter().enumerate() {
        for (j, chunk) in measurement.as_bytes().chunks_exact(4).enumerate() {
            model
                .soc_ifc()
                .stash_bank_slot_data()
                .at(i * DWORDS_PER_SLOT + j)
                .write(|_| u32::from_le_bytes(chunk.try_into().unwrap()))
        }
        model
            .soc_ifc()
            .stash_bank_soc_lock()
            .write(|x| x.lock(1 << i));
    }

    // SoC writes end-of-stash.
    model
        .soc_ifc()
        .stash_end_stash()
        .write(|x| x.end_stash(true));

    // Fast-forward to the mailbox command loop.
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // At this point Caliptra should have draind the measurements and
    // have locked the bank.
    assert!(model.soc_ifc().stash_bank_status().read().cptra_lock());

    // Verify the measurements actually landed in PCR31.
    let mut cmd = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
    let resp = QuotePcrsEcc384Resp::read_from_bytes(resp.as_slice()).unwrap();

    let mut expected_pcr31 = [0u8; 48];
    for measurement in MEASUREMENTS.iter() {
        let mut hasher = Sha384::new();
        hasher.update(expected_pcr31);
        hasher.update(measurement.measurement);
        expected_pcr31.copy_from_slice(&hasher.finalize());
    }
    assert_eq!(resp.pcrs[31], expected_pcr31);

    // Verify DPE actually derived a context for the drained measurements.
    // The default context should be derived from the last measurement, and
    // its current TCI should match the test measurement.
    const TAG: u32 = 0xc01d_cafe;
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        // Default context handle.
        handle: [0u8; 16],
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We should have received a response");

    let mut cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
    let resp = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();

    assert_eq!(resp.tci_current, MEASUREMENTS[1].measurement);
    assert_ne!(resp.tci_cumulative, resp.tci_current);
    assert_ne!(resp.tci_cumulative, [0u8; 48]);
}

#[test]
fn test_soc_populates_measurements_with_gaps() {
    let mut model = run_model(CaliptraHwVersion::V2_2, false, false);

    // SoC writes measurements.
    for (i, measurement) in MEASUREMENTS.iter().enumerate() {
        for (j, chunk) in measurement.as_bytes().chunks_exact(4).enumerate() {
            model
                .soc_ifc()
                .stash_bank_slot_data()
                .at(i * DWORDS_PER_SLOT + j)
                .write(|_| u32::from_le_bytes(chunk.try_into().unwrap()))
        }

        // Skip locking the very first slot.
        if i != 0 {
            model
                .soc_ifc()
                .stash_bank_soc_lock()
                .write(|x| x.lock(1 << i));
        }
    }

    // SoC writes end-of-stash.
    model
        .soc_ifc()
        .stash_end_stash()
        .write(|x| x.end_stash(true));

    // Fast-forward until the error happens.
    model.step_until_fatal_error(
        CaliptraError::RUNTIME_STASH_MEASUREMENT_BANK_INVALID_STATUS.into(),
        MAX_WAIT_CYCLES,
    );
}

#[test]
fn test_soc_populates_no_measurement() {
    let mut model = run_model(CaliptraHwVersion::V2_2, false, false);

    // SoC writes end-of-stash.
    model
        .soc_ifc()
        .stash_end_stash()
        .write(|x| x.end_stash(true));

    // Fast-forward to the mailbox command loop.
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // At this point Caliptra should have locked the bank.
    assert!(model.soc_ifc().stash_bank_status().read().cptra_lock());

    // Verify that PCR31 is not populated.
    let mut cmd = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
    let resp = QuotePcrsEcc384Resp::read_from_bytes(resp.as_slice()).unwrap();

    let expected_pcr31 = [0u8; 48];
    assert_eq!(resp.pcrs[31], expected_pcr31);
}

#[test]
fn test_soc_never_asserted_end_of_stash() {
    // Set debug locked to allow watchdog timer to fire.
    let mut model = run_model(CaliptraHwVersion::V2_2, false, true);

    // Fast-forward until the watchdog timer fires.
    model.step_until_fatal_error(
        CaliptraError::RUNTIME_GLOBAL_WDT_EXPIRED.into(),
        MAX_WAIT_CYCLES,
    );
}

#[test]
// The hardware revision is only honored by the emulated model. The version of
// the FPGA bitstream version is fixed, so the scenario can't be set up in that case.
#[cfg(not(feature = "fpga_realtime"))]
fn test_draining_is_skipped_on_old_hardware() {
    let mut model = run_model(CaliptraHwVersion::V2_1, false, false);

    // Fast-forward to the mailbox command loop. Boot status is not reported
    // while debug is locked, so wait for ready_for_runtime instead.
    model.step_until_or_timeout("ready_for_runtime", MAX_WAIT_CYCLES, |m| {
        m.soc_ifc().cptra_flow_status().read().ready_for_runtime()
    });

    // Verify that PCR31 is not populated.
    let mut cmd = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
    let resp = QuotePcrsEcc384Resp::read_from_bytes(resp.as_slice()).unwrap();

    let expected_pcr31 = [0u8; 48];
    assert_eq!(resp.pcrs[31], expected_pcr31);
}

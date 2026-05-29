// Licensed under the Apache-2.0 license.

//! Measures the peak runtime stack usage of each Runtime Command.
//!
//! This walks a representative subset of the commands dispatched by
//! `handle_command()` and, for each, drives the command with a simple
//! representative parameter set while the emulator tracks the lowest stack
//! pointer reached. Peak usage is the distance from the top of the runtime
//! stack down to that high-water mark.
//!
//! The mechanism relies on the emulator's stack-pointer tracking, so this test
//! only runs against the software emulator (not verilator/FPGA).
#![cfg(not(any(feature = "verilator", feature = "fpga_realtime")))]

use crate::common::{
    execute_dpe_cmd, run_rt_test, DpeResult, RuntimeTestArgs, TEST_DIGEST, TEST_LABEL,
};
use caliptra_api::SocManager;
use caliptra_common::{
    mailbox_api::{
        CommandId, EcdsaVerifyReq, MailboxReq, MailboxReqHeader, QuotePcrsReq, StashMeasurementReq,
    },
    memory_layout::{STACK_ORG, STACK_SIZE},
};
use caliptra_hw_model::{DefaultHwModel, HwModel, ShaAccMode};
use caliptra_runtime::RtBootStatus;
use dpe::{
    commands::{CertifyKeyCmd, CertifyKeyFlags, Command},
    context::ContextHandle,
};
use zerocopy::IntoBytes;

/// Top of the runtime stack. The stack grows downward from here, so peak usage
/// is `STACK_TOP - min_sp`.
const STACK_TOP: u32 = STACK_ORG + STACK_SIZE;

/// Read the peak stack usage (in bytes) observed since the last reset.
fn peak_stack_usage(model: &DefaultHwModel) -> u32 {
    let min_sp = model
        .stack_min_sp()
        .expect("no stack activity observed; was the model built with stack_info?");
    STACK_TOP - min_sp
}

/// Run a single mailbox command and return its peak stack usage in bytes.
///
/// The high-water mark is reset immediately before the command is dispatched so
/// the measurement captures only the stack consumed while servicing it.
fn measure_mbox_cmd(model: &mut DefaultHwModel, cmd_id: u32, req: &[u8]) -> u32 {
    model.reset_stack_high_water();
    // We only care that the command executes; the response contents are
    // irrelevant for stack measurement, and some commands legitimately fail
    // (e.g. a verify of a zero signature) while still exercising their stack.
    let _ = model.mailbox_execute(cmd_id, req);
    peak_stack_usage(model)
}

/// Build a header-only request (commands that take no payload).
fn header_only(cmd_id: u32) -> Vec<u8> {
    MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(cmd_id, &[]),
    }
    .as_bytes()
    .to_vec()
}

#[test]
fn measure_runtime_command_stack_usage() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // (name, peak stack usage in bytes)
    let mut results: Vec<(&str, u32)> = Vec::new();

    // --- Commands with no payload (header only) ---
    for (name, cmd_id) in [
        ("VERSION", CommandId::VERSION),
        ("CAPABILITIES", CommandId::CAPABILITIES),
        ("FW_INFO", CommandId::FW_INFO),
        ("GET_IDEV_INFO", CommandId::GET_IDEV_INFO),
        ("GET_FMC_ALIAS_CERT", CommandId::GET_FMC_ALIAS_CERT),
        ("GET_RT_ALIAS_CERT", CommandId::GET_RT_ALIAS_CERT),
    ] {
        let cmd_id = u32::from(cmd_id);
        let req = header_only(cmd_id);
        results.push((name, measure_mbox_cmd(&mut model, cmd_id, &req)));
    }

    // --- STASH_MEASUREMENT ---
    {
        let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq {
            measurement: TEST_DIGEST,
            ..Default::default()
        });
        cmd.populate_chksum().unwrap();
        results.push((
            "STASH_MEASUREMENT",
            measure_mbox_cmd(
                &mut model,
                u32::from(CommandId::STASH_MEASUREMENT),
                cmd.as_bytes().unwrap(),
            ),
        ));
    }

    // --- ECDSA384_VERIFY (heavy crypto) ---
    {
        // The command reads the message digest from the SHA accelerator, so it
        // must be primed before dispatch. This streaming happens host-side and
        // does not run firmware, but we reset the high-water mark afterward
        // anyway via measure_mbox_cmd to be safe.
        model
            .compute_sha512_acc_digest(&TEST_DIGEST, ShaAccMode::Sha384Stream)
            .unwrap();
        let mut cmd = MailboxReq::EcdsaVerify(EcdsaVerifyReq {
            hdr: MailboxReqHeader { chksum: 0 },
            pub_key_x: [0u8; 48],
            pub_key_y: [0u8; 48],
            signature_r: [0u8; 48],
            signature_s: [0u8; 48],
        });
        cmd.populate_chksum().unwrap();
        results.push((
            "ECDSA384_VERIFY",
            measure_mbox_cmd(
                &mut model,
                u32::from(CommandId::ECDSA384_VERIFY),
                cmd.as_bytes().unwrap(),
            ),
        ));
    }

    // --- QUOTE_PCRS (heavy: collects PCRs and signs) ---
    {
        let mut cmd = MailboxReq::QuotePcrs(QuotePcrsReq {
            hdr: MailboxReqHeader { chksum: 0 },
            nonce: [0u8; 32],
        });
        cmd.populate_chksum().unwrap();
        results.push((
            "QUOTE_PCRS",
            measure_mbox_cmd(
                &mut model,
                u32::from(CommandId::QUOTE_PCRS),
                cmd.as_bytes().unwrap(),
            ),
        ));
    }

    // --- INVOKE_DPE: GetProfile (light DPE path) ---
    {
        model.reset_stack_high_water();
        let _ = execute_dpe_cmd(&mut model, &mut Command::GetProfile, DpeResult::Success);
        results.push(("INVOKE_DPE(GetProfile)", peak_stack_usage(&model)));
    }

    // --- INVOKE_DPE: CertifyKey/X509 (heavy DPE path) ---
    {
        let mut certify_key_cmd = Command::CertifyKey(&CertifyKeyCmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCmd::FORMAT_X509,
        });
        model.reset_stack_high_water();
        let _ = execute_dpe_cmd(&mut model, &mut certify_key_cmd, DpeResult::Success);
        results.push(("INVOKE_DPE(CertifyKey/X509)", peak_stack_usage(&model)));
    }

    // Report, highest stack usage first.
    results.sort_by(|a, b| b.1.cmp(&a.1));
    println!(
        "\nRuntime command peak stack usage (runtime stack = {} bytes):",
        STACK_SIZE
    );
    println!("{:<32} {:>10} {:>8}", "command", "bytes", "% stack");
    println!("{}", "-".repeat(52));
    for (name, bytes) in &results {
        let pct = (*bytes as f64) * 100.0 / (STACK_SIZE as f64);
        println!("{name:<32} {bytes:>10} {pct:>7.1}%");
    }

    // Sanity: every command must consume some stack and stay within the budget.
    for (name, bytes) in &results {
        assert!(*bytes > 0, "{name} reported zero stack usage");
        assert!(
            *bytes < STACK_SIZE,
            "{name} stack usage {bytes} exceeds runtime stack size {STACK_SIZE}"
        );
    }
}

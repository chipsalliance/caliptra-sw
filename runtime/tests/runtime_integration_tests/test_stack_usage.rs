// Licensed under the Apache-2.0 license.

//! Measures the peak runtime stack usage of each Runtime Command.
//!
//! This walks every command dispatched by `handle_command()` and, for each,
//! drives it with a simple representative parameter set while the emulator
//! tracks the lowest stack pointer reached. Peak usage is the distance from the
//! top of the runtime stack down to that high-water mark, i.e. the absolute
//! deepest the stack gets while servicing the command (including the dispatch
//! frames already on the stack).
//!
//! Commands are issued in an order that respects state dependencies: state
//! builders (auth manifest, exported CDI, tagged contexts) run before their
//! consumers, and the side-effecting `DISABLE_ATTESTATION` / `SHUTDOWN` run
//! last.
//!
//! When built with `mldsa_attestation`, the test runs against the PQC-enabled
//! firmware and additionally measures the ML-DSA-87 commands via
//! `run_pqc_command_suite` (`SET_PQ_SEED`, `GET_PQ_CSR`,
//! `CERTIFY_KEY_EXTENDED_MLDSA87`, `MLDSA87_SIGNATURE_VERIFY`, `GET_PQ_CERT`,
//! `POPULATE_PQ_CERT`). The order matters: `SET_PQ_SEED` provisions the PQ.DevID
//! CDI and enables PQC mode, so running `GET_PQ_CSR` / `CERTIFY_KEY_EXTENDED_MLDSA87`
//! afterwards exercises their full ML-DSA-87 keygen+sign paths (the maximal stack
//! consumers) rather than early-returning.
//!
//! The mechanism relies on the emulator's stack-pointer tracking, so this test
//! only runs against the software emulator (not verilator/FPGA).
#![cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "sw_emu_stack_check_disable"
)))]

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_measurements_common::{run_command_suite, CommandSampler};
use caliptra_api::SocManager;
use caliptra_common::memory_layout::{STACK_ORG, STACK_SIZE};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;

#[cfg(feature = "mldsa_attestation")]
use crate::test_measurements_common::{measure_mldsa_dpe_subcommands, run_pqc_command_suite};
#[cfg(feature = "mldsa_attestation")]
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;

/// Top of the runtime stack. The stack grows downward from here, so peak usage
/// is `STACK_TOP - min_sp`.
const STACK_TOP: u32 = STACK_ORG + STACK_SIZE;

fn peak_stack_usage(model: &DefaultHwModel) -> Option<u32> {
    model.stack_min_sp().map(|min_sp| STACK_TOP - min_sp)
}

struct StackSampler;

impl CommandSampler for StackSampler {
    fn before(&mut self, model: &mut DefaultHwModel) {
        model.reset_stack_high_water();
    }

    fn after(&mut self, model: &mut DefaultHwModel) -> u64 {
        let peak = peak_stack_usage(model)
            .expect("no stack activity observed; was the model built with stack_info?");
        // When CALIPTRA_EMU_STACK_WATERMARK_LOG is set, append this command's
        // high-water `(pc, sp)` events so they can be symbolized against the
        // firmware ELF. Each block is labeled by peak so commands are distinguishable.
        if let Some(path) = std::env::var_os("CALIPTRA_EMU_STACK_WATERMARK_LOG") {
            use std::io::Write;
            let events = model.take_stack_watermark_events();
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open stack watermark log");
            writeln!(f, "# peak_bytes={} events={}", peak, events.len()).unwrap();
            for (pc, sp) in events {
                writeln!(f, "{pc:#010x} {sp:#010x}").unwrap();
            }
        }
        // When CALIPTRA_EMU_STACK_SP_TRACE is set, append this command's full
        // stack-pointer-change trace (allocs and frees). A post-processor replays
        // it to reconstruct the live call stack and read off any sub-chain (e.g.
        // ML-DSA sign) frame-by-frame, independent of the global peak path.
        if let Some(path) = std::env::var_os("CALIPTRA_EMU_STACK_SP_TRACE") {
            use std::io::Write;
            let events = model.take_stack_sp_events();
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open stack sp trace");
            writeln!(f, "# peak_bytes={} sp_events={}", peak, events.len()).unwrap();
            for (pc, sp) in events {
                writeln!(f, "{pc:#010x} {sp:#010x}").unwrap();
            }
        }
        peak as u64
    }
}

#[test]
fn measure_runtime_command_stack_usage() {
    #[cfg(feature = "mldsa_attestation")]
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    #[cfg(not(feature = "mldsa_attestation"))]
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut results: Vec<(&'static str, u32)> = Vec::new();

    // Measure the PQC commands first so GET_PQ_CSR / CERTIFY_KEY_EXTENDED_MLDSA87
    // run with PQC mode enabled and before the side-effecting suite tail.
    #[cfg(feature = "mldsa_attestation")]
    results.extend(
        run_pqc_command_suite(&mut model, &mut StackSampler)
            .into_iter()
            .map(|(name, v)| (name, v as u32)),
    );

    results.extend(
        run_command_suite(&mut model, &mut StackSampler)
            .into_iter()
            .map(|(name, v)| (name, v as u32)),
    );

    // The ML-DSA INVOKE_DPE subcommands are measured against their own dedicated
    // model (see measure_mldsa_dpe_subcommands): the full set can't be sequenced in
    // this shared model (default-context retirement + DISABLE_ATTESTATION conflicts).
    #[cfg(feature = "mldsa_attestation")]
    results.extend(
        measure_mldsa_dpe_subcommands(&mut StackSampler)
            .into_iter()
            .map(|(name, v)| (name, v as u32)),
    );

    // Report, highest stack usage first. Size the name column to the widest
    // command name (some INVOKE_DPE_MLDSA87(..) subcommands are >40 chars) so the
    // bytes/% columns stay aligned instead of being pushed out by long names.
    results.sort_by_key(|b| std::cmp::Reverse(b.1));
    let name_w = results
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0)
        .max("command".len());
    println!("\nRuntime command peak stack usage (runtime stack = {STACK_SIZE} bytes):");
    println!("{:<name_w$} {:>10} {:>8}", "command", "bytes", "% stack");
    println!("{}", "-".repeat(name_w + 20));
    for (name, bytes) in &results {
        let pct = (*bytes as f64) * 100.0 / (STACK_SIZE as f64);
        println!("{name:<name_w$} {bytes:>10} {pct:>7.1}%");
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

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
//! firmware and additionally measures `SET_PQ_SEED` followed by `GET_PQ_CSR`.
//! The order matters: `SET_PQ_SEED` provisions the PQ.DevID CDI and enables PQC
//! mode, so running `GET_PQ_CSR` afterwards exercises its full ML-DSA-87
//! keygen+sign+CSR-assembly path (the maximal stack consumer) rather than
//! early-returning.
//!
//! The mechanism relies on the emulator's stack-pointer tracking, so this test
//! only runs against the software emulator (not verilator/FPGA).
#![cfg(not(any(feature = "verilator", feature = "fpga_realtime")))]

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_measurements_common::{run_command_suite, CommandSampler};
use caliptra_api::SocManager;
use caliptra_common::memory_layout::{STACK_ORG, STACK_SIZE};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;

#[cfg(feature = "mldsa_attestation")]
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
#[cfg(feature = "mldsa_attestation")]
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, SetPqSeedReq, SET_PQ_SEED_SEED_SIZE,
};
#[cfg(feature = "mldsa_attestation")]
use zerocopy::IntoBytes;

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
        peak_stack_usage(model)
            .expect("no stack activity observed; was the model built with stack_info?")
            as u64
    }
}

/// Measure the PQC command pair. `SET_PQ_SEED` must precede `GET_PQ_CSR` so that
/// PQC mode is enabled and the CSR path runs its full (maximal stack) flow.
#[cfg(feature = "mldsa_attestation")]
fn measure_pqc_commands(model: &mut DefaultHwModel) -> Vec<(&'static str, u32)> {
    let mut sampler = StackSampler;
    let mut results = Vec::new();

    let mut set_seed = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    set_seed.populate_chksum().unwrap();
    sampler.before(model);
    let _ = model.mailbox_execute(
        u32::from(CommandId::SET_PQ_SEED),
        set_seed.as_bytes().unwrap(),
    );
    results.push(("SET_PQ_SEED", sampler.after(model) as u32));

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_PQ_CSR), &[]),
    };
    sampler.before(model);
    let _ = model.mailbox_execute(u32::from(CommandId::GET_PQ_CSR), payload.as_bytes());
    results.push(("GET_PQ_CSR", sampler.after(model) as u32));

    results
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

    // Measure the PQC commands first so GET_PQ_CSR runs with PQC mode enabled.
    #[cfg(feature = "mldsa_attestation")]
    results.extend(measure_pqc_commands(&mut model));

    results.extend(
        run_command_suite(&mut model, &mut StackSampler)
            .into_iter()
            .map(|(name, v)| (name, v as u32)),
    );

    // Report, highest stack usage first.
    results.sort_by_key(|b| std::cmp::Reverse(b.1));
    println!("\nRuntime command peak stack usage (runtime stack = {STACK_SIZE} bytes):");
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

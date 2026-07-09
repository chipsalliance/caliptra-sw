// Licensed under the Apache-2.0 license.

//! Measures the simulated clock-cycle cost of each Runtime Command.
//!
//! For each command, the emulator's cycle counter is sampled immediately before
//! and after the mailbox round-trip. The difference is the number of clock
//! cycles the firmware consumed to service that command, including dispatch
//! overhead, crypto operations, and response serialization.
//!
//! Commands are issued in the same state-dependent order as test_stack_usage.rs
//! so that state builders (auth manifest, exported CDI, tagged contexts) run
//! before their consumers.
//!
//! When built with `mldsa_attestation`, the test runs against the PQC-enabled
//! firmware and additionally measures the ML-DSA-87 commands via
//! `run_pqc_command_suite` (`SET_PQ_SEED`, `GET_PQ_CSR`,
//! `CERTIFY_KEY_EXTENDED_MLDSA87`, `MLDSA87_SIGNATURE_VERIFY`, `GET_PQ_CERT`,
//! `POPULATE_PQ_CERT`).
//!
//! The mechanism relies on `DefaultHwModel::cycle_count()`, which reads the
//! emulated CPU's clock counter. It is therefore only meaningful against the
//! software emulator.
#![cfg(not(any(feature = "verilator", feature = "fpga_realtime")))]

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_measurements_common::{run_command_suite, CommandSampler};
use caliptra_api::SocManager;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;

#[cfg(feature = "mldsa_attestation")]
use crate::test_measurements_common::run_pqc_command_suite;
#[cfg(feature = "mldsa_attestation")]
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;

struct CycleSampler {
    start: u64,
}

impl CommandSampler for CycleSampler {
    fn before(&mut self, model: &mut DefaultHwModel) {
        self.start = model.cycle_count();
    }

    fn after(&mut self, model: &mut DefaultHwModel) -> u64 {
        model.cycle_count() - self.start
    }
}

#[test]
fn measure_runtime_command_timing() {
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

    let mut results = Vec::new();

    // Measure the PQC commands first so they run before the side-effecting
    // commands (DISABLE_ATTESTATION/SHUTDOWN) at the tail of the standard suite,
    // and so GET_PQ_CSR / CERTIFY_KEY_EXTENDED_MLDSA87 run with PQC mode enabled.
    #[cfg(feature = "mldsa_attestation")]
    results.extend(run_pqc_command_suite(
        &mut model,
        &mut CycleSampler { start: 0 },
    ));

    results.extend(run_command_suite(
        &mut model,
        &mut CycleSampler { start: 0 },
    ));

    results.sort_by_key(|b| std::cmp::Reverse(b.1));
    println!("\nRuntime command cycle cost (emulated clock cycles):");
    println!("{:<32} {:>12}", "command", "cycles");
    println!("{}", "-".repeat(46));
    for (name, cycles) in &results {
        println!("{name:<32} {cycles:>12}");
    }

    for (name, cycles) in &results {
        assert!(*cycles > 0, "{name} reported zero cycles");
    }
}

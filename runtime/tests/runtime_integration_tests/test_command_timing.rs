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
//! The ML-DSA-87 commands are measured via `run_pqc_command_suite` (`SET_PQ_SEED`, `GET_PQ_CSR`,
//! `CERTIFY_KEY_EXTENDED_MLDSA87`, `MLDSA87_SIGNATURE_VERIFY`, `GET_PQ_CERT`,
//! `POPULATE_PQ_CERT`) and every ML-DSA-87 `INVOKE_DPE` subcommand via
//! `measure_mldsa_dpe_subcommands` (InitCtx, DeriveContext, CertifyKey, Sign,
//! RotateCtx, DestroyCtx, GetProfile, GetCertificateChain,
//! UpdateContextMeasurement).
//!
//! The mechanism relies on `DefaultHwModel::cycle_count()`, which reads the
//! emulated CPU's clock counter. It is therefore only meaningful against the
//! software emulator.
#![cfg(not(any(feature = "verilator", feature = "fpga_realtime")))]

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_measurements_common::{
    measure_mldsa_dpe_subcommands, run_command_suite, run_pqc_command_suite, CommandSampler,
};
use caliptra_api::SocManager;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;

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

fn test_args(
    sample_stack_traces: bool,
    stack_sample_rate: Option<u64>,
) -> RuntimeTestArgs<'static> {
    RuntimeTestArgs {
        sample_stack_traces,
        stack_sample_rate,
        ..RuntimeTestArgs::default()
    }
}

fn measure_timing(args: RuntimeTestArgs) {
    let mut model = run_rt_test(args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut results = Vec::new();

    // Measure the PQC commands first so they run before the side-effecting
    // commands (DISABLE_ATTESTATION/SHUTDOWN) at the tail of the standard suite,
    // and so GET_PQ_CSR / CERTIFY_KEY_EXTENDED_MLDSA87 run with PQC mode enabled.
    results.extend(run_pqc_command_suite(
        &mut model,
        &mut CycleSampler { start: 0 },
    ));

    results.extend(run_command_suite(
        &mut model,
        &mut CycleSampler { start: 0 },
    ));

    // The ML-DSA INVOKE_DPE subcommands are measured against their own dedicated
    // model (see measure_mldsa_dpe_subcommands): the full set can't be sequenced in
    // this shared model (default-context retirement + DISABLE_ATTESTATION conflicts).
    results.extend(measure_mldsa_dpe_subcommands(&mut CycleSampler {
        start: 0,
    }));

    // Size the name column to the widest command name (some INVOKE_DPE_MLDSA87(..)
    // subcommands are >40 chars) so the cycles column stays aligned instead of
    // being pushed out by long names.
    results.sort_by_key(|b| std::cmp::Reverse(b.1));
    let name_w = results
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0)
        .max("command".len());
    println!("\nRuntime command cycle cost (emulated clock cycles):");
    println!("{:<name_w$} {:>12}", "command", "cycles");
    println!("{}", "-".repeat(name_w + 13));
    for (name, cycles) in &results {
        println!("{name:<name_w$} {cycles:>12}");
    }

    for (name, cycles) in &results {
        assert!(*cycles > 0, "{name} reported zero cycles");
    }
}

#[test]
fn measure_runtime_command_timing() {
    measure_timing(test_args(false, None));
}

#[test]
#[ignore = "Traces the stack; invoke with --ignored"]
fn measure_runtime_command_timing_and_sample_stack_traces() {
    measure_timing(test_args(true, None));
}

/// Profile the cycle-cost distribution of `CERTIFY_KEY_EXTENDED_MLDSA87` across
/// many distinct labels.
///
/// ML-DSA-87 signing uses rejection sampling, so the number of loop iterations —
/// and hence the cycle cost — depends on the data being signed. The DPE
/// `CertifyKey` label seeds leaf-key derivation, so each distinct label yields a
/// different derived key, a different certificate TBS, a different `mu`, and thus
/// a different rejection-loop count. Leaf key generation itself is rejection-free
/// (constant work), so the spread measured here reflects the signing loop.
///
/// Marked `#[ignore]`: this runs the full keygen+sign path 50 times and is a
/// profiling aid, not a pass/fail gate. Run with:
///   cargo test -p caliptra-runtime \
///     measure_certify_key_mldsa_timing_distribution -- --ignored --nocapture
#[test]
#[ignore = "50x CERTIFY_KEY_EXTENDED_MLDSA87 profiling run; invoke with --ignored"]
fn measure_certify_key_mldsa_timing_distribution() {
    /// Number of distinct-label CERTIFY_KEY calls to sample.
    const N: usize = 50;

    CERTIFY_DONE.store(0, std::sync::atomic::Ordering::Relaxed);
    let samples = sample_certify_worker(0, N, N);
    print_timing_stats("CERTIFY_KEY_EXTENDED_MLDSA87", &samples);
}

/// Compute and print summary statistics (mean, sample std dev, spread,
/// percentiles) over a set of cycle-count samples, and assert none are zero.
fn print_timing_stats(title: &str, samples: &[u64]) {
    let n = samples.len();
    assert!(n > 1, "need at least 2 samples");
    let mean = samples.iter().sum::<u64>() as f64 / n as f64;
    // Sample variance (n-1 denominator).
    let variance = samples
        .iter()
        .map(|&c| {
            let d = c as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / (n - 1) as f64;
    let std_dev = variance.sqrt();
    let cv = std_dev / mean;
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let pct = |p: f64| -> u64 { sorted[((p * (n as f64 - 1.0)).round() as usize).min(n - 1)] };
    let median = if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) as f64 / 2.0
    } else {
        sorted[n / 2] as f64
    };

    println!("\n{title} timing over {n} distinct labels (emulated clock cycles):");
    println!("  n         = {n}");
    println!("  mean      = {mean:.1}");
    println!("  std dev   = {std_dev:.1}  (sample, n-1)");
    println!("  cv        = {:.2}%  (std/mean)", cv * 100.0);
    println!("  min       = {}", sorted[0]);
    println!("  p25       = {}", pct(0.25));
    println!("  median    = {median:.1}");
    println!("  p75       = {}", pct(0.75));
    println!("  p90       = {}", pct(0.90));
    println!("  p99       = {}", pct(0.99));
    println!("  max       = {}", sorted[n - 1]);
    println!("  range     = {}", sorted[n - 1] - sorted[0]);

    for (i, c) in samples.iter().enumerate() {
        assert!(*c > 0, "sample {i} reported zero cycles");
    }
}

/// Global progress counter shared by the CERTIFY_KEY sampling workers. Reset by
/// each test before spawning its workers.
static CERTIFY_DONE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Same distribution as `measure_certify_key_mldsa_timing_distribution`, but
/// gathers 1000 samples by running several emulators in parallel worker threads
/// (each over a disjoint label range) and combining them. The firmware-build
/// cache is process-global and thread-safe (each worker reads the same cached
/// ELF), so the workers share one build and only the emulation runs in parallel.
#[test]
#[ignore = "1000x CERTIFY_KEY_EXTENDED_MLDSA87 across parallel emulators; invoke with --ignored"]
fn measure_certify_key_mldsa_timing_distribution_1000() {
    use std::sync::atomic::Ordering;

    const TOTAL: usize = 1000;
    // One single-threaded emulator per worker; leave a couple of cores free.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(2).max(1))
        .unwrap_or(8)
        .min(TOTAL);
    let per = TOTAL / workers;
    let total = per * workers;
    CERTIFY_DONE.store(0, Ordering::Relaxed);

    // Warm the thread-safe, process-global firmware build cache once so the
    // workers read the cached ELF rather than racing to build it.
    let _ = caliptra_builder::build_firmware_elf(&caliptra_builder::firmware::APP_WITH_UART);

    let handles: Vec<_> = (0..workers)
        .map(|w| std::thread::spawn(move || sample_certify_worker(w * per, per, total)))
        .collect();

    let mut samples: Vec<u64> = Vec::with_capacity(total);
    for h in handles {
        samples.extend(h.join().expect("worker thread panicked"));
    }
    print_timing_stats("CERTIFY_KEY_EXTENDED_MLDSA87 (parallel)", &samples);
}

/// Boot one emulator, provision PQC, and time `count` CERTIFY_KEY calls whose
/// labels start at `label_start`. Returns the per-call cycle counts.
fn sample_certify_worker(label_start: usize, count: usize, total: usize) -> Vec<u64> {
    use caliptra_common::mailbox_api::{
        CertifyKeyExtendedFlags, CertifyKeyExtendedMldsa87Req, CommandId, MailboxReq,
        MailboxReqHeader, SetPqSeedReq, SET_PQ_SEED_SEED_SIZE,
    };
    use dpe::{
        commands::{CertifyKeyCommand, CertifyKeyFlags, CertifyKeyMldsa87Cmd},
        context::ContextHandle,
    };
    use std::sync::atomic::Ordering;
    use zerocopy::IntoBytes;

    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });
    let mut seed_req = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    seed_req.populate_chksum().unwrap();
    model
        .mailbox_execute(
            u32::from(CommandId::SET_PQ_SEED),
            seed_req.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("SET_PQ_SEED failed");

    let mut samples = Vec::with_capacity(count);
    for i in 0..count {
        let mut label = [0u8; 48];
        label[..8].copy_from_slice(&((label_start + i) as u64).to_le_bytes());
        let certify_key_cmd = CertifyKeyMldsa87Cmd {
            handle: ContextHandle::default(),
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCommand::FORMAT_X509,
            label,
        };
        let mut req = MailboxReq::CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req {
            hdr: MailboxReqHeader { chksum: 0 },
            flags: CertifyKeyExtendedFlags::empty(),
            certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
        });
        req.populate_chksum().unwrap();
        let bytes = req.as_bytes().unwrap().to_vec();
        let start = model.cycle_count();
        model
            .mailbox_execute(u32::from(CommandId::CERTIFY_KEY_EXTENDED_MLDSA87), &bytes)
            .unwrap()
            .expect("CERTIFY_KEY_EXTENDED_MLDSA87 failed");
        samples.push(model.cycle_count() - start);
        let d = CERTIFY_DONE.fetch_add(1, Ordering::Relaxed) + 1;
        if d.is_multiple_of(10) || d == total {
            eprintln!("  {d}/{total} done");
        }
    }
    samples
}

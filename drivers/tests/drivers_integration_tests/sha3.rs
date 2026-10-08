// Licensed under the Apache-2.0 license

use super::driver_init_params;
use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use caliptra_registers::kmac::Kmac;

#[derive(Default)]
struct Operation {
    config: u32,
    data: Vec<u8>,
    processed: bool,
    digest_reads: usize,
    idle: bool,
}

fn operations_from_trace(trace: &str) -> Vec<Operation> {
    let base = u32::try_from(Kmac::PTR.addr()).unwrap();
    let mut operations = Vec::<Operation>::new();
    let mut current = None::<Operation>;
    let mut config = None;

    for line in trace.lines().filter(|line| line.starts_with("UC ")) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let address = u32::from_str_radix(fields[2].strip_prefix("*0x").unwrap(), 16).unwrap();
        if !(base..base + 0x1000).contains(&address) {
            continue;
        }
        assert_eq!(fields.len(), 5, "Unexpected SHA3 bus transaction: {line}");
        let value = u32::from_str_radix(fields[4].strip_prefix("0x").unwrap(), 16).unwrap();

        match fields[1] {
            "write4" if address == base + 0x14 => config = Some(value),
            "write4" if address == base + 0x18 => match value {
                0x1d => {
                    assert!(current.is_none(), "SHA3 operation was not finished");
                    if let Some(previous) = operations.last() {
                        assert!(previous.idle, "SHA3 was reused before returning to idle");
                    }
                    current = Some(Operation {
                        config: config.expect("SHA3 was not configured"),
                        ..Default::default()
                    });
                }
                0x2e => {
                    let operation = current.as_mut().expect("SHA3 PROCESS without START");
                    assert!(!operation.processed);
                    operation.processed = true;
                }
                0x16 => {
                    let operation = current.take().expect("SHA3 DONE without START");
                    assert!(operation.processed, "SHA3 DONE before PROCESS");
                    operations.push(operation);
                }
                _ => panic!("Unexpected SHA3 command: {value:#x}"),
            },
            size if size.starts_with("write")
                && (base + 0x800..base + 0x900).contains(&address) =>
            {
                let size: usize = size.strip_prefix("write").unwrap().parse().unwrap();
                assert!(matches!(size, 1 | 2 | 4));
                let operation = current.as_mut().expect("SHA3 data without START");
                assert!(!operation.processed, "SHA3 data after PROCESS");
                operation
                    .data
                    .extend_from_slice(&value.to_le_bytes()[..size]);
            }
            "read4" if (base + 0x400..base + 0x4c8).contains(&address) => {
                let operation = current.as_mut().expect("SHA3 digest read without START");
                assert!(operation.processed);
                operation.digest_reads += 1;
            }
            "read4" if address == base + 0x1c && value & 1 != 0 && current.is_none() => {
                if let Some(operation) = operations.last_mut() {
                    operation.idle = true;
                }
            }
            _ => {}
        }
    }
    assert!(current.is_none(), "SHA3 operation left unfinished");
    operations
}

fn assert_scrub_operations(operations: &[Operation]) {
    assert_eq!(operations.len() % 2, 0, "Missing SHA3 scrub operation");
    for pair in operations.chunks_exact(2) {
        assert!(pair[0].digest_reads > 0, "Real SHA3 digest was not saved");
        let scrub = &pair[1];
        assert_eq!(scrub.config & 0x3e, 0x04, "Scrub must use SHA3-256");
        assert_eq!(
            scrub.data.len(),
            80,
            "Scrub must overwrite all 80 FIFO bytes"
        );
        assert!(
            scrub.data.iter().all(|byte| *byte == 0),
            "Scrub input must be nonsecret zero data"
        );
        assert_eq!(scrub.digest_reads, 0, "Dummy digest must not be returned");
        assert!(pair.iter().all(|operation| operation.idle));
    }
}

pub(super) fn run_test() {
    let directory = tempfile::tempdir().unwrap();
    let trace_path = directory.path().join("sha3.log");
    let rom = caliptra_builder::build_firmware_rom(&firmware::driver_tests::SHA3).unwrap();
    let mut model = caliptra_hw_model::new_unbooted(InitParams {
        trace_path: Some(trace_path.clone()),
        ..driver_init_params(&rom)
    })
    .unwrap();
    model.tracing_hint(true);
    model.boot(BootParams::default()).unwrap();
    model.step_until_exit_success().unwrap();
    drop(model);

    let trace = std::fs::read_to_string(trace_path).unwrap();
    let operations = operations_from_trace(&trace);
    // KAT, 8 one-shot SHAKE, 5 incremental SHAKE, 2 SHA3, and 2 streaming completions.
    assert_eq!(operations.len(), 18 * 2);
    assert_scrub_operations(&operations);
}

fn fixture_operations(scrub: Vec<u8>) -> [Operation; 2] {
    [
        Operation {
            digest_reads: 8,
            idle: true,
            ..Default::default()
        },
        Operation {
            config: 0x204,
            data: scrub,
            idle: true,
            ..Default::default()
        },
    ]
}

#[test]
#[should_panic(expected = "Scrub must overwrite all 80 FIFO bytes")]
fn rejects_short_scrub() {
    assert_scrub_operations(&fixture_operations(vec![0; 79]));
}

#[test]
#[should_panic(expected = "Scrub input must be nonsecret zero data")]
fn rejects_unscrubbed_data() {
    assert_scrub_operations(&fixture_operations(vec![0xa5; 80]));
}

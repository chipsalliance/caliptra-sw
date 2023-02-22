/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_emu_bus::Clock;
use caliptra_emu_cpu::{Cpu, RvInstr, StepAction};
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs};
use clap::{arg, value_parser, ArgAction};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
mod gdb;
use crate::gdb::gdb_target::GdbTarget;
use gdb::gdb_state;

// CPU Main Loop (free_run no GDB)
fn free_run(mut cpu: Cpu<CaliptraRootBus>, trace_path: Option<PathBuf>) {
    if let Some(path) = trace_path {
        let mut f = File::create(path).unwrap();
        let trace_fn: &mut dyn FnMut(u32, RvInstr) = &mut |pc, instr| {
            let _ = write!(&mut f, "0x{:08x} ", pc);
            match instr {
                RvInstr::Instr32(instr) => {
                    let _ = writeln!(&mut f, "0x{:08x}", instr);
                }
                RvInstr::Instr16(instr) => {
                    let _ = writeln!(&mut f, "0x{:04x}", instr);
                }
            }
        };

        // Need to have the loop in the same scope as trace_fn to prevent borrowing rules violation
        loop {
            match cpu.step(Some(trace_fn)) {
                StepAction::Continue => continue,
                _ => break,
            }
        }
    } else {
        loop {
            match cpu.step(None) {
                StepAction::Continue => continue,
                _ => break,
            }
        }
    };
}

fn main() -> io::Result<()> {
    let args = clap::Command::new("caliptra-emu")
        .about("Caliptra emulator")
        .arg(
            arg!(--"rom" <FILE> "ROM binary path")
                .value_parser(value_parser!(PathBuf))
        )
        .arg(
            arg!(--"gdb-port" <VALUE> "Gdb Debugger")
                .required(false)
        )
        .arg(
            arg!(--"firmware" <FILE> "Firmware image file")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"trace-instr" ... "Trace instructions to a file in log-dir")
                .required(false)
                .action(ArgAction::SetTrue)
        )
        .arg(
            arg!(--"ueid" <U64> "64-bit Unique Endpoint Id")
                .required(false)
                .value_parser(value_parser!(u64))
                .default_value(&u64::MAX.to_string())
        )
        .arg(
            arg!(--"idevid-key-id-algo" <algo> "idevid certificate key id algorithm [sha1, sha2, fuses]")
                .required(false)
                .default_value("sha1"),
        )
        .arg(
            arg!(--"req-idevid-csr" ... "Request IDevID CSR. Downloaded CSR is store in log-dir.")
                .required(false)
                .action(ArgAction::SetTrue)
        )
        .arg(
            arg!(--"req-ldevid-cert" ... "Request LDevID Cert. Downloaded cert is stored in log-dir")
                .required(false)
                .action(ArgAction::SetTrue)
        )
        .arg(
            arg!(--"log-dir" <DIR> "Directory to log execution artifacts")
                .required(false)
                .value_parser(value_parser!(PathBuf))
                .default_value("/tmp")
        )
        .get_matches();

    let args_rom = args.get_one::<PathBuf>("rom").unwrap();
    let args_firmware = args.get_one::<PathBuf>("firmware");
    let args_log_dir = args.get_one::<PathBuf>("log-dir").unwrap();
    let args_idevid_key_id_algo = args.get_one::<String>("idevid-key-id-algo").unwrap();
    let args_ueid = args.get_one::<u64>("ueid").unwrap();

    if !Path::new(&args_rom).exists() {
        println!("ROM File {:?} does not exist", args_rom);
        exit(-1);
    }

    let mut rom = File::open(args_rom)?;
    let mut rom_buffer = Vec::new();
    rom.read_to_end(&mut rom_buffer)?;

    if rom_buffer.len() > CaliptraRootBus::ROM_SIZE {
        println!(
            "ROM File Size must not exceed {} bytes",
            CaliptraRootBus::ROM_SIZE
        );
        exit(-1);
    }

    let mut firmware_buffer = Vec::new();
    if let Some(path) = args_firmware {
        if !Path::new(&path).exists() {
            println!("Firmware File {:?} does not exist", args_firmware);
            exit(-1);
        }
        let mut firmware = File::open(path)?;
        firmware.read_to_end(&mut firmware_buffer)?;
    }

    let clock = Clock::new();
    let bus_args = CaliptraRootBusArgs {
        rom: rom_buffer,
        firmware: firmware_buffer,
        log_dir: args_log_dir.clone(),
        ueid: *args_ueid,
        idev_key_id_algo: args_idevid_key_id_algo.clone(),
        req_idevid_csr: args.get_flag("req-idevid-csr"),
        req_ldevid_cert: args.get_flag("req-ldevid-cert"),
    };
    let cpu = Cpu::new(CaliptraRootBus::new(&clock, bus_args), clock);

    // Check if Optional GDB Port is passed
    match args.get_one::<String>("gdb-port") {
        Some(port) => {
            // Create GDB Target Instance
            let mut gdb_target = GdbTarget::new(cpu);

            // Execute CPU through GDB State Machine
            gdb_state::wait_for_gdb_run(&mut gdb_target, port.parse().unwrap());
        }
        _ => {
            let instr_trace = if args.get_flag("trace-instr") {
                let mut path = args_log_dir.clone();
                path.push("caliptra_instr_trace.txt");
                Some(path)
            } else {
                None
            };

            // If no GDB Port is passed, Free Run
            free_run(cpu, instr_trace);
        }
    }

    Ok(())
}

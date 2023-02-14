/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_emu_bus::Clock;
use caliptra_emu_cpu::{Cpu, RvInstr, StepAction};
use caliptra_emu_periph::CaliptraRootBus;
use clap::{arg, value_parser};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
mod gdb;
use crate::gdb::gdb_target::GdbTarget;
use gdb::gdb_state;

// CPU Main Loop (free_run no GDB)
fn free_run(mut cpu: Cpu<CaliptraRootBus>, trace_path: Option<&PathBuf>) {
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
        .arg(arg!(--rom <FILE> "ROM binary path").value_parser(value_parser!(PathBuf)))
        .arg(
            arg!(--trace <FILE> "Execution trace file")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(--gdb_port <VALUE> "Gdb Debugger").required(false))
        .get_matches();

    let args_rom = args.get_one::<PathBuf>("rom").unwrap();
    let args_trace = args.get_one::<PathBuf>("trace");

    if !Path::new(&args_rom).exists() {
        println!("ROM File {:?} does not exist", args_rom);
        exit(-1);
    }

    let mut rom = File::open(args_rom)?;
    let mut buffer = Vec::new();
    rom.read_to_end(&mut buffer)?;

    if buffer.len() > CaliptraRootBus::ROM_SIZE {
        println!(
            "ROM File Size must not exceed {} bytes",
            CaliptraRootBus::ROM_SIZE
        );
        exit(-1);
    }
    let clock = Clock::new();
    let cpu = Cpu::new(CaliptraRootBus::new(&clock, buffer), clock);

    // Check if Optinal GDB Port is passed
    match args.get_one::<String>("gdb_port") {
        Some(port) => {
            // Create GDB Target Instance
            let mut gdb_target = GdbTarget::new(cpu);

            // Exexute CPU through GDB State Machine
            gdb_state::wait_for_gdb_run(&mut gdb_target, port.parse().unwrap());
        }
        _ => {
            // If no GDB Port is passed, Free Run
            free_run(cpu, args_trace);
        }
    }

    Ok(())
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_emu_cpu::{Cpu, StepAction};
use caliptra_emu_periph::CaliptraRootBus;
use clap::{arg, value_parser};
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::exit;

fn main() -> io::Result<()> {
    let args = clap::Command::new("caliptra-emu")
        .about("Caliptra emulator")
        .arg(arg!(--rom <FILE> "ROM binary path").value_parser(value_parser!(PathBuf)))
        .arg(
            arg!(--trace <FILE> "Execution trace file")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .get_matches();

    let args_rom = args.get_one::<PathBuf>("rom").unwrap();

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

    let mut cpu = Cpu::new(CaliptraRootBus::new());

    loop {
        match cpu.step(None) {
            StepAction::Continue => continue,
            _ => break,
        }
    }

    Ok(())
}

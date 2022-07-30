/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_emu_lib::EmuCtrl;
use caliptra_emu_lib::Ram;
use caliptra_emu_lib::Rom;
use caliptra_emu_lib::Uart;
use caliptra_emu_lib::{Cpu, StepAction};
use clap::{arg, value_parser};
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::exit;

fn main() -> io::Result<()> {
    const ROM_SIZE: usize = 32 * 1024;
    const ICCM_SIZE: usize = 128 * 1024;
    const DCCM_SIZE: usize = 128 * 1024;

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

    if buffer.len() > ROM_SIZE {
        println!("ROM File Size must not exceed {} bytes", ROM_SIZE);
        exit(-1);
    }

    let mut cpu = Cpu::new();
    let rom = Rom::new("ROM", 0x0000_0000, buffer);
    let iccm = Ram::new("ICCM", 0x4000_0000, vec![0; ICCM_SIZE]);
    let dccm = Ram::new("DCCM", 0x5000_0000, vec![0; DCCM_SIZE]);
    let uart = Uart::new("UART0", 0x2000_0000);
    let ctrl = EmuCtrl::new("EMU_CTRL", 0x3000_0000);

    if !cpu.attach_dev(Box::new(rom)) {
        println!("Failed to attach ROM.");
        exit(-1);
    }

    if !cpu.attach_dev(Box::new(iccm)) {
        println!("Failed to attach ICCM.");
        exit(-1);
    }

    if !cpu.attach_dev(Box::new(dccm)) {
        println!("Failed to attach DCCM.");
        exit(-1);
    }

    if !cpu.attach_dev(Box::new(uart)) {
        println!("Failed to attach UART.");
        exit(-1);
    }

    if !cpu.attach_dev(Box::new(ctrl)) {
        println!("Failed to attach Emulator Control.");
        exit(-1);
    }

    loop {
        match cpu.step(None) {
            StepAction::Continue => continue,
            _ => break,
        }
    }

    Ok(())
}

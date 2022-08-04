/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_emu_cpu::DynamicBus;
use caliptra_emu_cpu::EmuCtrl;
use caliptra_emu_cpu::Ram;
use caliptra_emu_cpu::Rom;
use caliptra_emu_cpu::Uart;
use caliptra_emu_cpu::{Cpu, StepAction};
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

    let mut cpu = Cpu::new(DynamicBus::new());
    let rom = Rom::new("ROM", 0x0000_0000, buffer);
    let iccm = Ram::new("ICCM", 0x4000_0000, vec![0; ICCM_SIZE]);
    let dccm = Ram::new("DCCM", 0x5000_0000, vec![0; DCCM_SIZE]);
    let uart = Uart::new("UART0", 0x2000_0000);
    let ctrl = EmuCtrl::new("EMU_CTRL", 0x3000_0000);

    cpu.bus.attach_dev(Box::new(rom))?;
    cpu.bus.attach_dev(Box::new(iccm))?;
    cpu.bus.attach_dev(Box::new(dccm))?;
    cpu.bus.attach_dev(Box::new(uart))?;
    cpu.bus.attach_dev(Box::new(ctrl))?;

    loop {
        match cpu.step(None) {
            StepAction::Continue => continue,
            _ => break,
        }
    }

    Ok(())
}

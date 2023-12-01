// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use elf::{endian::LittleEndian, ElfBytes};

#[test]
fn test_cpu_fault() {
    const GLOBAL_EXCEPTION: u32 = 0x01050002;

    let rom_fwid = firmware::rom_from_env();

    let elf_bytes = caliptra_builder::build_firmware_elf(rom_fwid).unwrap();
    let mut rom = caliptra_builder::elf2rom(&elf_bytes).unwrap();
    let elf = ElfBytes::<LittleEndian>::minimal_parse(&elf_bytes).unwrap();
    let symbol_table = elf.symbol_table().unwrap().unwrap().0;
    let string_table = elf.symbol_table().unwrap().unwrap().1;
    let rom_entry_offset = symbol_table
        .iter()
        .find(|symbol| string_table.get(symbol.st_name as usize).unwrap() == "rom_entry")
        .unwrap()
        .st_value as usize;
    println!("rom_entry_offset is {}", rom_entry_offset);

    // Write an instruction that causes a cpu fault to the rom_entry offset
    let illegal_instruction = [0xFF, 0xFF, 0xFF, 0xFF];
    rom[rom_entry_offset..rom_entry_offset + illegal_instruction.len()]
        .copy_from_slice(&illegal_instruction);

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() == GLOBAL_EXCEPTION);

    let mcause = hw.soc_ifc().cptra_fw_extended_error_info().at(0).read();
    let mscause = hw.soc_ifc().cptra_fw_extended_error_info().at(1).read();
    let mepc = hw.soc_ifc().cptra_fw_extended_error_info().at(2).read();
    let ra = hw.soc_ifc().cptra_fw_extended_error_info().at(3).read();

    println!(
        "ROM Global Exception mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X} ra=0x{:08X}",
        mcause, mscause, mepc, ra,
    );

    // mcause must be illegal instruction
    assert_eq!(mcause, 0x2);
    // no mscause
    assert_eq!(mscause, 0);
    // mepc must be the value of the program counter at the failing instruction at rom_entry_offset
    assert_eq!(mepc as usize, rom_entry_offset);
    // return address won't be 0
    assert_ne!(ra, 0);

    #[cfg(feature = "verilator")]
    assert!(hw.v.output.cptra_error_fatal);
}

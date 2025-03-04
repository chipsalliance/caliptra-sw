// Licensed under the Apache-2.0 license

use caliptra_builder::{
    elf_symbols,
    firmware::{ROM, ROM_WITH_UART},
    Symbol,
};
use caliptra_common::RomBootStatus;
use caliptra_emu_cpu::CoverageBitmaps;
use caliptra_hw_model::{BootParams, HwModel, InitParams};

fn find_symbol<'a>(symbols: &'a [Symbol<'a>], name: &str) -> &'a Symbol<'a> {
    symbols
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("Could not find symbol {name}"))
}

fn find_symbol_containing<'a>(symbols: &'a [Symbol<'a>], search: &str) -> &'a Symbol<'a> {
    let mut matching_symbols = symbols.iter().filter(|s| s.name.contains(search));
    let Some(result) = matching_symbols.next() else {
        panic!("Could not find symbol with substring {search:?}");
    };
    if let Some(second_match) = matching_symbols.next() {
        panic!(
            "Multiple symbols matching substring {search:?}: {:?}, {:?}",
            result.name, second_match.name
        );
    }
    result
}

fn assert_symbol_not_called(hw: &caliptra_hw_model::ModelEmulated, symbol: &Symbol) {
    let CoverageBitmaps { rom, iccm: _iccm } = hw.code_coverage_bitmap();
    assert!(
        !rom[symbol.value as usize],
        "{}() was called before the boot status changed to KatStarted. This is a CFI risk, as glitching a function like that could lead to an out-of-bounds write", symbol.name);
}

#[test]
fn test_memcpy_not_called_before_cfi_init() {
    for fwid in &[&ROM_WITH_UART, &ROM] {
        println!("Runing with firmware {:?}", fwid);
        let elf_bytes = caliptra_builder::build_firmware_elf(fwid).unwrap();
        let symbols = elf_symbols(&elf_bytes).unwrap();

        let rom = caliptra_builder::elf2rom(&elf_bytes).unwrap();

        let mut hw = caliptra_hw_model::ModelEmulated::new(
            InitParams {
                rom: &rom,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        hw.step_until_boot_status(RomBootStatus::CfiInitialized.into(), true);

        assert_symbol_not_called(&hw, find_symbol(&symbols, "memcpy"));
        assert_symbol_not_called(&hw, find_symbol(&symbols, "memset"));
        assert_symbol_not_called(&hw, find_symbol_containing(&symbols, "read_volatile_slice"));
        assert_symbol_not_called(
            &hw,
            find_symbol_containing(&symbols, "write_volatile_slice"),
        );
    }
}

// Licensed under the Apache-2.0 license

use std::{collections::HashMap, mem};

use caliptra_builder::{firmware, Symbol};
use caliptra_cfi_lib::CfiState;
use caliptra_drivers::memory_layout;

#[test]
fn test_linker_symbols_match_memory_layout() {
    let elf_bytes = caliptra_builder::build_firmware_elf(firmware::rom_from_env()).unwrap();
    let symbols = caliptra_builder::elf_symbols(&elf_bytes).unwrap();
    let symbols: HashMap<&str, Symbol> = symbols.into_iter().map(|s| (s.name, s)).collect();

    fn assert_symbol_addr(symbols: &HashMap<&str, Symbol>, name: &str, expected_val: u32) {
        let sym = symbols
            .get(name)
            .unwrap_or_else(|| panic!("Unknown symbol {name}"));
        if sym.value != u64::from(expected_val) {
            panic!(
                "Unexpected value for symbol {name}: was 0x{:x} expected 0x{expected_val:x}",
                sym.value
            );
        }
    }

    assert_symbol_addr(&symbols, "ROM_ORG", memory_layout::ROM_ORG);
    assert_symbol_addr(&symbols, "ICCM_ORG", memory_layout::ICCM_ORG);
    assert_symbol_addr(&symbols, "DCCM_ORG", memory_layout::DCCM_ORG);
    assert_symbol_addr(&symbols, "DATA_ORG", memory_layout::ROM_DATA_ORG);
    assert_symbol_addr(&symbols, "STACK_ORG", memory_layout::ROM_STACK_ORG);
    assert_symbol_addr(&symbols, "ESTACK_ORG", memory_layout::ESTACK_ORG);
    assert_symbol_addr(&symbols, "NSTACK_ORG", memory_layout::NSTACK_ORG);

    assert_symbol_addr(
        &symbols,
        "_sstack",
        memory_layout::ROM_STACK_ORG + memory_layout::ROM_STACK_SIZE,
    );

    assert_symbol_addr(&symbols, "CFI_STATE_ORG", memory_layout::CFI_STATE_ORG);
    assert_eq!(
        memory_layout::ROM_DATA_ORG + memory_layout::ROM_DATA_SIZE,
        memory_layout::CFI_STATE_ORG
    );
    assert_eq!(
        memory_layout::CFI_STATE_ORG + mem::size_of::<CfiState>() as u32,
        memory_layout::BOOT_STATUS_ORG
    );

    assert_symbol_addr(&symbols, "ROM_SIZE", memory_layout::ROM_SIZE);
    assert_symbol_addr(&symbols, "ICCM_SIZE", memory_layout::ICCM_SIZE);
    assert_symbol_addr(&symbols, "DCCM_SIZE", memory_layout::DCCM_SIZE);
    assert_symbol_addr(&symbols, "DATA_SIZE", memory_layout::ROM_DATA_SIZE);
    assert_symbol_addr(&symbols, "STACK_SIZE", memory_layout::ROM_STACK_SIZE);
    assert_symbol_addr(&symbols, "ESTACK_SIZE", memory_layout::ROM_ESTACK_SIZE);
    assert_symbol_addr(&symbols, "NSTACK_SIZE", memory_layout::ROM_NSTACK_SIZE);
}

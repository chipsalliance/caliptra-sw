// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;

#[test]
fn test_panic_missing() {
    let rom_elf = caliptra_builder::build_firmware_elf(firmware::rom_from_env()).unwrap();
    let symbols = caliptra_builder::elf_symbols(&rom_elf).unwrap();
    if symbols.iter().any(|s| s.name.contains("panic_is_possible")) {
        panic!(
            "The caliptra ROM contains the panic_is_possible symbol, which is not allowed. \
                Please remove any code that might panic."
        )
    }
}

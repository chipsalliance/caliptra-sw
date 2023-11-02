// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;

#[test]
fn test_panic_missing() {
    let fmc_elf = caliptra_builder::build_firmware_elf(&firmware::FMC_WITH_UART).unwrap();
    let symbols = caliptra_builder::elf_symbols(&fmc_elf).unwrap();
    if symbols.iter().any(|s| s.name.contains("panic_is_possible")) {
        panic!(
            "The caliptra FMC contains the panic_is_possible symbol, which is not allowed. \
                Please remove any code that might panic."
        )
    }
}

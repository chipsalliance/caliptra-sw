// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;

/// Verify that the caliptra-api mailbox functions are panic-free.
#[test]
fn test_panic_missing() {
    let api_elf = caliptra_builder::build_firmware_elf(&firmware::api_tests::MAILBOX).unwrap();
    let symbols = caliptra_builder::elf_symbols(&api_elf).unwrap();
    if symbols.iter().any(|s| s.name.contains("panic_is_possible")) {
        panic!(
            "The caliptra-api mailbox test binary contains the panic_is_possible symbol, \
             which is not allowed. Please remove any code that might panic."
        )
    }
}

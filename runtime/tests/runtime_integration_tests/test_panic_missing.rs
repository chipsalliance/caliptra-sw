// Licensed under the Apache-2.0 license
use caliptra_builder::firmware::{APP_WITH_UART, APP_WITH_UART_OCP_LOCK};

#[test]
fn test_panic_missing() {
    for elf_id in [&APP_WITH_UART, &APP_WITH_UART_OCP_LOCK] {
        let rt_elf = caliptra_builder::build_firmware_elf(elf_id).unwrap();
        let symbols = caliptra_builder::elf_symbols(&rt_elf).unwrap();
        if symbols.iter().any(|s| s.name.contains("panic_is_possible")) {
            panic!(
                "The caliptra RT {:?} contains the panic_is_possible symbol, which is not allowed. \
                Please remove any code that might panic.", elf_id
            )
        }
    }
}

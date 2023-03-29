#![no_std]
#![no_main]

mod harness;

use caliptra_registers::entropy_src;

fn test_success() {
    println!("Hello.");

    let esrc = entropy_src::RegisterBlock::entropy_src_reg();

    const FALSE: u32 = 9;
    const TRUE: u32 = 6;

    // esrc.conf().write(|_| 0x909099.into());
    // esrc.module_enable().write(|_| 6.into());

    esrc.entropy_control().write(|w| w.es_route(TRUE));

    esrc.module_enable().write(|w| w.module_enable(TRUE));

    println!("L");

    for _ in 0..100 {
        core::hint::black_box(esrc);
    }

    println!("X");
    let valid_bit = esrc.interrupt_state().read().es_entropy_valid();

    println!("valid_bit = {valid_bit}");
    println!(
        "InterruptState register = {:x}",
        u32::from(esrc.interrupt_state().read())
    );
}

test_suite! {
    test_success,
}

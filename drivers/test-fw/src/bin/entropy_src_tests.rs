#![no_std]
#![no_main]

mod harness;

use caliptra_registers::entropy_src;

fn test_success() {
    let esrc = entropy_src::RegisterBlock::entropy_src_reg();

    const FALSE: u32 = 9;
    const TRUE: u32 = 6;

    esrc.conf().write(
        |w| w.entropy_data_reg_enable(TRUE)
            .fips_enable(FALSE)
            .rng_bit_enable(FALSE)
            .rng_bit_sel(0)
            .threshold_scope(TRUE));
    esrc.entropy_control().write(|w| w.es_route(TRUE)
                                      .es_type(TRUE));
    esrc.module_enable().write(|w| w.module_enable(TRUE));

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

#![no_std]
#![no_main]

mod harness;

use caliptra_registers::entropy_src;
use core::panic::PanicInfo;
use core::arch::global_asm;

global_asm!(include_str!("start.S"));

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    println!("[failed]");
    println!("Error: {}\n", info);
    loop {}
}

#[no_mangle]
pub extern "C" fn main() {
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

    for i in 0..17 {
        let state = esrc.interrupt_state().read();
        state.es_entropy_valid();
        println!("state={:01x} data={:08x}", 
        u32::from(state),
            esrc.entropy_data().read());
        esrc.interrupt_state().write(|_| u32::from(state).into());
    }
    println!("Complete");
}


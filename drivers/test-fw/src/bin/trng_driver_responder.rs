// Licensed under the Apache-2.0 license

//! A very simple program that responds with TRNG data through the mailbox

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::{self, println};

use caliptra_drivers::{self, Trng};
use caliptra_registers::{
    csrng::CsrngReg, entropy_src::EntropySrcReg, mbox::MboxCsr, soc_ifc::SocIfcReg,
    soc_ifc_trng::SocIfcTrngReg,
};
use zerocopy::IntoBytes;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn cfi_panic_handler(code: u32) -> ! {
    println!("[TRNG] CFI Panic code=0x{:08X}", code);
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_trng = unsafe { SocIfcTrngReg::new() };
    let mut soc_ifc = unsafe { SocIfcReg::new() };

    let mut mbox = unsafe { MboxCsr::new() };
    let mut trng = Trng::new(csrng_reg, entropy_src_reg, soc_ifc_trng, &soc_ifc).unwrap();
    loop {
        if !mbox.regs().status().read().mbox_fsm_ps().mbox_execute_uc() {
            continue;
        }

        match trng.generate() {
            Ok(data) => {
                mbox.regs_mut()
                    .dlen()
                    .write(|_| data.0.as_bytes().len() as u32);
                for word in data.0 {
                    mbox.regs_mut().datain().write(|_| word);
                }
                mbox.regs_mut()
                    .status()
                    .write(|w| w.status(|w| w.data_ready()));
            }
            Err(e) => {
                soc_ifc
                    .regs_mut()
                    .cptra_fw_error_non_fatal()
                    .write(|_| e.into());
                mbox.regs_mut()
                    .status()
                    .write(|w| w.status(|w| w.cmd_failure()));
            }
        }
    }
}

// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use core::mem::MaybeUninit;

use crate::Array4x12;

pub struct TrngExt {
    soc_ifc_trng: SocIfcTrngReg,
}

impl TrngExt {
    pub fn new(soc_ifc_trng: SocIfcTrngReg) -> Self {
        Self { soc_ifc_trng }
    }

    pub fn generate(&mut self) -> CaliptraResult<Array4x12> {
        const MAX_CYCLES_TO_WAIT: u32 = 250000;

        let regs = self.soc_ifc_trng.regs_mut();
        regs.cptra_trng_status().write(|w| w.data_req(true));
        let mut cycles = 0;
        while !regs.cptra_trng_status().read().data_wr_done() {
            cycles += 1;
            if cycles >= MAX_CYCLES_TO_WAIT {
                return Err(CaliptraError::DRIVER_TRNG_EXT_TIMEOUT);
            }
        }

        // Manually unroll the generation of rng data to avoid a memcpy.
        //
        // This step occurs prior to CFI initialization where memcpy is
        // prohibited.
        let data = regs.cptra_trng_data();
        let mut result = MaybeUninit::<[u32; 12]>::uninit();
        let dest = result.as_mut_ptr() as *mut u32;

        // Safety: The destination array is a valid location on the stack, and aligned for word
        // writes so this is safe.
        unsafe {
            dest.add(0).write_volatile(data.at(0).read());
            dest.add(1).write_volatile(data.at(1).read());
            dest.add(2).write_volatile(data.at(2).read());
            dest.add(3).write_volatile(data.at(3).read());
            dest.add(4).write_volatile(data.at(4).read());
            dest.add(5).write_volatile(data.at(5).read());
            dest.add(6).write_volatile(data.at(6).read());
            dest.add(7).write_volatile(data.at(7).read());
            dest.add(8).write_volatile(data.at(8).read());
            dest.add(9).write_volatile(data.at(9).read());
            dest.add(10).write_volatile(data.at(10).read());
            dest.add(11).write_volatile(data.at(11).read());
        }
        regs.cptra_trng_status().write(|w| w.data_req(false));
        Ok(unsafe { result.assume_init() }.into())
    }
}

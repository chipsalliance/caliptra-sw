// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;

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
        let result = Array4x12::read_from_reg(regs.cptra_trng_data());
        regs.cptra_trng_status().write(|w| w.data_req(false));
        Ok(result)
    }

    pub fn generate4(&mut self) -> CaliptraResult<(u32, u32, u32, u32)> {
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
        let a = regs.cptra_trng_data().at(0).read();
        let b = regs.cptra_trng_data().at(1).read();
        let c = regs.cptra_trng_data().at(2).read();
        let d = regs.cptra_trng_data().at(3).read();
        regs.cptra_trng_status().write(|w| w.data_req(false));
        Ok((a, b, c, d))
    }
}

// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::sha512::Sha512Reg;

use crate::Array4x12;

pub struct Sha512 {
    sha512: Sha512Reg,
}

impl Sha512 {
    pub fn new(sha512: Sha512Reg) -> Self {
        Self { sha512 }
    }

    pub fn gen_pcr_hash(&mut self, nonce: [u32; 8]) -> CaliptraResult<Array4x12> {
        let reg = self.sha512.regs_mut();

        let status_reg = reg.gen_pcr_hash_status();

        // Wait for the registers to be ready
        while !status_reg.read().ready() {}

        // Write the nonce into the register
        reg.gen_pcr_hash_nonce().write(&nonce);

        // Use the start command to start the digesting process
        reg.gen_pcr_hash_ctrl().write(|ctrl| ctrl.start(true));

        // Wait for the registers to be ready
        while !status_reg.read().ready() {}

        if status_reg.read().valid() {
            Ok(reg.gen_pcr_hash_digest().read().into())
        } else {
            Err(CaliptraError::DRIVER_SHA384_INVALID_STATE_ERR)
        }
    }
}

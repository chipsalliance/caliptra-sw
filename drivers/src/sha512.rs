use caliptra_registers::sha512::Sha512Reg;

pub struct Sha512 {
    sha512: Sha512Reg,
}

impl Sha512 {
    pub fn new(sha512: Sha512Reg) -> Self {
        Self { sha512 }
    }

    pub fn gen_pcr_hash(&mut self, nonce: [u32; 8]) -> [u32; 12] {
        let reg = self.sha512.regs_mut();

        let status = reg.gen_pcr_hash_status().read();

        // Wait for the registers to be ready
        while !status.ready() {}

        // Write the nonce into the register
        reg.gen_pcr_hash_nonce().write(&nonce);

        // Use the start command to start the digesting process
        reg.gen_pcr_hash_ctrl().write(|ctrl| ctrl.start(true));

        // Wait for the registers to be ready
        while !status.ready() {}

        if status.valid() {
            reg.gen_pcr_hash_digest().read()
        } else {
            [0; 12] // TODO: This has to return a proper Result<T, E> type
        }
    }
}

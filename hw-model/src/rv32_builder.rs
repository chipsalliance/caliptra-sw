// Licensed under the Apache-2.0 license

/// The world's most primitive RISC-V assembler
#[derive(Default)]
pub struct Rv32Builder(Vec<u8>);

impl Rv32Builder {
    pub fn new() -> Self {
        Default::default()
    }
    /// Emit machine code to store val at address addr.
    pub fn store(mut self, addr: u32, val: u32) -> Self {
        self.lui(addr, 5);
        self.lui(val, 6);
        self.addi(val, 6, 6);
        self.sw(addr, 6, 5);
        self
    }
    /// Enter an infinite loop that does nothing.
    pub fn empty_loop(mut self) -> Self {
        self.instr32(0b1101111);
        self
    }

    /// Return the generated machine code.
    pub fn build(mut self) -> Vec<u8> {
        self.nop();
        self.0
    }

    fn lui(&mut self, imm: u32, rd: u32) {
        self.instr32((imm & !0xfff) | (rd << 7) | 0b0110111);
    }
    fn addi(&mut self, imm: u32, rs1: u32, rd: u32) {
        self.instr_j(imm, rs1, 0b000, rd, 0b010011);
    }
    fn sw(&mut self, imm: u32, src: u32, base: u32) {
        self.instr_s(imm, src, base, 0b010, 0b0100011);
    }
    fn nop(&mut self) {
        self.addi(0, 0, 0);
    }

    fn instr_j(&mut self, imm: u32, rs1: u32, op3: u32, rd: u32, op7: u32) {
        self.instr32(
            ((imm & 0xfff) << 20)
                | ((rs1 & 0x1f) << 15)
                | ((op3 & 0x7) << 12)
                | ((rd & 0x1f) << 7)
                | (op7 & 0x7f),
        );
    }
    fn instr_s(&mut self, imm: u32, rs2: u32, rs1: u32, op3: u32, op7: u32) {
        self.instr32(
            ((imm & 0xfe0) << 20)
                | ((rs2 & 0x1f) << 20)
                | ((rs1 & 0x1f) << 15)
                | ((op3 & 0x7) << 12)
                | ((imm & 0x1f) << 7)
                | (op7 & 0x7f),
        );
    }

    fn instr32(&mut self, instr: u32) {
        self.0.extend_from_slice(&instr.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rv32gen_mmio() {
        let code = Rv32Builder::new()
            .store(0x5678_1234, 0xa03d_2931)
            .empty_loop()
            .build();

        assert_eq!(
            &code,
            &[
                0xb7, 0x12, 0x78, 0x56, 0x37, 0x23, 0x3d, 0xa0, 0x13, 0x3, 0x13, 0x93, 0x23, 0xaa,
                0x62, 0x22, 0x6f, 0x0, 0x0, 0x0, 0x13, 0x0, 0x0, 0x0,
            ]
        );
    }
}

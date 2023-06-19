// License by Apache-2.0

pub struct Packet {
    cmd: u32,
    data: &[u8],
    checksum: u32,
}

impl Packet {
    pub fn new(cmd: u32, data: &[u8]) -> Self {
        let checksum = crate::calc_checksum(cmd, data.to_le_bytes());
        Self {
            cmd,
            data,
            checksum,
        }
    }
    pub fn verify(&self) -> bool {
        crate::verify_checksum(self.checksum, self.cmd, self.data)
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    capabilities.rs

Abstract:

    Capability bits

--*/

bitflags::bitflags! {
    /// First 32 bits are reserved for ROM, next 32 bits are rserved for FMC, and final 64 bits for
    /// RT.
    #[derive(Default, Copy, Clone, Debug)]
    pub struct Capabilities : u128 {
        // Represents base capabilities present in Caliptra ROM v1.0
        const ROM_BASE = 0b1;
        // Represents base capabilities present in Caliptra Runtime v1.0
        const RT_BASE = 0b1 << 64;
        // Represents ML-DSA attestation support in Caliptra Runtime
        const RT_MLDSA_ATTESTATION = 0b1 << 65;
    }
}

impl Capabilities {
    pub const SIZE_IN_BYTES: usize = 16;
    pub fn to_bytes(&self) -> [u8; Capabilities::SIZE_IN_BYTES] {
        self.bits().to_be_bytes()
    }
}

impl TryFrom<&[u8]> for Capabilities {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != Capabilities::SIZE_IN_BYTES {
            Err(())
        } else {
            let capabilities = u128::from_be_bytes(value.try_into().unwrap());
            let caps = Capabilities::from_bits(capabilities);
            caps.ok_or(())
        }
    }
}

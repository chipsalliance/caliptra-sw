/*++

Licensed under the Apache-2.0 license.

File Name:

    capabilities.rs

Abstract:

    Capability bits

--*/

bitflags::bitflags! {
    #[derive(Default, Copy, Clone, Debug)]
    pub struct Capabilities : u128 {
        // Represents base capabilities present in Caliptra ROM v1.0
        const ROM_BASE = 0b0001;
    }
}

impl Capabilities {
    pub fn to_bytes(&self) -> [u8; 16] {
        self.bits().to_be_bytes()
    }
}

impl TryFrom<&[u8]> for Capabilities {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            Err(())
        } else {
            let capabilities = u128::from_be_bytes(value.try_into().unwrap());
            let caps = Capabilities::from_bits(capabilities);
            caps.ok_or(())
        }
    }
}

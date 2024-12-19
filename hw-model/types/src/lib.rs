// Licensed under the Apache-2.0 license

use caliptra_api_types::{self, Fuses, SecurityState};
use std::array;

pub use caliptra_api_types::DeviceLifecycle;
use rand::{
    rngs::{StdRng, ThreadRng},
    RngCore, SeedableRng,
};

// Rationale behind this choice
//
// * The constant should be easily recognizable in waveforms and debug logs
// * Every word must be different to ensure that a "stuck word" bug is noticed.
// * Each byte in a word must be unique to ensure an endianness bug is noticed.
pub const DEFAULT_UDS_SEED: [u32; 16] = [
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
    0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f, 0x30313233, 0x34353637, 0x38393a3b, 0x3c3d3e3f,
];

pub const DEFAULT_FIELD_ENTROPY: [u32; 8] = [
    0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f, 0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f,
];

pub const DEFAULT_CPTRA_OBF_KEY: [u32; 8] = [
    0xa0a1a2a3, 0xb0b1b2b3, 0xc0c1c2c3, 0xd0d1d2d3, 0xe0e1e2e3, 0xf0f1f2f3, 0xa4a5a6a7, 0xb4b5b6b7,
];

pub const DEFAULT_MANUF_DEBUG_UNLOCK_TOKEN: [u32; 4] =
    [0xcfcecdcc, 0xcbcac9c8, 0xc7c6c5c4, 0xc3c2c1c0];

struct SecurityStateWrapper(SecurityState);
impl std::fmt::Debug for SecurityStateWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityState")
            .field("debug_locked", &self.0.debug_locked())
            .field("device_lifecycle", &self.0.device_lifecycle())
            .finish()
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum U4 {
    #[default]
    X0 = 0x0,
    X1 = 0x1,
    X2 = 0x2,
    X3 = 0x3,
    X4 = 0x4,
    X5 = 0x5,
    X6 = 0x6,
    X7 = 0x7,
    X8 = 0x8,
    X9 = 0x9,
    Xa = 0xa,
    Xb = 0xb,
    Xc = 0xc,
    Xd = 0xd,
    Xe = 0xe,
    Xf = 0xf,
}
impl U4 {
    pub const B0000: Self = Self::X0;
    pub const B0001: Self = Self::X1;
    pub const B0010: Self = Self::X2;
    pub const B0011: Self = Self::X3;
    pub const B0100: Self = Self::X4;
    pub const B0101: Self = Self::X5;
    pub const B0110: Self = Self::X6;
    pub const B0111: Self = Self::X7;
    pub const B1000: Self = Self::X8;
    pub const B1001: Self = Self::X9;
    pub const B1010: Self = Self::Xa;
    pub const B1011: Self = Self::Xb;
    pub const B1100: Self = Self::Xc;
    pub const B1101: Self = Self::Xd;
    pub const B1110: Self = Self::Xe;
    pub const B1111: Self = Self::Xf;
}
impl From<U4> for u32 {
    fn from(value: U4) -> Self {
        value as u32
    }
}

impl TryFrom<u32> for U4 {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0b0000 => Ok(Self::X0),
            0b0001 => Ok(Self::X1),
            0b0010 => Ok(Self::X2),
            0b0011 => Ok(Self::X3),
            0b0100 => Ok(Self::X4),
            0b0101 => Ok(Self::X5),
            0b0110 => Ok(Self::X6),
            0b0111 => Ok(Self::X7),
            0b1000 => Ok(Self::X8),
            0b1001 => Ok(Self::X9),
            0b1010 => Ok(Self::Xa),
            0b1011 => Ok(Self::Xb),
            0b1100 => Ok(Self::Xc),
            0b1101 => Ok(Self::Xd),
            0b1110 => Ok(Self::Xe),
            0b1111 => Ok(Self::Xf),
            16_u32..=u32::MAX => Err(()),
        }
    }
}

struct FusesWrapper(Fuses);
impl std::fmt::Debug for FusesWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fuses")
            .field("uds_seed", &HexSlice(&self.0.uds_seed))
            .field("field_entropy", &HexSlice(&self.0.field_entropy))
            .field(
                "key_manifest_pk_hash",
                &HexSlice(&self.0.key_manifest_pk_hash),
            )
            .field(
                "key_manifest_pk_hash_mask",
                &self.0.key_manifest_pk_hash_mask,
            )
            .field("owner_pk_hash", &HexSlice(&self.0.owner_pk_hash))
            .field("fmc_key_manifest_svn", &self.0.fmc_key_manifest_svn)
            .field("runtime_svn", &HexSlice(&self.0.runtime_svn))
            .field("anti_rollback_disable", &self.0.anti_rollback_disable)
            .field("idevid_cert_attr", &HexSlice(&self.0.idevid_cert_attr))
            .field(
                "idevid_manuf_hsm_id",
                &HexSlice(&self.0.idevid_manuf_hsm_id),
            )
            .field("life_cycle", &self.0.life_cycle)
            .field("fuse_lms_revocation", &self.0.fuse_lms_revocation)
            .field("soc_stepping_id", &self.0.soc_stepping_id)
            .finish()
    }
}

pub struct HexSlice<'a, T: std::fmt::LowerHex + PartialEq>(pub &'a [T]);
impl<'a, T: std::fmt::LowerHex + PartialEq> std::fmt::Debug for HexSlice<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let width = std::mem::size_of::<T>() * 2 + 2;
        if self.0.len() > 1 && self.0.iter().all(|item| item == &self.0[0]) {
            write!(f, "[{:#0width$x}; {}]", self.0[0], self.0.len())?;
            return Ok(());
        }
        write!(f, "[")?;
        for (i, val) in self.0.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{:#0width$x}", val)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

pub struct HexBytes<'a>(pub &'a [u8]);
impl<'a> std::fmt::Debug for HexBytes<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"")?;
        for val in self.0.iter() {
            write!(f, "{val:02x}")?;
        }
        write!(f, "\"")?;
        Ok(())
    }
}

pub struct RandomNibbles<R: RngCore>(pub R);

impl RandomNibbles<ThreadRng> {
    pub fn new_from_thread_rng() -> Self {
        Self(rand::thread_rng())
    }
}

impl<R: RngCore> Iterator for RandomNibbles<R> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        Some((self.0.next_u32() & 0xf) as u8)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct EtrngResponse {
    pub delay: u32,
    pub data: [u32; 12],
}

pub struct RandomEtrngResponses<R: RngCore>(pub R);
impl RandomEtrngResponses<StdRng> {
    pub fn new_from_stdrng() -> Self {
        Self(StdRng::from_entropy())
    }
}
impl<R: RngCore> Iterator for RandomEtrngResponses<R> {
    type Item = EtrngResponse;

    fn next(&mut self) -> Option<Self::Item> {
        Some(EtrngResponse {
            delay: 0,
            data: array::from_fn(|_| self.0.next_u32()),
        })
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ErrorInjectionMode {
    #[default]
    None,
    IccmDoubleBitEcc,
    DccmDoubleBitEcc,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hex_bytes() {
        assert_eq!("\"\"", format!("{:?}", HexBytes(&[])));
        assert_eq!("\"ab1f\"", format!("{:?}", HexBytes(&[0xab, 0x1f])))
    }

    #[test]
    fn test_hex_slice() {
        assert_eq!("[]", format!("{:?}", HexSlice(&[0_u8; 0])));
        assert_eq!("[]", format!("{:?}", HexSlice(&[0_u16; 0])));
        assert_eq!("[]", format!("{:?}", HexSlice(&[0_u32; 0])));

        assert_eq!("[0x84]", format!("{:?}", HexSlice(&[0x84_u8])));
        assert_eq!("[0x7c63]", format!("{:?}", HexSlice(&[0x7c63_u16])));
        assert_eq!("[0x47dbaa30]", format!("{:?}", HexSlice(&[0x47dbaa30_u32])));
        assert_eq!(
            "[0x97f48c6bf52f06bb]",
            format!("{:?}", HexSlice(&[0x97f48c6bf52f06bb_u64]))
        );

        assert_eq!("[0x00; 32]", format!("{:?}", HexSlice(&[0x00_u8; 32])));
        assert_eq!("[0x7c63; 32]", format!("{:?}", HexSlice(&[0x7c63_u16; 32])));
        assert_eq!(
            "[0x47dbaa30; 32]",
            format!("{:?}", HexSlice(&[0x47dbaa30_u32; 32]))
        );
        assert_eq!(
            "[0x97f48c6bf52f06bb; 32]",
            format!("{:?}", HexSlice(&[0x97f48c6bf52f06bb_u64; 32]))
        );

        assert_eq!("[0xab, 0x1f]", format!("{:?}", HexSlice(&[0xab_u8, 0x1f])));
        assert_eq!(
            "[0x00ab, 0x001f]",
            format!("{:?}", HexSlice(&[0xab_u16, 0x1f]))
        );
        assert_eq!(
            "[0x000000ab, 0x0000001f]",
            format!("{:?}", HexSlice(&[0xab_u32, 0x1f]))
        );
        assert_eq!(
            "[0x00000000000000ab, 0x000000000000001f]",
            format!("{:?}", HexSlice(&[0xab_u64, 0x1f]))
        );

        assert_eq!(
            "[0x0b, 0x2a, 0x40]",
            format!("{:?}", HexSlice(&[0x0b_u8, 0x2a, 0x40]))
        );
        assert_eq!(
            "[0xad83, 0xa91f, 0x9c8b]",
            format!("{:?}", HexSlice(&[0xad83_u16, 0xa91f, 0x9c8b]))
        );
        assert_eq!(
            "[0xde85388f, 0xda448d4c, 0x329c1f58]",
            format!("{:?}", HexSlice(&[0xde85388f_u32, 0xda448d4c, 0x329c1f58]))
        );
        assert_eq!(
            "[0x8ab6401e7f681569, 0xc60f65a019714215, 0xbc24d103aeecad40]",
            format!(
                "{:?}",
                HexSlice(&[
                    0x8ab6401e7f681569_u64,
                    0xc60f65a019714215,
                    0xbc24d103aeecad40
                ])
            )
        );
    }
}

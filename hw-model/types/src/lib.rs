// Licensed under the Apache-2.0 license

use std::array;

use rand::{
    rngs::{StdRng, ThreadRng},
    RngCore, SeedableRng,
};

// Rationale behind this choice
//
// * The constant should be easily recognizable in waveforms and debug logs
// * Every word must be different to ensure that a "stuck word" bug is noticed.
// * Each byte in a word must be unique to ensure an endianness bug is noticed.
pub const DEFAULT_UDS_SEED: [u32; 12] = [
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
    0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f,
];

pub const DEFAULT_FIELD_ENTROPY: [u32; 8] = [
    0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f, 0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f,
];

pub const DEFAULT_CPTRA_OBF_KEY: [u32; 8] = [
    0xa0a1a2a3, 0xb0b1b2b3, 0xc0c1c2c3, 0xd0d1d2d3, 0xe0e1e2e3, 0xf0f1f2f3, 0xa4a5a6a7, 0xb4b5b6b7,
];

// Based on device_lifecycle_e from RTL
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum DeviceLifecycle {
    #[default]
    Unprovisioned = 0b00,
    Manufacturing = 0b01,
    Reserved2 = 0b10,
    Production = 0b11,
}
impl TryFrom<u32> for DeviceLifecycle {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(Self::Unprovisioned),
            0b01 => Ok(Self::Manufacturing),
            0b10 => Ok(Self::Reserved2),
            0b11 => Ok(Self::Production),
            _ => Err(()),
        }
    }
}
impl From<DeviceLifecycle> for u32 {
    fn from(value: DeviceLifecycle) -> Self {
        value as u32
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct SecurityState(u32);
impl From<u32> for SecurityState {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl From<SecurityState> for u32 {
    fn from(value: SecurityState) -> Self {
        value.0
    }
}

impl SecurityState {
    pub fn debug_locked(self) -> bool {
        (self.0 & (1 << 2)) != 0
    }
    pub fn set_debug_locked(&mut self, val: bool) -> &mut Self {
        let mask = 1 << 2;
        if val {
            self.0 |= mask;
        } else {
            self.0 &= !mask
        };
        self
    }
    pub fn device_lifecycle(self) -> DeviceLifecycle {
        DeviceLifecycle::try_from(self.0 & 0x3).unwrap()
    }
    pub fn set_device_lifecycle(&mut self, val: DeviceLifecycle) -> &mut Self {
        self.0 |= (val as u32) & 0x3;
        self
    }
}
impl std::fmt::Debug for SecurityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityState")
            .field("debug_locked", &self.debug_locked())
            .field("device_lifecycle", &self.device_lifecycle())
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

#[derive(Clone, Copy)]
pub struct Fuses {
    pub uds_seed: [u32; 12],
    pub field_entropy: [u32; 8],
    pub key_manifest_pk_hash: [u32; 12],
    pub key_manifest_pk_hash_mask: U4,
    pub owner_pk_hash: [u32; 12],
    pub fmc_key_manifest_svn: u32,
    pub runtime_svn: [u32; 4],
    pub anti_rollback_disable: bool,
    pub idevid_cert_attr: [u32; 24],
    pub idevid_manuf_hsm_id: [u32; 4],
    pub life_cycle: DeviceLifecycle,
    pub lms_verify: bool,
    pub fuse_lms_revocation: u32,
    pub soc_stepping_id: u16,
}
impl Default for Fuses {
    fn default() -> Self {
        Self {
            uds_seed: DEFAULT_UDS_SEED,
            field_entropy: DEFAULT_FIELD_ENTROPY,
            key_manifest_pk_hash: Default::default(),
            key_manifest_pk_hash_mask: Default::default(),
            owner_pk_hash: Default::default(),
            fmc_key_manifest_svn: Default::default(),
            runtime_svn: Default::default(),
            anti_rollback_disable: Default::default(),
            idevid_cert_attr: Default::default(),
            idevid_manuf_hsm_id: Default::default(),
            life_cycle: Default::default(),
            lms_verify: Default::default(),
            fuse_lms_revocation: Default::default(),
            soc_stepping_id: Default::default(),
        }
    }
}
impl std::fmt::Debug for Fuses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fuses")
            .field("uds_seed", &HexSlice(&self.uds_seed))
            .field("field_entropy", &HexSlice(&self.field_entropy))
            .field(
                "key_manifest_pk_hash",
                &HexSlice(&self.key_manifest_pk_hash),
            )
            .field("key_manifest_pk_hash_mask", &self.key_manifest_pk_hash_mask)
            .field("owner_pk_hash", &HexSlice(&self.owner_pk_hash))
            .field("fmc_key_manifest_svn", &self.fmc_key_manifest_svn)
            .field("runtime_svn", &HexSlice(&self.runtime_svn))
            .field("anti_rollback_disable", &self.anti_rollback_disable)
            .field("idevid_cert_attr", &HexSlice(&self.idevid_cert_attr))
            .field("idevid_manuf_hsm_id", &HexSlice(&self.idevid_manuf_hsm_id))
            .field("life_cycle", &self.life_cycle)
            .field("lms_verify", &self.lms_verify)
            .field("fuse_lms_revocation", &self.fuse_lms_revocation)
            .field("soc_stepping_id", &self.soc_stepping_id)
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
    fn test_security_state() {
        let mut ss = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Manufacturing);
        assert_eq!(0x5u32, ss.into());
        assert!(ss.debug_locked());
        assert_eq!(ss.device_lifecycle(), DeviceLifecycle::Manufacturing);
        ss.set_debug_locked(false);
        assert_eq!(0x1u32, ss.into());
    }

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

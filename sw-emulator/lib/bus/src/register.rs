use crate::BusError;
use caliptra_emu_types::{RvData, RvSize};

pub trait Register {
    /// Read the register contents with an load of size `size`.
    fn read(&self, size: RvSize) -> Result<RvData, BusError>;

    /// Write the register contents with a store of size `size`.
    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError>;
}

impl Register for u8 {
    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        match size {
            RvSize::Byte => Ok(u32::from(*self)),
            _ => Err(BusError::LoadAccessFault),
        }
    }

    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        match size {
            RvSize::Byte => {
                *self = val as u8;
                Ok(())
            }
            _ => Err(BusError::StoreAccessFault),
        }
    }
}
impl Register for u16 {
    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        match size {
            RvSize::HalfWord => Ok(u32::from(*self)),
            _ => Err(BusError::LoadAccessFault),
        }
    }

    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        match size {
            RvSize::HalfWord => {
                *self = val as u16;
                Ok(())
            }
            _ => Err(BusError::StoreAccessFault),
        }
    }
}

impl Register for u32 {
    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        match size {
            RvSize::Word => Ok(*self),
            _ => Err(BusError::LoadAccessFault),
        }
    }

    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        match size {
            RvSize::Word => {
                *self = val;
                Ok(())
            }
            _ => Err(BusError::StoreAccessFault),
        }
    }
}

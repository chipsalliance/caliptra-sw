use caliptra_emu_types::{RvData, RvException, RvSize};

pub trait Register {
    /// Read the register contents with an load of size `size`.
    fn read(&self, size: RvSize) -> Result<RvData, RvException>;

    /// Write the register contents with a store of size `size`.
    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), RvException>;
}

impl Register for u8 {
    fn read(&self, size: RvSize) -> Result<RvData, RvException> {
        match size {
            RvSize::Byte => Ok(u32::from(*self)),
            // TODO(kor) - Remove address from access_fault errors returned
            // by Bus/Register; they don't know what the actual address is, but
            // the CPU knows and can add it to the RvException.
            _ => Err(RvException::load_access_fault(0)),
        }
    }

    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), RvException> {
        match size {
            RvSize::Byte => {
                *self = val as u8;
                Ok(())
            }
            _ => Err(RvException::store_access_fault(0)),
        }
    }
}
impl Register for u16 {
    fn read(&self, size: RvSize) -> Result<RvData, RvException> {
        match size {
            RvSize::HalfWord => Ok(u32::from(*self)),
            _ => Err(RvException::load_access_fault(0)),
        }
    }

    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), RvException> {
        match size {
            RvSize::HalfWord => {
                *self = val as u16;
                Ok(())
            }
            _ => Err(RvException::store_access_fault(0)),
        }
    }
}

impl Register for u32 {
    fn read(&self, size: RvSize) -> Result<RvData, RvException> {
        match size {
            RvSize::Word => Ok(*self),
            _ => Err(RvException::load_access_fault(0)),
        }
    }

    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), RvException> {
        match size {
            RvSize::Word => {
                *self = val;
                Ok(())
            }
            _ => Err(RvException::store_access_fault(0)),
        }
    }
}

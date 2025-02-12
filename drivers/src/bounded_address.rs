// Licensed under the Apache-2.0 license

use core::fmt::Debug;
use core::marker::PhantomData;

use caliptra_error::CaliptraError;
use zerocopy::{FromBytes, Immutable, IntoBytes, TryFromBytes, Unalign};
use zeroize::Zeroize;

use crate::memory_layout;

pub trait MemBounds {
    const ORG: usize;
    const SIZE: usize;
    const ERROR: CaliptraError;
}
pub struct RomBounds {}
impl MemBounds for RomBounds {
    const ORG: usize = memory_layout::ROM_ORG as usize;
    const SIZE: usize = memory_layout::ROM_SIZE as usize;
    const ERROR: CaliptraError = CaliptraError::ADDRESS_NOT_IN_ROM;
}

pub type RomAddr<T> = BoundedAddr<T, RomBounds>;

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable)]
pub struct BoundedAddr<T: IntoBytes + FromBytes, B: MemBounds> {
    addr: Unalign<u32>,
    _phantom: PhantomData<(T, B)>,
}

impl<T, B> Zeroize for BoundedAddr<T, B>
where
    T: IntoBytes + FromBytes,
    B: MemBounds,
{
    fn zeroize(&mut self) {
        // This should never fail, and always be aligned.
        if let Ok(addr) = self.addr.try_deref_mut() {
            addr.zeroize();
        }
        // NOP since PhantomData has no data, but might as well be thorough.
        self._phantom.zeroize();
    }
}

impl<T: IntoBytes + FromBytes, B: MemBounds> BoundedAddr<T, B> {
    pub fn new(addr: u32) -> Self {
        Self {
            addr: Unalign::new(addr),
            _phantom: Default::default(),
        }
    }
    pub fn get(&self) -> Result<&T, CaliptraError> {
        assert!(core::mem::size_of::<Self>() == core::mem::size_of::<u32>());
        Self::validate_addr(self.addr.get())?;
        Ok(unsafe { &*(self.addr.get() as *const T) })
    }
    pub fn is_valid(&self) -> bool {
        Self::validate_addr(self.addr.get()).is_ok()
    }
    pub fn validate_addr(addr: u32) -> Result<(), CaliptraError> {
        let addr = addr as usize;

        if addr % core::mem::align_of::<T>() != 0 {
            return Err(CaliptraError::ADDRESS_MISALIGNED);
        }
        let size = core::mem::size_of::<T>();
        if addr < B::ORG || size > B::SIZE || addr > B::ORG + (B::SIZE - size) {
            return Err(B::ERROR);
        }
        Ok(())
    }
}
impl<T: IntoBytes + FromBytes, B: MemBounds> Clone for BoundedAddr<T, B> {
    fn clone(&self) -> Self {
        Self::new(self.addr.get())
    }
}
impl<T: IntoBytes + FromBytes, B: MemBounds> Debug for BoundedAddr<T, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RomAddr")
            .field("addr", &self.addr.get())
            .finish()
    }
}
impl<T: IntoBytes + FromBytes, B: MemBounds> From<&'static T> for BoundedAddr<T, B> {
    fn from(value: &'static T) -> Self {
        Self::new(value as *const T as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_layout::{ROM_ORG, ROM_SIZE};

    #[derive(IntoBytes, FromBytes)]
    #[repr(C)]
    struct MyStruct {
        a: u32,
        b: u32,
    }

    #[test]
    fn test_rom_address_validate() {
        RomAddr::<MyStruct>::validate_addr(ROM_ORG).unwrap();
        RomAddr::<MyStruct>::validate_addr(ROM_ORG + 4).unwrap();
        RomAddr::<MyStruct>::validate_addr(ROM_ORG + ROM_SIZE - 8).unwrap();
        RomAddr::<u8>::validate_addr(ROM_ORG + ROM_SIZE - 1).unwrap();

        assert_eq!(
            RomAddr::<MyStruct>::validate_addr(ROM_ORG + 1),
            Err(CaliptraError::ADDRESS_MISALIGNED)
        );
        assert_eq!(
            RomAddr::<MyStruct>::validate_addr(ROM_ORG + 2),
            Err(CaliptraError::ADDRESS_MISALIGNED)
        );
        assert_eq!(
            RomAddr::<MyStruct>::validate_addr(ROM_ORG + ROM_SIZE - 4),
            Err(CaliptraError::ADDRESS_NOT_IN_ROM)
        );
        assert_eq!(
            RomAddr::<u8>::validate_addr(ROM_ORG + ROM_SIZE),
            Err(CaliptraError::ADDRESS_NOT_IN_ROM)
        );
        assert_eq!(
            RomAddr::<u8>::validate_addr(ROM_ORG + ROM_SIZE + 24381),
            Err(CaliptraError::ADDRESS_NOT_IN_ROM)
        );
        assert_eq!(
            RomAddr::<[u8; 128 * 1024]>::validate_addr(ROM_ORG),
            Err(CaliptraError::ADDRESS_NOT_IN_ROM)
        );
    }
}

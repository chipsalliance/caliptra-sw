// Licensed under the Apache-2.0 license

use std::{
    marker::PhantomData,
    ops::{Index, IndexMut},
};

use caliptra_emu_types::{RvAddr, RvData, RvSize};
use tock_registers::{LocalRegisterCopy, RegisterLongName, UIntLike};

use crate::{Bus, BusError, Register};

pub trait RegisterArray {
    const ITEM_SIZE: usize;
    const LEN: usize;
}
impl<const LEN: usize, T: Register> RegisterArray for [T; LEN] {
    const ITEM_SIZE: usize = T::SIZE;
    const LEN: usize = LEN;
}
pub struct ReadWriteRegisterArray<
    T: Copy + UIntLike + Into<RvData> + TryFrom<RvData>,
    const SIZE: usize,
    R: RegisterLongName = (),
> {
    regs: [LocalRegisterCopy<T, R>; SIZE],
    associated_register: PhantomData<R>,
}

impl<
        T: UIntLike + Into<RvData> + TryFrom<RvData>,
        const SIZE: usize,
        R: Copy + RegisterLongName,
    > ReadWriteRegisterArray<T, SIZE, R>
{
    pub fn new(default_value: T) -> Self {
        Self {
            regs: [LocalRegisterCopy::new(default_value); SIZE],
            associated_register: PhantomData,
        }
    }
}
impl<T: UIntLike + Into<RvData> + TryFrom<RvData>, const SIZE: usize, R: RegisterLongName>
    ReadWriteRegisterArray<T, SIZE, R>
{
    pub fn iter(&self) -> impl Iterator<Item = &LocalRegisterCopy<T, R>> {
        self.regs.iter()
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut LocalRegisterCopy<T, R>> {
        self.regs.iter_mut()
    }
}
impl<T: UIntLike + Into<RvData> + TryFrom<RvData>, const SIZE: usize, R: RegisterLongName>
    Index<usize> for ReadWriteRegisterArray<T, SIZE, R>
{
    type Output = LocalRegisterCopy<T, R>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.regs[index]
    }
}
impl<T: UIntLike + Into<RvData> + TryFrom<RvData>, const SIZE: usize, R: RegisterLongName>
    IndexMut<usize> for ReadWriteRegisterArray<T, SIZE, R>
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.regs[index]
    }
}
impl<T: UIntLike + Into<RvData> + TryFrom<RvData>, const SIZE: usize, R: RegisterLongName>
    RegisterArray for ReadWriteRegisterArray<T, SIZE, R>
{
    const ITEM_SIZE: usize = std::mem::size_of::<T>();
    const LEN: usize = SIZE;
}
impl<T: UIntLike + Into<RvData> + TryFrom<RvData>, const SIZE: usize, R: RegisterLongName> Bus
    for ReadWriteRegisterArray<T, SIZE, R>
{
    fn read(&mut self, _size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if addr as usize % std::mem::size_of::<T>() != 0 {
            return Err(BusError::LoadAddrMisaligned);
        }
        // TODO: Check size?
        let i = addr as usize / std::mem::size_of::<T>();
        Ok((*self.regs.get(i).ok_or(BusError::LoadAccessFault)?)
            .get()
            .into())
    }
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if usize::from(size) != std::mem::size_of::<T>() {
            return Err(BusError::StoreAccessFault);
        }
        if addr as usize % std::mem::size_of::<T>() != 0 {
            return Err(BusError::StoreAddrMisaligned);
        }
        let i = addr as usize / std::mem::size_of::<T>();
        self.regs
            .get_mut(i)
            .ok_or(BusError::StoreAccessFault)?
            .set(T::try_from(val).map_err(|_| BusError::StoreAccessFault)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tock_registers::register_bitfields;

    use super::*;

    register_bitfields! [
        u32,

        Meipl [
            PRIORITY OFFSET(0) NUMBITS(4) [],
        ],
    ];
    register_bitfields! [
        u16,

        Meipl16 [
            PRIORITY OFFSET(0) NUMBITS(4) [],
        ],
    ];

    #[test]
    fn test_read_and_write() {
        let mut array: ReadWriteRegisterArray<u32, 32, Meipl::Register> =
            ReadWriteRegisterArray::new(0x40);
        assert_eq!(0, array[0].read(Meipl::PRIORITY));
        assert_eq!(0x40, array[0].get());
        assert_eq!(0x40, Bus::read(&mut array, RvSize::Word, 0).unwrap());

        array[0].write(Meipl::PRIORITY.val(0xa));
        assert_eq!(0x0a, array[0].read(Meipl::PRIORITY));
        assert_eq!(0x0a, array[0].get());
        assert_eq!(0x0a, Bus::read(&mut array, RvSize::Word, 0).unwrap());

        array[1].modify(Meipl::PRIORITY.val(5));
        assert_eq!(0x05, array[1].read(Meipl::PRIORITY));
        assert_eq!(0x45, Bus::read(&mut array, RvSize::Word, 4).unwrap());

        Bus::write(&mut array, RvSize::Word, 31 * 4, 0x2e).unwrap();
        assert_eq!(0x2e, Bus::read(&mut array, RvSize::Word, 31 * 4).unwrap());
        assert_eq!(0x0e, array[31].read(Meipl::PRIORITY));

        assert_eq!(
            vec![
                0x0a, 0x45, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x2e
            ],
            array.iter().map(|a| a.get()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_bus_faults() {
        let mut array: ReadWriteRegisterArray<u32, 32, Meipl::Register> =
            ReadWriteRegisterArray::new(0x00);

        assert_eq!(
            Bus::read(&mut array, RvSize::Word, 32 * 4),
            Err(BusError::LoadAccessFault)
        );
        assert_eq!(
            Bus::write(&mut array, RvSize::Word, 32 * 4, 0),
            Err(BusError::StoreAccessFault)
        );
        assert_eq!(
            Bus::read(&mut array, RvSize::Word, 1),
            Err(BusError::LoadAddrMisaligned)
        );
        assert_eq!(
            Bus::write(&mut array, RvSize::Word, 1, 0),
            Err(BusError::StoreAddrMisaligned)
        );
        assert_eq!(
            Bus::write(&mut array, RvSize::HalfWord, 0, 0),
            Err(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_read_and_write_16bit() {
        let mut array: ReadWriteRegisterArray<u16, 32, Meipl16::Register> =
            ReadWriteRegisterArray::new(0x40);
        assert_eq!(0, array[0].read(Meipl16::PRIORITY));
        assert_eq!(0x40, array[0].get());
        assert_eq!(0x40, Bus::read(&mut array, RvSize::HalfWord, 0).unwrap());

        array[0].write(Meipl16::PRIORITY.val(0xa));
        assert_eq!(0x0a, array[0].read(Meipl16::PRIORITY));
        assert_eq!(0x0a, array[0].get());
        assert_eq!(0x0a, Bus::read(&mut array, RvSize::HalfWord, 0).unwrap());

        array[1].modify(Meipl16::PRIORITY.val(5));
        assert_eq!(0x05, array[1].read(Meipl16::PRIORITY));
        assert_eq!(0x45, Bus::read(&mut array, RvSize::HalfWord, 2).unwrap());

        Bus::write(&mut array, RvSize::HalfWord, 31 * 2, 0x2e).unwrap();
        assert_eq!(
            0x2e,
            Bus::read(&mut array, RvSize::HalfWord, 31 * 2).unwrap()
        );
        assert_eq!(0x0e, array[31].read(Meipl16::PRIORITY));

        assert_eq!(
            vec![
                0x0a, 0x45, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
                0x40, 0x40, 0x40, 0x2e
            ],
            array.iter().map(|a| a.get()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_bus_faults_16bit() {
        let mut array: ReadWriteRegisterArray<u16, 32, Meipl16::Register> =
            ReadWriteRegisterArray::new(0x00);

        assert_eq!(
            Bus::read(&mut array, RvSize::HalfWord, 32 * 2),
            Err(BusError::LoadAccessFault)
        );
        assert_eq!(
            Bus::write(&mut array, RvSize::HalfWord, 32 * 2, 0),
            Err(BusError::StoreAccessFault)
        );
        assert_eq!(
            Bus::read(&mut array, RvSize::HalfWord, 1),
            Err(BusError::LoadAddrMisaligned)
        );
        assert_eq!(
            Bus::write(&mut array, RvSize::HalfWord, 1, 0),
            Err(BusError::StoreAddrMisaligned)
        );
        assert_eq!(
            Bus::write(&mut array, RvSize::Word, 0, 0),
            Err(BusError::StoreAccessFault)
        );
        assert_eq!(
            Bus::write(&mut array, RvSize::Byte, 0, 0),
            Err(BusError::StoreAccessFault)
        );
    }
}

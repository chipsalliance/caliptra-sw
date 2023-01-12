/*++

Licensed under the Apache-2.0 license.

File Name:

    array.rs

Abstract:

    File contains common array definitions used by Caliptra hardware software
    interface.

--*/

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Array4xN<const W: usize, const B: usize>(pub [u32; W]);

impl<const W: usize, const B: usize> Default for Array4xN<W, B> {
    fn default() -> Self {
        Self([0u32; W])
    }
}

impl<const W: usize, const B: usize> Array4xN<W, B> {
    #[inline(never)]
    #[allow(unused)]
    pub fn read_from_reg<
        const W2: usize,
        TReg: ureg::ReadableReg<ReadVal = u32>,
        TMmio: ureg::Mmio,
    >(
        reg_array: ureg::Array<W2, ureg::RegRef<TReg, TMmio>>,
    ) -> Self {
        let mut result = [0u32; W];

        for (i, part) in result.iter_mut().enumerate().take(W) {
            *part = reg_array.at(i).read();
        }

        result.into()
    }

    #[inline(never)]
    #[allow(unused)]
    pub fn write_to_reg<
        TReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = u32>,
        TMmio: ureg::Mmio,
    >(
        &self,
        reg_array: ureg::Array<W, ureg::RegRef<TReg, TMmio>>,
    ) {
        for i in 0..W {
            reg_array.at(i).write(|_| self.0[i]);
        }
    }
}

impl<const W: usize, const B: usize> From<[u8; B]> for Array4xN<W, B> {
    #[inline(never)]
    fn from(value: [u8; B]) -> Self {
        let mut result = Self([0u32; W]);
        for i in 0..W {
            result.0[i] = u32::from_be_bytes(value[i * 4..][..4].try_into().unwrap())
        }
        result
    }
}

impl<const W: usize, const B: usize> From<Array4xN<W, B>> for [u8; B] {
    #[inline(never)]
    fn from(value: Array4xN<W, B>) -> Self {
        let mut result = [0u8; B];
        for i in 0..W {
            *<&mut [u8; 4]>::try_from(&mut result[i * 4..][..4]).unwrap() =
                value.0[i].to_be_bytes();
        }
        result
    }
}

impl<'a, const W: usize, const B: usize> From<&'a [u8; B]> for Array4xN<W, B> {
    #[inline(never)]
    fn from(value: &'a [u8; B]) -> Self {
        let mut result = Self([0u32; W]);
        for i in 0..W {
            result.0[i] = u32::from_be_bytes(value[i * 4..][..4].try_into().unwrap())
        }
        result
    }
}

impl<const W: usize, const B: usize> From<[u32; W]> for Array4xN<W, B> {
    #[inline(never)]
    fn from(value: [u32; W]) -> Self {
        Self(value)
    }
}

impl<const W: usize, const B: usize> From<Array4xN<W, B>> for [u32; W] {
    #[inline(never)]
    fn from(value: Array4xN<W, B>) -> Self {
        value.0
    }
}

pub type Array4x4 = Array4xN<4, 16>;
pub type Array4x8 = Array4xN<8, 32>;
pub type Array4x12 = Array4xN<12, 48>;
pub type Array4x16 = Array4xN<16, 64>;
pub type Array4x32 = Array4xN<32, 128>;

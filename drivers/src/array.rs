/*++

Licensed under the Apache-2.0 license.

File Name:

    array.rs

Abstract:

    File contains common array definitions used by Caliptra hardware software
    interface.

--*/

macro_rules! array4 {
    ($dim: literal) => {
        paste::paste! {
             pub const [<ARRAY_4X $dim _BYTE_SIZE>]: usize = $dim * core::mem::size_of::<u32>();
             pub const [<ARRAY_4X $dim _WORD_SIZE>]: usize = $dim ;

             #[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
             pub struct [<Array4x $dim>](pub [u32; [<ARRAY_4X $dim _WORD_SIZE>]]);

             impl From<[u8; [<ARRAY_4X $dim _BYTE_SIZE>]]> for [<Array4x $dim>] {
                 #[inline(never)]
                 fn from(value: [u8; [<ARRAY_4X $dim _BYTE_SIZE>]]) -> Self {
                     let mut result = [<Array4x $dim>]([0u32; [<ARRAY_4X $dim _WORD_SIZE>]]);

                     for i in 0..[<ARRAY_4X $dim _WORD_SIZE>] {
                         result.0[i] = u32::from_be_bytes(value[i * 4..][..4].try_into().unwrap())
                     }

                     result
                 }
             }

             impl From<[<Array4x $dim>]> for [u8; [<ARRAY_4X $dim _BYTE_SIZE>]] {
                 #[inline(never)]
                 fn from(value: [<Array4x $dim>]) -> Self {
                     let mut result = [0u8; [<ARRAY_4X $dim _BYTE_SIZE>]];

                     for i in 0..[<ARRAY_4X $dim _WORD_SIZE>] {
                         *<&mut [u8; 4]>::try_from(&mut result[i * 4..][..4]).unwrap() =
                             value.0[i].to_be_bytes();
                     }

                     result
                 }
             }

             impl<'a> From<&'a [u8; [<ARRAY_4X $dim _BYTE_SIZE>]]> for [<Array4x $dim>] {
                 #[inline(never)]
                 fn from(value: &'a [u8; [<ARRAY_4X $dim _BYTE_SIZE>]]) -> Self {
                     let mut result = [<Array4x $dim>]([0u32; [<ARRAY_4X $dim _WORD_SIZE>]]);

                     for i in 0..[<ARRAY_4X $dim _WORD_SIZE>] {
                         result.0[i] = u32::from_be_bytes(value[i * 4..][..4].try_into().unwrap())
                     }

                     result
                 }
             }

             impl From<[u32; [<ARRAY_4X $dim _WORD_SIZE>]]> for [<Array4x $dim>] {
                 #[inline(never)]
                 fn from(value: [u32; [<ARRAY_4X $dim _WORD_SIZE>]]) -> Self {
                     [<Array4x $dim>](value)
                 }
             }

             impl From<[<Array4x $dim>]> for [u32; [<ARRAY_4X $dim _WORD_SIZE>]] {
                 #[inline(never)]
                 fn from(value: [<Array4x $dim>]) -> Self {
                     value.0
                 }
             }

            #[inline(never)]
            #[allow(unused)]
            pub fn [<read_reg_4x $dim>]<TReg: ureg::ReadableReg<ReadVal = u32>, TMmio: ureg::Mmio>(
                reg_array: ureg::Array<[<ARRAY_4X $dim _WORD_SIZE>], ureg::RegRef<TReg, TMmio>>,
            ) -> [<Array4x $dim>] {
                let mut result = [0u32; [<ARRAY_4X $dim _WORD_SIZE>]];
                for i in 0..[<ARRAY_4X $dim _WORD_SIZE>] {
                    result[i] = reg_array.at(i).read();
                }
                result.into()
            }

            #[inline(never)]
            #[allow(unused)]
            pub fn [<write_reg_4x $dim>]<
                TReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = u32>,
                TMmio: ureg::Mmio,
            >(
                reg_array: ureg::Array<[<ARRAY_4X $dim _WORD_SIZE>], ureg::RegRef<TReg, TMmio>>,
                src: &[<Array4x $dim>],
            ) {
                for i in 0..[<ARRAY_4X $dim _WORD_SIZE>] {
                    reg_array.at(i).write(|_| {
                        src.0[i]
                    });
                }
            }
        }
    };
}

array4!(4);
array4!(8);
array4!(12);
array4!(16);
array4!(32);

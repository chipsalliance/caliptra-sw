// Licensed under the Apache-2.0 license

// TODO: These names need to make it clearer what they're actually doing. It's
// swapping the bytes of every 4-byte chunk, regardless of the element type.
pub trait EndianessTransform {
    fn change_endianess(&mut self);
    fn to_big_endian(&mut self);
    fn to_little_endian(&mut self);
}

impl EndianessTransform for [u8] {
    fn change_endianess(&mut self) {
        for idx in (0..self.len()).step_by(4) {
            self.swap(idx, idx + 3);
            self.swap(idx + 1, idx + 2);
        }
    }

    fn to_big_endian(&mut self) {
        self.change_endianess();
    }

    fn to_little_endian(&mut self) {
        self.change_endianess();
    }
}

impl EndianessTransform for [u32] {
    fn change_endianess(&mut self) {
        for val in self.iter_mut() {
            *val = val.swap_bytes();
        }
    }

    fn to_big_endian(&mut self) {
        self.change_endianess();
    }

    fn to_little_endian(&mut self) {
        self.change_endianess();
    }
}

impl EndianessTransform for [u64] {
    fn change_endianess(&mut self) {
        for val in self.iter_mut() {
            let msd_be = ((*val >> 32) as u32).swap_bytes();
            let lsd_be = ((*val & 0xFFFFFFFF) as u32).swap_bytes();
            *val = ((msd_be as u64) << 32) | lsd_be as u64;
        }
    }

    fn to_big_endian(&mut self) {
        self.change_endianess();
    }

    fn to_little_endian(&mut self) {
        self.change_endianess();
    }
}

#[cfg(test)]
mod test {
    use crate::EndianessTransform;

    #[test]
    fn test_change_endianness_u8() {
        let mut val = [0x11_u8, 0x22, 0x33, 0x44, 0x99, 0xaa, 0xbb, 0xcc];
        val.change_endianess();
        assert_eq!([0x44, 0x33, 0x22, 0x11, 0xcc, 0xbb, 0xaa, 0x99], val);
    }

    #[test]
    fn test_change_endianness_u32() {
        let mut val = [0x1122_3344_u32, 0x99aa_bbcc];
        val.change_endianess();
        assert_eq!([0x4433_2211, 0xccbb_aa99], val);
    }

    #[test]
    fn test_change_endianness_u64() {
        let mut val = [0x1122_3344_5566_7788_u64, 0x99aa_bbcc_ddee_ff00];
        val.change_endianess();
        assert_eq!([0x4433_2211_8877_6655, 0xccbb_aa99_00ff_eedd], val);
    }
}

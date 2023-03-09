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
            let mut val = self[idx];
            self[idx] = self[idx + 3];
            self[idx + 3] = val;
            val = self[idx + 1];
            self[idx + 1] = self[idx + 2];
            self[idx + 2] = val;
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
        for idx in 0..self.len() {
            let val = (self[idx] << 24)
                | ((self[idx] << 8) & 0x00ff0000)
                | ((self[idx] >> 8) & 0x0000ff00)
                | ((self[idx] >> 24) & 0x000000ff);
            self[idx] = val;
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
        for idx in 0..self.len() {
            let msd = (self[idx] >> 32) as u32;
            let lsd = (self[idx] & 0xFFFFFFFF) as u32;

            let msd_be = (msd << 24)
                | ((msd << 8) & 0x00FF0000)
                | ((msd >> 8) & 0x0000FF00)
                | ((msd >> 24) & 0x000000FF);

            let lsd_be = (lsd << 24)
                | ((lsd << 8) & 0x00FF0000)
                | ((lsd >> 8) & 0x0000FF00)
                | ((lsd >> 24) & 0x000000FF);

            self[idx] = ((msd_be as u64) << 32) | lsd_be as u64;
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

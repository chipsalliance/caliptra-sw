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

/*++

Licensed under the Apache-2.0 license.

File Name:

    slice.rs

Abstract:

    File contains helper API for rust slices

--*/

use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};

pub(crate) trait CopyFromByteSlice {
    fn copy_from_byte_slice(&self, buf: &[u8]);
}

impl CopyFromByteSlice for [WriteOnly<u32>] {
    fn copy_from_byte_slice(&self, buf: &[u8]) {
        for idx in (0..buf.len()).step_by(4) {
            let block_part = buf[idx] as u32
                | ((buf[idx + 1] as u32) << 8)
                | ((buf[idx + 2] as u32) << 16)
                | ((buf[idx + 3] as u32) << 24);
            self[idx >> 2].set(block_part);
        }
    }
}

impl CopyFromByteSlice for [ReadWrite<u32>] {
    fn copy_from_byte_slice(&self, buf: &[u8]) {
        for idx in (0..buf.len()).step_by(4) {
            let block_part = buf[idx] as u32
                | ((buf[idx + 1] as u32) << 8)
                | ((buf[idx + 2] as u32) << 16)
                | ((buf[idx + 3] as u32) << 24);
            self[idx >> 2].set(block_part);
        }
    }
}

pub(crate) trait CopyFromReadOnlyRegisterArray {
    fn copy_from_ro_reg(&mut self, reg: &[ReadOnly<u32>]);
}

impl CopyFromReadOnlyRegisterArray for [u8] {
    fn copy_from_ro_reg(&mut self, reg: &[ReadOnly<u32>]) {
        for idx in (0..self.len()).step_by(4) {
            let part = reg[idx >> 2].get();
            self[idx] = (part & 0xFF) as u8;
            self[idx + 1] = ((part >> 8) & 0xFF) as u8;
            self[idx + 2] = ((part >> 16) & 0xFF) as u8;
            self[idx + 3] = ((part >> 24) & 0xFF) as u8;
        }
    }
}

pub(crate) trait CopyFromReadWriteRegisterArray {
    fn copy_from_rw_reg(&mut self, reg: &[ReadWrite<u32>]);
}

impl CopyFromReadWriteRegisterArray for [u8] {
    fn copy_from_rw_reg(&mut self, reg: &[ReadWrite<u32>]) {
        for idx in (0..self.len()).step_by(4) {
            let part = reg[idx >> 2].get();
            self[idx] = (part & 0xFF) as u8;
            self[idx + 1] = ((part >> 8) & 0xFF) as u8;
            self[idx + 2] = ((part >> 16) & 0xFF) as u8;
            self[idx + 3] = ((part >> 24) & 0xFF) as u8;
        }
    }
}

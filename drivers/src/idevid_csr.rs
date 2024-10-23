// Licensed under the Apache-2.0 license

use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

use crate::memory_layout;

pub const MAX_CSR_SIZE: usize = 512;

#[derive(FromBytes, AsBytes, Zeroize)]
#[repr(C)]
pub struct IDevIDCsr {
    pub csr: [u8; MAX_CSR_SIZE],
    pub csr_len: u32,
}

impl Default for IDevIDCsr {
    fn default() -> Self {
        Self {
            csr: [0; MAX_CSR_SIZE],
            csr_len: 0,
        }
    }
}

impl IDevIDCsr {
    /// Get the CSR buffer
    pub fn get(&self) -> Option<&[u8]> {
        self.csr.get(..self.csr_len as usize)
    }
}

const _: () = assert!(size_of::<IDevIDCsr>() < memory_layout::IDEVID_CSR_SIZE as usize);

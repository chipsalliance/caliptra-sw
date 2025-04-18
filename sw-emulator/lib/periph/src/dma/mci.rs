/*++

Licensed under the Apache-2.0 license.

File Name:

    mci.rs

Abstract:

    File contains implementation of MCI

--*/

use bitfield::size_of;
use caliptra_emu_derive::Bus;
use sha2::{Digest, Sha384};

const SS_MANUF_DBG_UNLOCK_FUSE_SIZE: usize = 48;
const SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES: usize = 8;

#[derive(Bus)]
pub struct Mci {
    #[register(offset = 0x24)]
    flow_status: u32,
    #[register_array(offset = 0xa00)]
    fuses: [u32; SS_MANUF_DBG_UNLOCK_FUSE_SIZE / size_of::<u32>()
        * SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES],
}

impl Mci {
    pub const SS_MANUF_DBG_UNLOCK_FUSE_OFFSET: usize = 0xa00;
    pub const SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES: usize = SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES;

    pub fn new(key_pairs: Vec<(&[u8; 96], &[u8; 2592])>) -> Self {
        Self {
            flow_status: 0,
            fuses: {
                let mut fuses = [0; SS_MANUF_DBG_UNLOCK_FUSE_SIZE / size_of::<u32>()
                    * SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES];
                key_pairs.iter().enumerate().for_each(|(i, (ecc, mldsa))| {
                    // Create a single hasher for the concatenated keys
                    let mut hasher = Sha384::new();
                    hasher.update(ecc);
                    hasher.update(mldsa);
                    let hash = hasher.finalize();

                    // Copy hash into fuses array (64 bytes / 16 u32s)
                    let base_idx = i * (SS_MANUF_DBG_UNLOCK_FUSE_SIZE / size_of::<u32>());
                    hash.chunks(4).enumerate().for_each(|(j, chunk)| {
                        // Program the hash in hardware format i.e. little endian.
                        let value = u32::from_be_bytes(chunk.try_into().unwrap());
                        fuses[base_idx + j] = value;
                    });
                });
                fuses
            },
        }
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    stash_measurement.rs

Abstract:

    File contains APIs for accessing stash measurment registers via SoC interface

--*/

use crate::soc_ifc::SocIfc;
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::{FromBytes, Immutable, IntoBytes};

impl SocIfc {
    pub fn stash_measurement_iter(
        &self,
    ) -> CaliptraResult<impl Iterator<Item = CaliptraResult<StashMeasurementData>>> {
        let status = self.soc_ifc.regs().stash_bank_status().read();
        let end_stash = status.end_stash();
        let slot_locked = status.slot_locked();

        // SoC populated and locked slots but failed to assert end-of-stash.
        if !end_stash && slot_locked != 0 {
            return Err(CaliptraError::RUNTIME_STASH_MEASUREMENT_BANK_INVALID_STATUS);
        }

        // Check if measurements are populated sequentially.
        if slot_locked.trailing_ones() + slot_locked.leading_zeros() != u32::BITS {
            return Err(CaliptraError::RUNTIME_STASH_MEASUREMENT_BANK_INVALID_STATUS);
        }

        Ok(StashMeasurementSlotIter {
            data: self.soc_ifc.regs().stash_bank_slot_data().read(),
            current_slot: 0,
            num_slots: slot_locked.trailing_ones() as usize,
        })
    }

    pub fn lock_stash_measurement_bank(&mut self) {
        self.soc_ifc
            .regs_mut()
            .stash_bank_cptra_lock()
            .write(|w| w.cptra_lock(true));
    }

    pub fn poll_end_stash(&self) -> CaliptraResult<()> {
        while !self.soc_ifc.regs().stash_bank_status().read().end_stash() {}
        Ok(())
    }
}

#[repr(C, packed)]
#[derive(Immutable, FromBytes, IntoBytes)]
pub struct StashMeasurementData {
    pub metadata: [u8; 4],
    pub measurement: [u8; 48],
    pub context: [u8; 48],
    pub svn: u32,
}

pub const DWORDS_PER_SLOT: usize =
    core::mem::size_of::<StashMeasurementData>() / core::mem::size_of::<u32>();

pub struct StashMeasurementSlotIter<const LEN: usize> {
    data: [u32; LEN],
    current_slot: usize,
    num_slots: usize,
}

impl<const LEN: usize> Iterator for StashMeasurementSlotIter<LEN> {
    type Item = CaliptraResult<StashMeasurementData>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_slot >= self.num_slots {
            return None;
        }

        let dword_offset = DWORDS_PER_SLOT * self.current_slot;
        self.current_slot += 1;

        let result = self
            .data
            .get(dword_offset..dword_offset + DWORDS_PER_SLOT)
            .map(|dwords| dwords.as_bytes())
            .ok_or(CaliptraError::RUNTIME_STASH_MEASUREMENT_SLOT_OUT_OF_BOUNDS)
            .and_then(|bytes| {
                StashMeasurementData::read_from_bytes(&bytes)
                    .map_err(|_| CaliptraError::RUNTIME_STASH_MEASUREMENT_SLOT_SIZE_ERROR)
            });

        Some(result)
    }
}

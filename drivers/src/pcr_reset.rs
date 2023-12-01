/*++
Licensed under the Apache-2.0 license.

File Name:

    pcr_reset.rs

Abstract:

    PCR reset counter.

--*/

use crate::pcr_bank::{PcrBank, PcrId};
use core::ops::{Index, IndexMut};
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

#[repr(C, align(4))]
#[derive(AsBytes, FromBytes, Zeroize)]
pub struct PcrResetCounter {
    counter: [u32; PcrBank::ALL_PCR_IDS.len()],
}

impl Default for PcrResetCounter {
    fn default() -> Self {
        PcrResetCounter {
            counter: [0; PcrBank::ALL_PCR_IDS.len()],
        }
    }
}

impl Index<PcrId> for PcrResetCounter {
    type Output = u32;

    fn index(&self, id: PcrId) -> &Self::Output {
        &self.counter[usize::from(id)]
    }
}

impl IndexMut<PcrId> for PcrResetCounter {
    fn index_mut(&mut self, id: PcrId) -> &mut Self::Output {
        &mut self.counter[usize::from(id)]
    }
}

impl PcrResetCounter {
    pub fn new() -> PcrResetCounter {
        PcrResetCounter::default()
    }

    /// Increment the selected reset counter.
    /// Returns `false` in case of a counter overflow
    pub fn increment(&mut self, id: PcrId) -> bool {
        let old_value = self[id];

        if let Some(new_value) = old_value.checked_add(1) {
            self[id] = new_value;

            true
        } else {
            false
        }
    }

    pub fn all_counters(&self) -> [u32; PcrBank::ALL_PCR_IDS.len()] {
        self.counter
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr_bank.rs

Abstract:

    File contains API for managing Platform Configuration Register (PCR) Bank.

--*/

use crate::{caliptra_err_def, Array4x12, CaliptraResult};
use caliptra_registers::kv;

/// PCR Identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrId {
    /// PCR Id 0
    PcrId0 = 0,

    /// PCR Id 1
    PcrId1 = 1,

    /// PCR Id 2
    PcrId2 = 2,

    /// PCR Id 3
    PcrId3 = 3,

    /// PCR Id 4
    PcrId4 = 4,

    /// PCR Id 5
    PcrId5 = 5,

    /// PCR Id 6
    PcrId6 = 6,

    /// PCR Id 7
    PcrId7 = 7,
}

impl From<PcrId> for u32 {
    /// Converts to this type from the input type.
    fn from(id: PcrId) -> Self {
        id as Self
    }
}

impl From<PcrId> for usize {
    /// Converts to this type from the input type.
    fn from(id: PcrId) -> Self {
        id as Self
    }
}

caliptra_err_def! {
    PcrBank,
    PcrBankErr
    {
        // Erase failed due to write lock st
        EraseWriteLockSetFailure = 0x01,
    }
}

/// Platform Configuration Register (PCR) Bank
#[derive(Default)]
pub struct PcrBank {}

impl PcrBank {
    /// Erase all the pcrs in the pcr vault
    ///
    /// Note: The pcrs that have "use" lock set will not be erased
    pub fn erase_all_pcrs(&mut self) {
        const PCR_IDS: [PcrId; 8] = [
            PcrId::PcrId0,
            PcrId::PcrId1,
            PcrId::PcrId2,
            PcrId::PcrId3,
            PcrId::PcrId4,
            PcrId::PcrId5,
            PcrId::PcrId6,
            PcrId::PcrId7,
        ];

        let kv = kv::RegisterBlock::kv_reg();
        for id in PCR_IDS {
            if !self.pcr_write_lock(id) {
                kv.pcr_ctrl().at(id.into()).write(|w| w.clear(true));
            }
        }
    }

    /// Erase specified pcr
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID to erase
    pub fn erase_pcr(&mut self, id: PcrId) -> CaliptraResult<()> {
        if self.pcr_write_lock(id) {
            raise_err!(EraseWriteLockSetFailure)
        }

        let kv = kv::RegisterBlock::kv_reg();
        kv.pcr_ctrl().at(id.into()).write(|w| w.clear(true));
        Ok(())
    }

    /// Retrieve the write lock status for a PCR
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID
    ///
    /// # Returns
    ///
    /// * `true` - If the PCR is write locked
    /// * `false` - If the PCR is not write locked
    pub fn pcr_write_lock(&self, id: PcrId) -> bool {
        let kv = kv::RegisterBlock::kv_reg();
        kv.pcr_ctrl().at(id.into()).read().lock_wr()
    }

    /// Set the write lock for a PCR
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID
    pub fn set_pcr_write_lock(&mut self, id: PcrId) {
        let kv = kv::RegisterBlock::kv_reg();
        kv.pcr_ctrl().at(id.into()).write(|w| w.lock_wr(true))
    }

    /// Clear the write lock for a PCR
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID
    pub fn clear_pcr_write_lock(&mut self, id: PcrId) {
        let kv = kv::RegisterBlock::kv_reg();
        kv.pcr_ctrl().at(id.into()).write(|w| w.lock_wr(false))
    }

    /// Read the value of a PCR
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID
    ///
    /// # Returns
    ///
    /// * `Array4x12` - PCR Value
    pub fn read_pcr(&self, id: PcrId) -> Array4x12 {
        let kv = kv::RegisterBlock::kv_reg();

        let mut result = Array4x12::default();
        for i in 0..result.0.len() {
            result.0[i] = kv.pcr_entry().at(id.into()).at(i).read();
        }

        result
    }

    /// Write value to a PCR
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID
    /// * `val` - Value to write
    pub fn write_pcr(&self, id: PcrId, val: &Array4x12) -> CaliptraResult<()> {
        if self.pcr_write_lock(id) {
            raise_err!(EraseWriteLockSetFailure)
        }

        let kv = kv::RegisterBlock::kv_reg();
        for i in 0..val.0.len() {
            kv.pcr_entry().at(id.into()).at(i).write(|_| val.0[i])
        }

        Ok(())
    }
}

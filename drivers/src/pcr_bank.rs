/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr_bank.rs

Abstract:

    File contains API for managing Platform Configuration Register (PCR) Bank.

--*/

use crate::{Array4x12, CaliptraError, CaliptraResult, Sha384};
use caliptra_registers::pv::PvReg;

/// PCR Identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrId {
    PcrId0 = 0,
    PcrId1 = 1,
    PcrId2 = 2,
    PcrId3 = 3,
    PcrId4 = 4,
    PcrId5 = 5,
    PcrId6 = 6,
    PcrId7 = 7,
    PcrId8 = 8,
    PcrId9 = 9,
    PcrId10 = 10,
    PcrId11 = 11,
    PcrId12 = 12,
    PcrId13 = 13,
    PcrId14 = 14,
    PcrId15 = 15,
    PcrId16 = 16,
    PcrId17 = 17,
    PcrId18 = 18,
    PcrId19 = 19,
    PcrId20 = 20,
    PcrId21 = 21,
    PcrId22 = 22,
    PcrId23 = 23,
    PcrId24 = 24,
    PcrId25 = 25,
    PcrId26 = 26,
    PcrId27 = 27,
    PcrId28 = 28,
    PcrId29 = 29,
    PcrId30 = 30,
    PcrId31 = 31,
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

/// Platform Configuration Register (PCR) Bank
pub struct PcrBank {
    pv: PvReg,
}

impl PcrBank {
    pub fn new(pv: PvReg) -> Self {
        Self { pv }
    }
    /// Erase all the pcrs in the pcr vault
    ///
    /// Note: The pcrs that have "use" lock set will not be erased
    pub fn erase_all_pcrs(&mut self) {
        const PCR_IDS: [PcrId; 32] = [
            PcrId::PcrId0,
            PcrId::PcrId1,
            PcrId::PcrId2,
            PcrId::PcrId3,
            PcrId::PcrId4,
            PcrId::PcrId5,
            PcrId::PcrId6,
            PcrId::PcrId7,
            PcrId::PcrId8,
            PcrId::PcrId9,
            PcrId::PcrId10,
            PcrId::PcrId11,
            PcrId::PcrId12,
            PcrId::PcrId13,
            PcrId::PcrId14,
            PcrId::PcrId15,
            PcrId::PcrId16,
            PcrId::PcrId17,
            PcrId::PcrId18,
            PcrId::PcrId19,
            PcrId::PcrId20,
            PcrId::PcrId21,
            PcrId::PcrId22,
            PcrId::PcrId23,
            PcrId::PcrId24,
            PcrId::PcrId25,
            PcrId::PcrId26,
            PcrId::PcrId27,
            PcrId::PcrId28,
            PcrId::PcrId29,
            PcrId::PcrId30,
            PcrId::PcrId31,
        ];

        for id in PCR_IDS {
            if !self.pcr_lock(id) {
                let pv = self.pv.regs_mut();
                pv.pcr_ctrl().at(id.into()).write(|w| w.clear(true));
            }
        }
    }

    /// Erase specified pcr
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID to erase
    pub fn erase_pcr(&mut self, id: PcrId) -> CaliptraResult<()> {
        if self.pcr_lock(id) {
            return Err(CaliptraError::DRIVER_PCR_BANK_ERASE_WRITE_LOCK_SET_FAILURE);
        }

        let pv = self.pv.regs_mut();
        pv.pcr_ctrl().at(id.into()).write(|w| w.clear(true));
        Ok(())
    }

    /// Retrieve the 'lock for clear' status for a PCR
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID
    ///
    /// # Returns
    ///
    /// * `true` - If the PCR is locked for clear
    /// * `false` - If the PCR is not locked for clear
    pub fn pcr_lock(&self, id: PcrId) -> bool {
        let pv = self.pv.regs();
        pv.pcr_ctrl().at(id.into()).read().lock()
    }

    /// Set the 'lock for clear' setting for a PCR
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID
    pub fn set_pcr_lock(&mut self, id: PcrId) {
        let pv = self.pv.regs_mut();
        pv.pcr_ctrl().at(id.into()).write(|w| w.lock(true))
    }

    /// Clear the 'lock for clear' setting for a PCR
    ///
    /// # Arguments
    ///
    /// * `id` - PCR ID
    pub fn clear_pcr_lock(&mut self, id: PcrId) {
        let pv = self.pv.regs_mut();
        pv.pcr_ctrl().at(id.into()).write(|w| w.lock(false))
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
    #[inline(never)]
    pub fn read_pcr(&self, id: PcrId) -> Array4x12 {
        let pv = self.pv.regs();

        let mut result = Array4x12::default();
        for i in 0..result.0.len() {
            result.0[i] = pv.pcr_entry().at(id.into()).at(i).read();
        }

        result
    }

    /// Extend the PCR with specified data
    ///
    /// # Arguments
    ///
    /// * `id`   - PCR ID
    /// * `sha`  - SHA2-384 Engine
    /// * `data` - Data to extend
    ///
    pub fn extend_pcr(&self, id: PcrId, sha: &mut Sha384, data: &[u8]) -> CaliptraResult<()> {
        sha.pcr_extend(id, data)
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    handoff.rs

Abstract:

    File contains helper functions that extract values from the FirmwareHandoffTable and DataVault.

--*/

use caliptra_common::DataStore::{DataVaultNonSticky4, DataVaultSticky4, KeyVaultSlot};
use caliptra_drivers::{hand_off::DataStore, DataVault, FirmwareHandoffTable, KeyId};
use caliptra_error::{CaliptraError, CaliptraResult};

pub struct RtHandoff<'a> {
    pub data_vault: &'a DataVault,
    pub fht: &'a FirmwareHandoffTable,
}

impl RtHandoff<'_> {
    /// Retrieve the value from a DataStore
    ///
    /// # Arguments
    ///
    /// * `ds` - DataStore
    ///
    /// # Returns
    ///
    /// * `u32` - The value in `ds`
    fn read_from_ds(&self, ds: DataStore) -> CaliptraResult<u32> {
        match ds {
            DataVaultNonSticky4(dv_entry) => Ok(self.data_vault.read_warm_reset_entry4(dv_entry)),
            DataVaultSticky4(dv_entry) => Ok(self.data_vault.read_cold_reset_entry4(dv_entry)),
            _ => Err(CaliptraError::RUNTIME_INTERNAL),
        }
    }

    fn read_as_kv(&self, ds: DataStore) -> CaliptraResult<KeyId> {
        match ds {
            KeyVaultSlot(key_id) => Ok(key_id),
            _ => Err(CaliptraError::RUNTIME_INTERNAL),
        }
    }

    /// Retrieve runtime SVN.
    pub fn rt_svn(&self) -> CaliptraResult<u32> {
        self.read_from_ds(self.fht.rt_svn_dv_hdl.try_into()?)
            .map_err(|_| CaliptraError::RUNTIME_RT_SVN_HANDOFF_FAILED)
    }

    /// Retrieve runtime minimum SVN.
    pub fn rt_min_svn(&self) -> CaliptraResult<u32> {
        self.read_from_ds(self.fht.rt_min_svn_dv_hdl.try_into()?)
            .map_err(|_| CaliptraError::RUNTIME_RT_MIN_SVN_HANDOFF_FAILED)
    }

    /// Retrieve FMC SVN.
    pub fn fmc_svn(&self) -> CaliptraResult<u32> {
        self.read_from_ds(self.fht.fmc_svn_dv_hdl.try_into()?)
            .map_err(|_| CaliptraError::RUNTIME_FMC_SVN_HANDOFF_FAILED)
    }

    /// Retrieve the RT FW hash chain.
    pub fn rt_hash_chain(&self) -> CaliptraResult<KeyId> {
        self.read_as_kv(self.fht.rt_hash_chain_kv_hdl.try_into()?)
            .map_err(|_| CaliptraError::RUNTIME_HASH_CHAIN_HANDOFF_FAILED)
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    handoff.rs

Abstract:

    File contains helper functions that extract values from the FirmwareHandoffTable and DataVault.

--*/

use caliptra_common::DataStore::KeyVaultSlot;
use caliptra_drivers::{hand_off::DataStore, DataVault, FirmwareHandoffTable, KeyId};
use caliptra_error::{CaliptraError, CaliptraResult};

pub struct RtHandoff<'a> {
    pub data_vault: &'a DataVault,
    pub fht: &'a FirmwareHandoffTable,
}

impl RtHandoff<'_> {
    fn read_as_kv(&self, ds: DataStore) -> CaliptraResult<KeyId> {
        match ds {
            KeyVaultSlot(key_id) => Ok(key_id),
            _ => Err(CaliptraError::RUNTIME_INTERNAL),
        }
    }

    /// Retrieve runtime SVN.
    pub fn rt_svn(&self) -> u32 {
        self.data_vault.rt_svn()
    }

    /// Retrieve runtime minimum SVN.
    pub fn rt_min_svn(&self) -> u32 {
        self.data_vault.rt_min_svn()
    }

    /// Retrieve FMC SVN.
    pub fn fmc_svn(&self) -> u32 {
        self.data_vault.fmc_svn()
    }

    /// Retrieve the RT FW hash chain.
    pub fn rt_hash_chain(&self) -> CaliptraResult<KeyId> {
        self.read_as_kv(self.fht.rt_hash_chain_kv_hdl.try_into()?)
            .map_err(|_| CaliptraError::RUNTIME_HASH_CHAIN_HANDOFF_FAILED)
    }
}

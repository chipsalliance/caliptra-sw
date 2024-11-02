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

    /// Retrieve firmware SVN.
    pub fn fw_svn(&self) -> u32 {
        self.data_vault.fw_svn()
    }

    /// Retrieve firmware minimum SVN.
    pub fn fw_min_svn(&self) -> u32 {
        self.data_vault.fw_min_svn()
    }

    /// Retrieve cold-boot firmware SVN.
    pub fn cold_boot_fw_svn(&self) -> u32 {
        self.data_vault.cold_boot_fw_svn()
    }

    /// Retrieve the FW hash chain.
    pub fn fw_hash_chain(&self) -> CaliptraResult<KeyId> {
        self.read_as_kv(self.fht.fw_hash_chain_kv_hdl.try_into()?)
            .map_err(|_| CaliptraError::RUNTIME_HASH_CHAIN_HANDOFF_FAILED)
    }
}

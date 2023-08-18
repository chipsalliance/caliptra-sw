// Licensed under the Apache-2.0 license

use caliptra_common::DataStore::{DataVaultNonSticky4, DataVaultSticky4};
use caliptra_drivers::{hand_off::DataStore, DataVault, FirmwareHandoffTable};
use caliptra_error::{CaliptraError, CaliptraResult};

pub struct RtHandoff<'a> {
    pub data_vault: &'a DataVault,
    pub fht: &'a FirmwareHandoffTable,
}

impl RtHandoff<'_> {
    fn read_from_ds(&self, ds: DataStore) -> CaliptraResult<u32> {
        match ds {
            DataVaultNonSticky4(dv_entry) => Ok(self.data_vault.read_warm_reset_entry4(dv_entry)),
            DataVaultSticky4(dv_entry) => Ok(self.data_vault.read_cold_reset_entry4(dv_entry)),
            _ => Err(CaliptraError::RUNTIME_HANDOFF_INVALID_PARM),
        }
    }

    /// Retrieve runtime SVN.
    pub fn rt_svn(&self) -> CaliptraResult<u32> {
        self.read_from_ds(self.fht.rt_svn_dv_hdl.try_into()?)
    }

    /// Retrieve runtime minimum SVN.
    pub fn rt_min_svn(&self) -> CaliptraResult<u32> {
        self.read_from_ds(self.fht.rt_min_svn_dv_hdl.try_into()?)
    }

    /// Retrieve FMC SVN.
    pub fn fmc_svn(&self) -> CaliptraResult<u32> {
        self.read_from_ds(self.fht.fmc_svn_dv_hdl.try_into()?)
    }
}

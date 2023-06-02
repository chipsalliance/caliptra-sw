/*++

Licensed under the Apache-2.0 license.

File Name:

    hand_off.rs

    Implements handoff behavior of FMC :
        - Retrieves FHT table from fixed address in DCCM.
        - Transfers control to the runtime firmware.
++*/

use crate::flow::dice::DiceOutput;
use crate::fmc_env::FmcEnv;
use caliptra_common::DataStore::*;
use caliptra_common::{DataStore, FirmwareHandoffTable};
use caliptra_drivers::{Array4x12, KeyId};
use caliptra_error::CaliptraResult;

#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("transfer_control.S"));

struct IccmAddress(u32);
struct DccmAddress(u32);

struct MemoryRegion {
    start: u32,
    size: u32,
}

impl MemoryRegion {
    fn validate_address(&self, phys_addr: u32) -> bool {
        phys_addr >= self.start && phys_addr <= self.start + self.size
    }
}

impl IccmAddress {
    const ICCM_ORG: u32 = 0x40000000;
    const ICCM_SIZE: u32 = 128 << 10;
    const ICCM: MemoryRegion = MemoryRegion {
        start: Self::ICCM_ORG,
        size: Self::ICCM_SIZE,
    };

    /// Validate that the address is within the ICCM region.
    pub fn is_valid(&self) -> bool {
        Self::ICCM.validate_address(self.0)
    }
}

impl DccmAddress {
    const DCCM_ORG: u32 = 0x50000000;
    const DCCM_SIZE: u32 = 128 << 10;
    const DCCM: MemoryRegion = MemoryRegion {
        start: Self::DCCM_ORG,
        size: Self::DCCM_SIZE,
    };

    /// Validate that the address is within the ICCM region.
    pub fn is_valid(&self) -> bool {
        Self::DCCM.validate_address(self.0)
    }
}

pub struct HandOff {
    fht: FirmwareHandoffTable,
}

impl HandOff {
    /// Create a new `HandOff` from the FHT table.
    pub fn from_previous() -> Option<HandOff> {
        // try_load performs basic sanity check of the FHT (check FHT marker, valid indices, etc.)
        if let Some(fht) = FirmwareHandoffTable::try_load() {
            let me = Self { fht };

            return Some(me);
        }
        None
    }

    /// Retrieve FMC CDI
    pub fn fmc_cdi(&self) -> KeyId {
        let ds: DataStore = self.fht.fmc_cdi_kv_hdl.try_into().unwrap_or_else(|_| {
            caliptra_common::report_handoff_error_and_halt(
                "Invalid CDI DV handle",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            )
        });

        match ds {
            KeyVaultSlot(key_id) => key_id,
            _ => caliptra_common::report_handoff_error_and_halt(
                "Invalid KeySlot DV Entry",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            ),
        }
    }

    /// Retrieve FMC Alias Private Key
    pub fn fmc_priv_key(&self) -> KeyId {
        let ds: DataStore = self.fht.fmc_priv_key_kv_hdl.try_into().unwrap_or_else(|_| {
            caliptra_common::report_handoff_error_and_halt(
                "Invalid FMC ALias Private Key DV handle",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            )
        });

        match ds {
            KeyVaultSlot(key_id) => key_id,
            _ => caliptra_common::report_handoff_error_and_halt(
                "Invalid KeySlot DV Entry",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            ),
        }
    }

    /// Transfer control to the runtime firmware.
    pub fn to_rt(&self, env: &mut FmcEnv) -> ! {
        // Function is defined in start.S
        extern "C" {
            fn transfer_control(entry: u32) -> !;
        }
        // Retrieve runtime entry point
        let rt_entry = IccmAddress(self.rt_entry_point(env));

        if !rt_entry.is_valid() {
            caliptra_common::report_handoff_error_and_halt(
                "Invalid KeySlot DV Entry",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            );
        }
        // Exit FMC and jump to speicified entry point
        unsafe { transfer_control(rt_entry.0) }
    }

    /// Retrieve runtime TCI (digest)
    pub fn rt_tci(&self, env: &FmcEnv) -> Array4x12 {
        let ds: DataStore = self.fht.rt_tci_dv_hdl.try_into().unwrap_or_else(|_| {
            caliptra_common::report_handoff_error_and_halt(
                "Invalid TCI DV handle",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            )
        });

        // The data store is either a warm reset entry or a cold reset entry.
        match ds {
            DataVaultNonSticky48(dv_entry) => env.data_vault.read_warm_reset_entry48(dv_entry),
            DataVaultSticky48(dv_entry) => env.data_vault.read_cold_reset_entry48(dv_entry),
            _ => {
                crate::report_error(
                    caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
                );
            }
        }
    }

    /// Retrieve image manifest load address in DCCM
    pub fn image_manifest_address(&self, _env: &FmcEnv) -> u32 {
        if !DccmAddress(self.fht.manifest_load_addr).is_valid() {
            crate::report_error(caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into());
        }
        self.fht.manifest_load_addr
    }

    /// Retrieve the entry point of the runtime firmware.
    fn rt_entry_point(&self, env: &FmcEnv) -> u32 {
        let ds: DataStore = self
            .fht
            .rt_fw_entry_point_hdl
            .try_into()
            .unwrap_or_else(|_| {
                caliptra_common::report_handoff_error_and_halt(
                    "Invalid runtime entry point DV handle",
                    caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
                )
            });
        // The data store is either a warm reset entry or a cold reset entry.
        match ds {
            DataVaultNonSticky4(dv_entry) => env.data_vault.read_warm_reset_entry4(dv_entry),
            DataVaultSticky4(dv_entry) => env.data_vault.read_cold_reset_entry4(dv_entry),
            _ => {
                crate::report_error(
                    caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
                );
            }
        }
    }

    /// Update HandOff Table with RT Parameters
    pub fn update(&self, _out: DiceOutput) -> CaliptraResult<()> {
        // Todo in a different PR : Issue #84
        // update fht.rt_cdi_kv_hdl
        // update fht.rt_priv_key_kv_hdl
        // update fht.rt_pub_key_y_dv_hdl
        // update fht.rt_cert_sig_r_dv_hdl
        // update fht.rt_cert_sig_r_dv_hdl
        //
        // Invalidate fmc_cdi_kv_hdl
        // Invalidate fmc_priv_key_kv_hdl
        Ok(())
    }
}

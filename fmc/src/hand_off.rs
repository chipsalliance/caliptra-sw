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
use caliptra_common::{DataStore, FirmwareHandoffTable, HandOffDataHandle, Vault};
use caliptra_drivers::{memory_layout, Array4x12, Ecc384Signature, KeyId};
use caliptra_drivers::{Ecc384PubKey, Ecc384Scalar};
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
    const ICCM: MemoryRegion = MemoryRegion {
        start: memory_layout::ICCM_ORG,
        size: memory_layout::ICCM_SIZE,
    };

    /// Validate that the address is within the ICCM region.
    pub fn is_valid(&self) -> bool {
        Self::ICCM.validate_address(self.0)
    }
}

impl DccmAddress {
    const DCCM: MemoryRegion = MemoryRegion {
        start: memory_layout::DCCM_ORG,
        size: memory_layout::DCCM_SIZE,
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
    pub fn from_previous(env: &mut FmcEnv) -> Option<HandOff> {
        let fht = &env.persistent_data.get().fht;
        // Perform basic sanity check of the FHT (check FHT marker, valid indices, etc.)
        if !fht.is_valid() {
            return None;
        }
        env.pcr_bank.log_index = fht.pcr_log_index as usize;
        Some(Self { fht: fht.clone() })
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
            KeyVaultSlot(key_id) => {
                caliptra_common::cprintln!("Handoff : FMC CDI: {:?}", key_id as u8);
                key_id
            }
            _ => caliptra_common::report_handoff_error_and_halt(
                "Invalid KeySlot DV Entry",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            ),
        }
    }

    fn fmc_pub_key_x(&self, env: &FmcEnv) -> Ecc384Scalar {
        let ds: DataStore = self
            .fht
            .fmc_pub_key_x_dv_hdl
            .try_into()
            .unwrap_or_else(|_| {
                caliptra_common::report_handoff_error_and_halt(
                    "Invalid FMC ALias Public Key X DV handle",
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

    fn fmc_pub_key_y(&self, env: &FmcEnv) -> Ecc384Scalar {
        let ds: DataStore = self
            .fht
            .fmc_pub_key_y_dv_hdl
            .try_into()
            .unwrap_or_else(|_| {
                caliptra_common::report_handoff_error_and_halt(
                    "Invalid FMC ALias Public Key Y DV handle",
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

    /// Get the fmc public key.
    ///
    /// # Returns
    /// * fmc public key
    ///
    pub fn fmc_pub_key(&self, env: &FmcEnv) -> Ecc384PubKey {
        Ecc384PubKey {
            x: self.fmc_pub_key_x(env),
            y: self.fmc_pub_key_y(env),
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
            KeyVaultSlot(key_id) => {
                caliptra_common::cprintln!("FMC Alias Private Key: {:?}", u32::from(key_id));
                key_id
            }
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

        env.persistent_data.get_mut().fht = self.fht.clone();

        // Retrieve runtime entry point
        let rt_entry = IccmAddress(self.rt_entry_point(env));

        if !rt_entry.is_valid() {
            caliptra_common::report_handoff_error_and_halt(
                "Invalid RT Entry Point",
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

    /// Retrieve runtime SVN.
    pub fn rt_svn(&self, env: &FmcEnv) -> u32 {
        let ds: DataStore = self.fht.rt_svn_dv_hdl.try_into().unwrap_or_else(|_| {
            caliptra_common::report_handoff_error_and_halt(
                "Invalid RT SVN handle",
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

    /// Retrieve runtime minimum SVN.
    pub fn rt_min_svn(&self, env: &FmcEnv) -> u32 {
        let ds: DataStore = self.fht.rt_min_svn_dv_hdl.try_into().unwrap_or_else(|_| {
            caliptra_common::report_handoff_error_and_halt(
                "Invalid RT Min SVN handle",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            )
        });

        // The data store must be a warm reset entry.
        match ds {
            DataVaultNonSticky4(dv_entry) => env.data_vault.read_warm_reset_entry4(dv_entry),
            _ => {
                crate::report_error(
                    caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
                );
            }
        }
    }

    pub fn set_and_lock_rt_min_svn(&self, env: &mut FmcEnv, min_svn: u32) -> CaliptraResult<()> {
        let ds: DataStore = self.fht.rt_min_svn_dv_hdl.try_into().unwrap_or_else(|_| {
            caliptra_common::report_handoff_error_and_halt(
                "Invalid RT Min SVN handle",
                caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
            )
        });

        // The data store must be a warm reset entry.
        match ds {
            DataVaultNonSticky4(dv_entry) => {
                env.data_vault.write_warm_reset_entry4(dv_entry, min_svn);
                env.data_vault.lock_warm_reset_entry4(dv_entry);
                Ok(())
            }
            _ => {
                crate::report_error(
                    caliptra_error::CaliptraError::FMC_HANDOFF_INVALID_PARAM.into(),
                );
            }
        }
    }

    /// Store runtime Dice Signature
    pub fn set_rt_dice_signature(&mut self, sig: &Ecc384Signature) {
        self.fht.rt_dice_sign = *sig;
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

    /// The FMC CDI is stored in a 32-bit DataVault sticky register.
    fn rt_cdi_store(rt_cdi: KeyId) -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | rt_cdi as u32)
    }

    fn rt_priv_key_store(rt_priv_key: KeyId) -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | rt_priv_key as u32)
    }

    /// Update HandOff Table with RT Parameters
    pub fn update(&mut self, out: DiceOutput) -> CaliptraResult<()> {
        // update fht.rt_cdi_kv_hdl
        self.fht.rt_cdi_kv_hdl = Self::rt_cdi_store(out.cdi);
        self.fht.rt_priv_key_kv_hdl = Self::rt_priv_key_store(out.subj_key_pair.priv_key);
        self.fht.rt_dice_pub_key = out.subj_key_pair.pub_key;
        Ok(())
    }
    /// Check if the HandOff Table is valid by ensuring RTAlias CDI and private key handles
    /// are valid.
    pub fn is_valid(&self) -> bool {
        self.fht.rt_cdi_kv_hdl.is_valid() && self.fht.rt_priv_key_kv_hdl.is_valid()
    }
}

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
use caliptra_error::{CaliptraError, CaliptraResult};

#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("transfer_control.S"));

pub struct IccmBounds {}
impl caliptra_drivers::MemBounds for IccmBounds {
    const ORG: usize = memory_layout::ICCM_ORG as usize;
    const SIZE: usize = memory_layout::ICCM_SIZE as usize;
    const ERROR: CaliptraError = CaliptraError::ADDRESS_NOT_IN_ICCM;
}

pub type IccmAddr<T> = caliptra_drivers::BoundedAddr<T, IccmBounds>;

pub struct HandOff {}

impl HandOff {
    fn fht(env: &FmcEnv) -> &FirmwareHandoffTable {
        &env.persistent_data.get().fht
    }

    fn fht_mut(env: &mut FmcEnv) -> &mut FirmwareHandoffTable {
        &mut env.persistent_data.get_mut().fht
    }

    /// Retrieve FMC CDI
    pub fn fmc_cdi(env: &FmcEnv) -> KeyId {
        let ds: DataStore = Self::fht(env)
            .fmc_cdi_kv_hdl
            .try_into()
            .unwrap_or_else(|_| {
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

    fn fmc_pub_key_x(env: &FmcEnv) -> Ecc384Scalar {
        let ds: DataStore = Self::fht(env)
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

    fn fmc_pub_key_y(env: &FmcEnv) -> Ecc384Scalar {
        let ds: DataStore = Self::fht(env)
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
    pub fn fmc_pub_key(env: &FmcEnv) -> Ecc384PubKey {
        Ecc384PubKey {
            x: Self::fmc_pub_key_x(env),
            y: Self::fmc_pub_key_y(env),
        }
    }

    /// Retrieve FMC Alias Private Key
    pub fn fmc_priv_key(env: &FmcEnv) -> KeyId {
        let ds: DataStore = Self::fht(env)
            .fmc_priv_key_kv_hdl
            .try_into()
            .unwrap_or_else(|_| {
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
    pub fn to_rt(env: &FmcEnv) -> ! {
        // Function is defined in start.S
        extern "C" {
            fn transfer_control(entry: u32) -> !;
        }

        let rt_entry_point = Self::rt_entry_point(env);

        match IccmAddr::<u32>::validate_addr(rt_entry_point) {
            Ok(_) => unsafe { transfer_control(rt_entry_point) },
            Err(e) => {
                caliptra_common::report_handoff_error_and_halt("Invalid RT Entry Point", e.into())
            }
        }
    }

    /// Retrieve runtime TCI (digest)
    pub fn rt_tci(env: &FmcEnv) -> Array4x12 {
        let ds: DataStore = Self::fht(env).rt_tci_dv_hdl.try_into().unwrap_or_else(|_| {
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
    pub fn rt_svn(env: &FmcEnv) -> u32 {
        let ds: DataStore = Self::fht(env).rt_svn_dv_hdl.try_into().unwrap_or_else(|_| {
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
    pub fn rt_min_svn(env: &FmcEnv) -> u32 {
        let ds: DataStore = Self::fht(env)
            .rt_min_svn_dv_hdl
            .try_into()
            .unwrap_or_else(|_| {
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

    pub fn set_and_lock_rt_min_svn(env: &mut FmcEnv, min_svn: u32) -> CaliptraResult<()> {
        let ds: DataStore = Self::fht(env)
            .rt_min_svn_dv_hdl
            .try_into()
            .unwrap_or_else(|_| {
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
    pub fn set_rt_dice_signature(env: &mut FmcEnv, sig: &Ecc384Signature) {
        Self::fht_mut(env).rt_dice_sign = *sig;
    }

    pub fn set_rtalias_tbs_size(env: &mut FmcEnv, rtalias_tbs_size: usize) {
        Self::fht_mut(env).rtalias_tbs_size = rtalias_tbs_size as u16;
    }

    /// Retrieve the entry point of the runtime firmware.
    fn rt_entry_point(env: &FmcEnv) -> u32 {
        let ds: DataStore = Self::fht(env)
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
    pub fn update(env: &mut FmcEnv, out: DiceOutput) -> CaliptraResult<()> {
        // update fht.rt_cdi_kv_hdl
        Self::fht_mut(env).rt_cdi_kv_hdl = Self::rt_cdi_store(out.cdi);
        Self::fht_mut(env).rt_priv_key_kv_hdl = Self::rt_priv_key_store(out.subj_key_pair.priv_key);
        Self::fht_mut(env).rt_dice_pub_key = out.subj_key_pair.pub_key;
        Ok(())
    }

    /// Check if the HandOff Table is ready for RT by ensuring RTAlias CDI and
    /// private key handles are valid.
    pub fn is_ready_for_rt(env: &FmcEnv) -> CaliptraResult<()> {
        let fht = Self::fht(env);
        if fht.rt_cdi_kv_hdl.is_valid() && fht.rt_priv_key_kv_hdl.is_valid() {
            Ok(())
        } else {
            Err(CaliptraError::FMC_HANDOFF_NOT_READY_FOR_RT)
        }
    }
}

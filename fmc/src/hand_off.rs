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
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::{handle_fatal_error, DataStore::*};
use caliptra_common::{DataStore, FirmwareHandoffTable, HandOffDataHandle, Vault};
use caliptra_drivers::{cprintln, memory_layout, Array4x12, Ecc384Signature, KeyId};
use caliptra_drivers::{Ecc384PubKey, Mldsa87PubKey};
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
        let ds: DataStore =
            Self::fht(env)
                .fmc_cdi_kv_hdl
                .try_into()
                .unwrap_or_else(|e: CaliptraError| {
                    cprintln!("[fht] Invalid CDI KV handle");
                    handle_fatal_error(e.into())
                });

        match ds {
            KeyVaultSlot(key_id) => {
                cprintln!("[fht] Handoff : FMC CDI: {:?}", key_id as u8);
                key_id
            }
            _ => {
                cprintln!("[fht] Invalid KeySlot KV Entry");
                handle_fatal_error(CaliptraError::FMC_HANDOFF_INVALID_PARAM.into())
            }
        }
    }

    /// Get the fmc ECC public key.
    ///
    /// # Returns
    /// * fmc ECC public key
    ///
    pub fn fmc_ecc_pub_key(env: &FmcEnv) -> Ecc384PubKey {
        env.persistent_data.get().data_vault.fmc_ecc_pub_key()
    }

    /// Get the fmc MLDSA public key.
    ///
    /// # Returns
    /// * fmc MLDSA public key
    ///
    pub fn fmc_mldsa_pub_key(env: &FmcEnv) -> Mldsa87PubKey {
        env.persistent_data.get().data_vault.fmc_mldsa_pub_key()
    }

    /// Retrieve FMC Alias ECC Private Key
    pub fn fmc_ecc_priv_key(env: &FmcEnv) -> KeyId {
        let ds: DataStore = Self::fht(env)
            .fmc_ecc_priv_key_kv_hdl
            .try_into()
            .unwrap_or_else(|e: CaliptraError| {
                cprintln!("[fht] Invalid FMC Alias ECC Private Key KV handle");
                handle_fatal_error(e.into())
            });

        match ds {
            KeyVaultSlot(key_id) => {
                cprintln!("[fht] FMC Alias ECC Private Key: {:?}", u32::from(key_id));
                key_id
            }
            _ => {
                cprintln!("[fht] Invalid KeySlot DV Entry");
                handle_fatal_error(CaliptraError::FMC_HANDOFF_INVALID_PARAM.into())
            }
        }
    }

    /// Retrieve FMC Alias MLDSA KeyPair Seed KV Slot
    pub fn fmc_mldsa_keypair_seed_key(env: &FmcEnv) -> KeyId {
        let ds: DataStore = Self::fht(env)
            .fmc_mldsa_keypair_seed_kv_hdl
            .try_into()
            .unwrap_or_else(|e: CaliptraError| {
                cprintln!("[fht] Invalid FMC Alias MLDSA Key Pair Seed KV handle");
                handle_fatal_error(e.into())
            });

        match ds {
            KeyVaultSlot(key_id) => {
                cprintln!(
                    "[fht] FMC Alias MLDSA Key Pair Seed KV Slot: {:?}",
                    u32::from(key_id)
                );
                key_id
            }
            _ => {
                cprintln!("[fht] Invalid KeySlot DV Entry");
                handle_fatal_error(CaliptraError::FMC_HANDOFF_INVALID_PARAM.into())
            }
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
                cprintln!("[fht] Invalid RT Entry Point");
                handle_fatal_error(e.into());
            }
        }
    }

    /// Retrieve runtime TCI (digest)
    pub fn rt_tci(env: &FmcEnv) -> Array4x12 {
        env.persistent_data.get().data_vault.rt_tci()
    }

    /// Retrieve runtime SVN.
    pub fn rt_svn(env: &FmcEnv) -> u32 {
        env.persistent_data.get().data_vault.rt_svn()
    }

    /// Store runtime Dice Signature
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn set_rt_dice_signature(env: &mut FmcEnv, sig: &Ecc384Signature) {
        Self::fht_mut(env).rt_dice_sign = *sig;
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn set_rtalias_tbs_size(env: &mut FmcEnv, rtalias_tbs_size: usize) {
        Self::fht_mut(env).rtalias_tbs_size = rtalias_tbs_size as u16;
    }

    /// Retrieve the entry point of the runtime firmware.
    fn rt_entry_point(env: &FmcEnv) -> u32 {
        env.persistent_data.get().data_vault.rt_entry_point()
    }

    /// The FMC CDI is stored in a 32-bit DataVault sticky register.
    fn key_id_to_handle(key_id: KeyId) -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | key_id as u32)
    }

    /// Update HandOff Table with RT Parameters
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn update(env: &mut FmcEnv, out: DiceOutput) -> CaliptraResult<()> {
        // update fht.rt_cdi_kv_hdl
        Self::fht_mut(env).rt_cdi_kv_hdl = Self::key_id_to_handle(out.cdi);
        Self::fht_mut(env).rt_priv_key_kv_hdl =
            Self::key_id_to_handle(out.ecc_subj_key_pair.priv_key);
        Self::fht_mut(env).rt_dice_pub_key = out.ecc_subj_key_pair.pub_key;
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

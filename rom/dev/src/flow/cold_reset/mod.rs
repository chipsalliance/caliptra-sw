/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the implementation of Cold Reset Flow

--*/

mod crypto;
mod dice;
mod fmc_alias;
mod fw_processor;
mod idev_id;
mod ldev_id;
mod x509;

use crate::fht;
use crate::flow::cold_reset::dice::*;
use crate::flow::cold_reset::fmc_alias::FmcAliasLayer;
use crate::flow::cold_reset::fw_processor::FirmwareProcessor;
use crate::flow::cold_reset::idev_id::InitDevIdLayer;
use crate::flow::cold_reset::ldev_id::LocalDevIdLayer;
use crate::{cprintln, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::*;

pub const KEY_ID_UDS: KeyId = KeyId::KeyId0;
pub const KEY_ID_FE: KeyId = KeyId::KeyId1;
pub const KEY_ID_CDI: KeyId = KeyId::KeyId6;
pub const KEY_ID_IDEVID_PRIV_KEY: KeyId = KeyId::KeyId7;
pub const KEY_ID_LDEVID_PRIV_KEY: KeyId = KeyId::KeyId5;
pub const KEY_ID_FMC_PRIV_KEY: KeyId = KeyId::KeyId7;

extern "C" {
    static mut LDEVID_TBS_ORG: u8;
    static mut FMCALIAS_TBS_ORG: u8;
    static mut LDEVID_TBS_SIZE: u8;
    static mut FMCALIAS_TBS_SIZE: u8;
}

pub enum TbsType {
    LdevidTbs = 0,
    FmcaliasTbs = 1,
}
/// Cold Reset Flow
pub struct ColdResetFlow {}

impl ColdResetFlow {
    /// Execute Cold Reset Flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<FirmwareHandoffTable> {
        cprintln!("[cold-reset] ++");

        // Execute IDEVID layer
        let idevid_layer_output = InitDevIdLayer::derive(env)?;
        let ldevid_layer_input = dice_input_from_output(&idevid_layer_output);

        // Execute LDEVID layer
        let ldevid_layer_output = LocalDevIdLayer::derive(env, &ldevid_layer_input)?;
        let fmc_layer_input = dice_input_from_output(&ldevid_layer_output);

        // Download and validate firmware.
        let fw_proc_info = FirmwareProcessor::process(env)?;

        // Execute FMCALIAS layer
        FmcAliasLayer::derive(env, &fmc_layer_input, &fw_proc_info)?;

        cprintln!("[cold-reset] --");

        Ok(fht::make_fht(env))
    }
}

/// Copies the TBS to DCCM
///
/// # Arguments
/// * `tbs` - TBS to copy
/// * `tbs_type` - Type of TBS
/// * `env` - ROM Environment
///
/// # Returns
///     CaliptraResult
pub fn copy_tbs(tbs: &[u8], tbs_type: TbsType, env: &mut RomEnv) -> CaliptraResult<()> {
    let dst = match tbs_type {
        TbsType::LdevidTbs => {
            env.fht_data_store.ldevid_tbs_size = tbs.len() as u16;
            unsafe {
                let tbs_max_size = &LDEVID_TBS_SIZE as *const u8 as usize;
                if tbs.len() > tbs_max_size {
                    return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE);
                }
                let ptr = &mut LDEVID_TBS_ORG as *mut u8;
                core::slice::from_raw_parts_mut(ptr, tbs.len())
            }
        }
        TbsType::FmcaliasTbs => {
            env.fht_data_store.fmcalias_tbs_size = tbs.len() as u16;
            unsafe {
                let tbs_max_size = &FMCALIAS_TBS_SIZE as *const u8 as usize;
                if tbs.len() > tbs_max_size {
                    return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE);
                }

                let ptr = &mut FMCALIAS_TBS_ORG as *mut u8;
                core::slice::from_raw_parts_mut(ptr, tbs.len())
            }
        }
    };

    dst[..tbs.len()].copy_from_slice(tbs);
    Ok(())
}

fn dice_input_from_output(dice_output: &DiceOutput) -> DiceInput {
    DiceInput {
        auth_key_pair: &dice_output.subj_key_pair,
        auth_sn: &dice_output.subj_sn,
        auth_key_id: &dice_output.subj_key_id,
    }
}

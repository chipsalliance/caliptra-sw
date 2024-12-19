/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the implementation of Cold Reset Flow

--*/

mod dice;
mod fmc_alias;
pub mod fw_processor;
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
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::*;
use zeroize::Zeroize;

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
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<()> {
        cprintln!("[cold-reset] ++");
        report_boot_status(ColdResetStarted.into());
        {
            let data_vault = &mut env.persistent_data.get_mut().data_vault;

            // Indicate that Cold-Reset flow has started.
            // This is used by the next Warm-Reset flow to confirm that the Cold-Reset was successful.
            // Success status is set at the end of the flow.
            data_vault.set_rom_cold_boot_status(ColdResetStarted.into());
        }

        // Initialize FHT
        fht::initialize_fht(env);

        // Execute IDEVID layer
        let mut idevid_layer_output = InitDevIdLayer::derive(env)?;
        let ldevid_layer_input = dice_input_from_output(&idevid_layer_output);

        // Execute LDEVID layer
        let result = LocalDevIdLayer::derive(env, &ldevid_layer_input);
        idevid_layer_output.zeroize();
        let mut ldevid_layer_output = result?;
        let fmc_layer_input = dice_input_from_output(&ldevid_layer_output);

        // Download and validate firmware.
        let mut fw_proc_info = FirmwareProcessor::process(env)?;

        // Execute FMCALIAS layer
        let result = FmcAliasLayer::derive(env, &fmc_layer_input, &fw_proc_info);
        ldevid_layer_output.zeroize();
        fw_proc_info.zeroize();
        result?;

        // Indicate Cold-Reset successful completion.
        // This is used by the Warm-Reset flow to confirm that the Cold-Reset was successful.
        let data_vault = &mut env.persistent_data.get_mut().data_vault;
        data_vault.set_rom_cold_boot_status(ColdResetComplete.into());

        report_boot_status(ColdResetComplete.into());

        cprintln!("[cold-reset] --");

        Ok(())
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
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
#[inline(never)]
pub fn copy_tbs(tbs: &[u8], tbs_type: TbsType, env: &mut RomEnv) -> CaliptraResult<()> {
    let mut persistent_data = env.persistent_data.get_mut();
    let dst = match tbs_type {
        TbsType::LdevidTbs => {
            persistent_data.fht.ldevid_tbs_size = tbs.len() as u16;
            persistent_data
                .ldevid_tbs
                .get_mut(..tbs.len())
                .ok_or(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE)?
        }
        TbsType::FmcaliasTbs => {
            persistent_data.fht.fmcalias_tbs_size = tbs.len() as u16;
            persistent_data
                .fmcalias_tbs
                .get_mut(..tbs.len())
                .ok_or(CaliptraError::ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE)?
        }
    };
    dst.copy_from_slice(tbs);
    Ok(())
}

fn dice_input_from_output(dice_output: &DiceOutput) -> DiceInput {
    DiceInput {
        ecc_auth_key_pair: &dice_output.ecc_subj_key_pair,
        ecc_auth_sn: &dice_output.ecc_subj_sn,
        ecc_auth_key_id: &dice_output.ecc_subj_key_id,
        mldsa_auth_key_pair: &dice_output.mldsa_subj_key_pair,
        mldsa_auth_sn: &dice_output.mldsa_subj_sn,
        mldsa_auth_key_id: &dice_output.mldsa_subj_key_id,
    }
}

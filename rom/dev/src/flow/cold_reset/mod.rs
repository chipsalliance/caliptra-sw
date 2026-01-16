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
mod ocp_lock;
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
use zerocopy::transmute;
use zeroize::Zeroize;

pub enum TbsType {
    EccLdevid = 0,
    EccFmcalias = 1,
    MldsaLdevid = 2,
    MldsaFmcalias = 3,
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

        env.persistent_data.get_mut().rom.marker = RomPersistentData::MAGIC;
        env.persistent_data.get_mut().rom.major_version = RomPersistentData::MAJOR_VERSION;
        env.persistent_data.get_mut().rom.minor_version = RomPersistentData::MINOR_VERSION;
        env.persistent_data.get_mut().rom.boot_mode = BootMode::Normal;

        {
            let data_vault = &mut env.persistent_data.get_mut().rom.data_vault;

            // Indicate that Cold-Reset flow has started.
            // This is used by the next Warm-Reset flow to confirm that the Cold-Reset was successful.
            // Success status is set at the end of the flow.
            data_vault.set_rom_cold_boot_status(ColdResetStarted.into());
        }

        // Initialize FHT
        fht::initialize_fht(env);

        // Execute IDEVID layer
        let mut dice_out = InitDevIdLayer::derive(env)?;
        let dice_in = dice_input_from_output(&dice_out);
        let mut dice_out = {
            // Execute LDEVID layer
            let res = LocalDevIdLayer::derive(env, &dice_in);
            dice_out.zeroize();
            res?
        };
        let dice_in = dice_input_from_output(&dice_out);
        // Generate the CMB AES key

        // Generate the CMB AES key
        generate_cmb_aes_key(env)?;

        // Download and validate firmware.
        let mut fw_proc_info = FirmwareProcessor::process(env)?;

        // Execute FMCALIAS layer
        let result = FmcAliasLayer::derive(env, &dice_in, &fw_proc_info);
        dice_out.zeroize();
        fw_proc_info.zeroize();
        result?;

        // Indicate Cold-Reset successful completion.
        // This is used by the Warm-Reset flow to confirm that the Cold-Reset was successful.
        let data_vault = &mut env.persistent_data.get_mut().rom.data_vault;
        data_vault.set_rom_cold_boot_status(ColdResetComplete.into());

        report_boot_status(ColdResetComplete.into());

        cprintln!("[cold-reset] --");

        Ok(())
    }
}

/// Generates the cryptographic mailbox AES key.
fn generate_cmb_aes_key(env: &mut RomEnv) -> CaliptraResult<()> {
    let key_share0: [u32; 8] = env.trng.generate()?.0[..8].try_into().unwrap();
    let key_share1: [u32; 8] = env.trng.generate()?.0[..8].try_into().unwrap();
    env.persistent_data.get_mut().rom.cmb_aes_key_share0 = transmute!(key_share0);
    env.persistent_data.get_mut().rom.cmb_aes_key_share1 = transmute!(key_share1);
    Ok(())
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
    let persistent_data = env.persistent_data.get_mut();
    let dst = match tbs_type {
        TbsType::EccLdevid => {
            persistent_data.rom.fht.ecc_ldevid_tbs_size = tbs.len() as u16;
            persistent_data
                .rom
                .ecc_ldevid_tbs
                .get_mut(..tbs.len())
                .ok_or(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE)?
        }
        TbsType::EccFmcalias => {
            persistent_data.rom.fht.ecc_fmcalias_tbs_size = tbs.len() as u16;
            persistent_data
                .rom
                .ecc_fmcalias_tbs
                .get_mut(..tbs.len())
                .ok_or(CaliptraError::ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE)?
        }
        TbsType::MldsaLdevid => {
            persistent_data.rom.fht.mldsa_ldevid_tbs_size = tbs.len() as u16;
            persistent_data
                .rom
                .mldsa_ldevid_tbs
                .get_mut(..tbs.len())
                .ok_or(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE)?
        }
        TbsType::MldsaFmcalias => {
            persistent_data.rom.fht.mldsa_fmcalias_tbs_size = tbs.len() as u16;
            persistent_data
                .rom
                .mldsa_fmcalias_tbs
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

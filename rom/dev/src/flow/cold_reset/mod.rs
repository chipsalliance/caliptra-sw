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
mod idev_id;
mod ldev_id;
mod x509;

use crate::fht;
use crate::flow::cold_reset::fmc_alias::FmcAliasLayer;
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

/// Initialization Vector used by Deobfuscation Engine during Unique Device Secret (UDS) decryption.
const DOE_UDS_IV: Array4x4 = Array4xN::<4, 16>([0xfb10365b, 0xa1179741, 0xfba193a1, 0x0f406d7e]);

/// Initialization Vector used by Deobfuscation Engine during Field Entropy decryption.
const DOE_FE_IV: Array4x4 = Array4xN::<4, 16>([0xfb10365b, 0xa1179741, 0xfba193a1, 0x0f406d7e]);

/// Cold Reset Flow
pub struct ColdResetFlow {}

impl ColdResetFlow {
    /// Execute Cold Reset Flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(env: &RomEnv) -> CaliptraResult<FirmwareHandoffTable> {
        cprintln!("[cold-reset] ++");

        Self::decrypt_uds(env, KEY_ID_UDS)?;
        Self::decrypt_field_entropy(env, KEY_ID_FE)?;
        Self::clear_doe_secrets(env)?;

        let idevid_output = InitDevIdLayer::derive(env)?;
        let ldevid_output = LocalDevIdLayer::derive(env, &idevid_output)?;
        let _fmc_output = FmcAliasLayer::derive(env, &ldevid_output)?;

        cprintln!("[cold-reset] --");

        Ok(fht::make_fht(env))
    }

    /// Decrypt Unique Device Secret (UDS)
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `uds` - Key Vault slot to store the decrypted UDS in
    fn decrypt_uds(env: &RomEnv, uds: KeyId) -> CaliptraResult<()> {
        // Engage the Deobfuscation Engine to decrypt the UDS
        env.doe().map(|d| d.decrypt_uds(&DOE_UDS_IV, uds))
    }

    /// Decrypt Field Entropy (FW)
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `slot` - Key Vault slot to store the decrypted UDS in
    fn decrypt_field_entropy(env: &RomEnv, fe: KeyId) -> CaliptraResult<()> {
        // Engage the Deobfuscation Engine to decrypt the UDS
        env.doe().map(|d| d.decrypt_field_entropy(&DOE_FE_IV, fe))
    }

    /// Clear Deobfuscation Engine secrets
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    fn clear_doe_secrets(env: &RomEnv) -> CaliptraResult<()> {
        env.doe().map(|d| d.clear_secrets())
    }
}

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
use crate::flow::cold_reset::dice::*;
use crate::flow::cold_reset::fmc_alias::FmcAliasLayer;
use crate::flow::cold_reset::idev_id::InitDevIdLayer;
use crate::flow::cold_reset::ldev_id::LocalDevIdLayer;
use crate::{cprintln, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_lib::*;
use crypto::Ecc384KeyPair;

pub const KEY_ID_CDI: KeyId = KeyId::KeyId6;
pub const KEY_ID_PRIV_KEY: KeyId = KeyId::KeyId7;

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

        // Compose the three dice layers into one function
        let dice_fn = compose_layers(
            InitDevIdLayer::derive,
            compose_layers(LocalDevIdLayer::derive, FmcAliasLayer::derive),
        );

        // Create initial output
        let input = DiceInput {
            cdi: KEY_ID_CDI,
            subj_priv_key: KEY_ID_PRIV_KEY,
            auth_key_pair: Ecc384KeyPair {
                priv_key: KeyId::KeyId5,
                pub_key: Ecc384PubKey::default(),
            },
            auth_sn: [0u8; 64],
            auth_key_id: [0u8; 20],
            uds_key: KeyId::KeyId0,
            fe_key: KeyId::KeyId1,
        };

        let _ = dice_fn(env, &input)?;

        cprintln!("[cold-reset] --");

        Ok(fht::make_fht(env))
    }
}

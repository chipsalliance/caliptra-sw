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
use caliptra_drivers::*;

pub const KEY_ID_UDS: KeyId = KeyId::KeyId0;
pub const KEY_ID_FE: KeyId = KeyId::KeyId1;
pub const KEY_ID_CDI: KeyId = KeyId::KeyId6;
pub const KEY_ID_IDEVID_PRIV_KEY: KeyId = KeyId::KeyId7;
pub const KEY_ID_LDEVID_PRIV_KEY: KeyId = KeyId::KeyId5;
pub const KEY_ID_FMC_PRIV_KEY: KeyId = KeyId::KeyId7;

caliptra_err_def! {
    RomGlobal,
    GlobalErr
    {
        TbsUnsupportedDataLength = 0x6,
    }
}

extern "C" {
    static mut LDEVID_TBS_ORG: u8;
    static mut FMCALIAS_TBS_ORG: u8;
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

        // Compose the three dice layers into one function
        let dice_fn = compose_layers(
            InitDevIdLayer::derive,
            compose_layers(LocalDevIdLayer::derive, FmcAliasLayer::derive),
        );

        let input = DiceInput::default();

        let _ = dice_fn(env, &input)?;

        cprintln!("[cold-reset] --");

        Ok(fht::make_fht(env))
    }
}

// Writes out a u32 length in little-endian byte order, followed by the TBS.
pub fn copy_tbs(tbs: &[u8], tbs_type: TbsType) -> CaliptraResult<()> {
    const SIZE_LEN: usize = core::mem::size_of::<u32>();
    const MAX_TBS_LEN: usize = 0x400 - SIZE_LEN;

    if tbs.len() > MAX_TBS_LEN {
        raise_err!(TbsUnsupportedDataLength);
    }

    let (len_dst, tbs_dst) = unsafe {
        let ptr = match tbs_type {
            TbsType::LdevidTbs => &mut LDEVID_TBS_ORG,
            TbsType::FmcaliasTbs => &mut FMCALIAS_TBS_ORG,
        } as *mut u8;

        ptr.write_bytes(0, SIZE_LEN);

        (
            core::slice::from_raw_parts_mut(ptr, SIZE_LEN),
            core::slice::from_raw_parts_mut(ptr.add(SIZE_LEN), tbs.len()),
        )
    };

    let len_bytes = tbs.len().to_le_bytes();

    len_dst[..len_bytes.len()].copy_from_slice(&len_bytes);
    tbs_dst[..tbs.len()].copy_from_slice(tbs);

    Ok(())
}

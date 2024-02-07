/*++
Licensed under the Apache-2.0 license.

File Name:

    keyids.rs

Abstract:

    Key IDs

--*/

use caliptra_drivers::KeyId;

#[cfg(feature = "rom")]
pub const KEY_ID_UDS: KeyId = KeyId::KeyId0;
#[cfg(feature = "rom")]
pub const KEY_ID_FE: KeyId = KeyId::KeyId1;
#[cfg(feature = "rom")]
pub const KEY_ID_IDEVID_PRIV_KEY: KeyId = KeyId::KeyId7;
#[cfg(feature = "rom")]
pub const KEY_ID_LDEVID_PRIV_KEY: KeyId = KeyId::KeyId5;
#[cfg(feature = "rom")]
pub const KEY_ID_ROM_FMC_CDI: KeyId = KeyId::KeyId6;
#[cfg(feature = "rom")]
pub const KEY_ID_FMC_PRIV_KEY: KeyId = KeyId::KeyId7;
#[cfg(feature = "fmc")]
pub const KEY_ID_RT_CDI: KeyId = KeyId::KeyId4;
#[cfg(feature = "fmc")]
pub const KEY_ID_RT_PRIV_KEY: KeyId = KeyId::KeyId5;
#[cfg(feature = "runtime")]
pub const KEY_ID_DPE_CDI: KeyId = KeyId::KeyId8;
#[cfg(feature = "runtime")]
pub const KEY_ID_DPE_PRIV_KEY: KeyId = KeyId::KeyId9;

pub const KEY_ID_TMP: KeyId = KeyId::KeyId3;

/*++
Licensed under the Apache-2.0 license.

File Name:

    keyids.rs

Abstract:

    Key IDs

--*/

use caliptra_drivers::KeyId;

pub const KEY_ID_UDS: KeyId = KeyId::KeyId0;
pub const KEY_ID_FE: KeyId = KeyId::KeyId1;
pub const KEY_ID_TMP: KeyId = KeyId::KeyId3;
pub const KEY_ID_ROM_FMC_CDI: KeyId = KeyId::KeyId6;
pub const KEY_ID_IDEVID_PRIV_KEY: KeyId = KeyId::KeyId7;
pub const KEY_ID_LDEVID_PRIV_KEY: KeyId = KeyId::KeyId5;
pub const KEY_ID_FMC_PRIV_KEY: KeyId = KeyId::KeyId7;
pub const KEY_ID_RT_CDI: KeyId = KeyId::KeyId4;
pub const KEY_ID_RT_PRIV_KEY: KeyId = KeyId::KeyId5;
pub const KEY_ID_RT_HASH_CHAIN: KeyId = KeyId::KeyId2;
pub const KEY_ID_DPE_CDI: KeyId = KeyId::KeyId8;
pub const KEY_ID_DPE_PRIV_KEY: KeyId = KeyId::KeyId9;

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
pub const KEY_ID_IDEVID_ECDSA_PRIV_KEY: KeyId = KeyId::KeyId7;
#[cfg(feature = "rom")]
pub const KEY_ID_IDEVID_MLDSA_KEYPAIR_SEED: KeyId = KeyId::KeyId8;
#[cfg(feature = "rom")]
pub const KEY_ID_LDEVID_MLDSA_KEYPAIR_SEED: KeyId = KeyId::KeyId4;
#[cfg(feature = "rom")]
pub const KEY_ID_LDEVID_ECDSA_PRIV_KEY: KeyId = KeyId::KeyId5;
#[cfg(feature = "rom")]
pub const KEY_ID_ROM_FMC_CDI: KeyId = KeyId::KeyId6;
#[cfg(feature = "rom")]
pub const KEY_ID_FMC_ECDSA_PRIV_KEY: KeyId = KeyId::KeyId7;
#[cfg(feature = "rom")]
pub const KEY_ID_FMC_MLDSA_KEYPAIR_SEED: KeyId = KeyId::KeyId8;
#[cfg(feature = "rom")]
pub const KEY_ID_FW_KEY_LADDER: KeyId = KeyId::KeyId2;
#[cfg(feature = "fmc")]
pub const KEY_ID_RT_CDI: KeyId = KeyId::KeyId4;
#[cfg(feature = "fmc")]
pub const KEY_ID_RT_ECDSA_PRIV_KEY: KeyId = KeyId::KeyId5;
#[cfg(feature = "fmc")]
pub const KEY_ID_RT_MLDSA_KEYPAIR_SEED: KeyId = KeyId::KeyId9;
#[cfg(feature = "runtime")]
pub const KEY_ID_DPE_CDI: KeyId = KeyId::KeyId10;
#[cfg(feature = "runtime")]
pub const KEY_ID_DPE_PRIV_KEY: KeyId = KeyId::KeyId11;
#[cfg(feature = "runtime")]
pub const KEY_ID_EXPORTED_DPE_CDI: KeyId = KeyId::KeyId12;
pub const KEY_ID_STABLE_IDEV: KeyId = KeyId::KeyId0;
pub const KEY_ID_STABLE_LDEV: KeyId = KeyId::KeyId1;

pub const KEY_ID_TMP: KeyId = KeyId::KeyId3;

#[cfg(feature = "ocp-lock")]
pub mod ocp_lock {
    use super::KeyId;

    pub const KEY_ID_MDK: KeyId = KeyId::KeyId16;
    pub const KEY_ID_EPK: KeyId = KeyId::KeyId17;
    pub const KEY_ID_HEK: KeyId = KeyId::KeyId22;
    pub const KEY_ID_HEK_SEED: KeyId = KeyId::KeyId22;
    pub const KEY_ID_MEK: KeyId = KeyId::KeyId23;
}

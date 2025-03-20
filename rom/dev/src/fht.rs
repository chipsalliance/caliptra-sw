/*++

Licensed under the Apache-2.0 license.

File Name:

    fht.rs

Abstract:

    Firmware Handoff table creation and loading.

--*/

use crate::{CALIPTRA_ROM_INFO, rom_env::RomEnv};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_common::{
    FHT_INVALID_HANDLE, FHT_MARKER, FirmwareHandoffTable, HandOffDataHandle, Vault,
    keyids::{
        KEY_ID_FMC_ECDSA_PRIV_KEY, KEY_ID_FMC_MLDSA_KEYPAIR_SEED, KEY_ID_FW_KEY_LADDER,
        KEY_ID_ROM_FMC_CDI,
    },
};
use caliptra_drivers::{RomAddr, cprintln};
use caliptra_image_verify::MAX_FIRMWARE_SVN;

const FHT_MAJOR_VERSION: u16 = 1;
const FHT_MINOR_VERSION: u16 = 0;

#[derive(Debug, Default)]
pub struct FhtDataStore {}

impl FhtDataStore {
    /// The FMC CDI is stored in a Key Vault slot.
    pub const fn fmc_cdi_store() -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_ROM_FMC_CDI as u32)
    }
    /// The FMC ECC private key is stored in a Key Vault slot.
    pub const fn fmc_ecc_priv_key_store() -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_FMC_ECDSA_PRIV_KEY as u32)
    }
    /// The FMC MLDSA key pair seed is stored in a Key Vault slot.
    pub const fn fmc_mldsa_keypair_seed_store() -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_FMC_MLDSA_KEYPAIR_SEED as u32)
    }
    /// The firmware key ladder is stored in a KeyVault slot.
    pub const fn fw_key_ladder_store() -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_FW_KEY_LADDER as u32)
    }
}

#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn initialize_fht(env: &mut RomEnv) {
    let pdata = &env.persistent_data.get();

    cprintln!("[fht] FHT @ 0x{:08X}", &pdata.fht as *const _ as usize);

    env.persistent_data.get_mut().fht = FirmwareHandoffTable {
        fht_marker: FHT_MARKER,
        fht_major_ver: FHT_MAJOR_VERSION,
        fht_minor_ver: FHT_MINOR_VERSION,
        fips_fw_load_addr_hdl: FHT_INVALID_HANDLE,
        fmc_cdi_kv_hdl: FhtDataStore::fmc_cdi_store(),
        fmc_ecc_priv_key_kv_hdl: FhtDataStore::fmc_ecc_priv_key_store(),
        fmc_mldsa_keypair_seed_kv_hdl: FhtDataStore::fmc_mldsa_keypair_seed_store(),
        rt_cdi_kv_hdl: FHT_INVALID_HANDLE,
        rt_priv_key_kv_hdl: FHT_INVALID_HANDLE,
        rom_info_addr: RomAddr::from(unsafe { &CALIPTRA_ROM_INFO }),
        manifest_load_addr: &pdata.manifest1 as *const _ as u32,
        ecc_ldevid_tbs_addr: &pdata.ecc_ldevid_tbs as *const _ as u32,
        ecc_fmcalias_tbs_addr: &pdata.ecc_fmcalias_tbs as *const _ as u32,
        mldsa_ldevid_tbs_addr: &pdata.mldsa_ldevid_tbs as *const _ as u32,
        mldsa_fmcalias_tbs_addr: &pdata.mldsa_fmcalias_tbs as *const _ as u32,
        pcr_log_addr: &pdata.pcr_log as *const _ as u32,
        meas_log_addr: &pdata.measurement_log as *const _ as u32,
        fuse_log_addr: &pdata.fuse_log as *const _ as u32,
        fw_key_ladder_max_svn: MAX_FIRMWARE_SVN as u16,
        fw_key_ladder_kv_hdl: FhtDataStore::fw_key_ladder_store(),
        ..Default::default()
    };
}

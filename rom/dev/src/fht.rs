/*++

Licensed under the Apache-2.0 license.

File Name:

    fht.rs

Abstract:

    Firmware Handoff table creation and loading.

--*/

use caliptra_common::{
    DataVaultRegister, FirmwareHandoffTable, HandOffDataHandle, Vault, FHT_INVALID_HANDLE,
    FHT_MARKER,
};
use caliptra_drivers::{ColdResetEntry4, ColdResetEntry48, WarmResetEntry4, WarmResetEntry48};
use zerocopy::AsBytes;

use crate::{
    cprintln,
    flow::{KEY_ID_CDI, KEY_ID_FMC_PRIV_KEY},
    rom_env::RomEnv,
};

const FHT_MAJOR_VERSION: u16 = 1;
const FHT_MINOR_VERSION: u16 = 0;

struct FhtDataStore {}
impl FhtDataStore {
    /// The FMC CDI is stored in a 32-bit DataVault sticky register.
    pub const fn fmc_cdi_store() -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_CDI as u32)
    }
    /// The FMC private key is stored in a 32-bit DataVault sticky register.
    pub const fn fmc_priv_key_store() -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_FMC_PRIV_KEY as u32)
    }
    /// The FMC SVN is stored in a 32-bit DataVault sticky register.
    pub const fn fmc_svn_store() -> HandOffDataHandle {
        HandOffDataHandle(
            ((Vault::DataVault as u32) << 12)
                | (DataVaultRegister::Sticky32BitReg as u32) << 8
                | ColdResetEntry4::FmcSvn as u32,
        )
    }
    /// The FMC TCI is stored in a 384-bit DataVault sticky register.
    pub const fn fmc_tci_store() -> HandOffDataHandle {
        HandOffDataHandle(
            ((Vault::DataVault as u32) << 12)
                | (DataVaultRegister::Sticky384BitReg as u32) << 8
                | ColdResetEntry48::FmcTci as u32,
        )
    }

    /// The FMC certificate signature R value is stored in a 384-bit DataVault
    /// sticky register.
    pub const fn fmc_cert_sig_r_store() -> HandOffDataHandle {
        HandOffDataHandle(
            ((Vault::DataVault as u32) << 12)
                | (DataVaultRegister::Sticky384BitReg as u32) << 8
                | ColdResetEntry48::FmcDiceSigR as u32,
        )
    }

    /// The FMC certificate signature S value is stored in a 384-bit DataVault
    /// sticky register.
    pub fn fmc_cert_sig_s_store() -> HandOffDataHandle {
        HandOffDataHandle(
            ((Vault::DataVault as u32) << 12)
                | (DataVaultRegister::Sticky384BitReg as u32) << 8
                | ColdResetEntry48::FmcDiceSigS as u32,
        )
    }
    /// The FMC public key X coordinate is stored in a 384-bit DataVault
    /// sticky register.
    pub const fn fmc_pub_key_x_store() -> HandOffDataHandle {
        HandOffDataHandle(
            (Vault::DataVault as u32) << 12
                | (DataVaultRegister::Sticky384BitReg as u32) << 8
                | ColdResetEntry48::FmcPubKeyX as u32,
        )
    }
    /// FMC public key Y coordinate is stored in a 384-bit DataVault
    /// sticky register.
    pub fn fmc_pub_key_y_store() -> HandOffDataHandle {
        HandOffDataHandle(
            (Vault::DataVault as u32) << 12
                | (DataVaultRegister::Sticky384BitReg as u32) << 8
                | ColdResetEntry48::FmcPubKeyY as u32,
        )
    }
    /// The RT SVN is stored in a 32-bit DataVault non-sticky register.
    pub fn rt_svn_data_store() -> HandOffDataHandle {
        HandOffDataHandle(
            ((Vault::DataVault as u32) << 12)
                | (DataVaultRegister::NonSticky32BitReg as u32) << 8
                | WarmResetEntry4::RtSvn as u32,
        )
    }
    /// The RT TCI is stored in a 384-bit DataVault non-sticky register.
    pub fn rt_tci_data_store() -> HandOffDataHandle {
        HandOffDataHandle(
            ((Vault::DataVault as u32) << 12)
                | (DataVaultRegister::NonSticky384BitReg as u32) << 8
                | WarmResetEntry48::RtTci as u32,
        )
    }
    /// The runtime firmware entry point is stored in a 32-bit DataVault
    /// non-sticky register.
    pub const fn rt_fw_entry_point() -> HandOffDataHandle {
        HandOffDataHandle(
            ((Vault::DataVault as u32) << 12)
                | (DataVaultRegister::NonSticky32BitReg as u32) << 8
                | WarmResetEntry4::RtEntryPoint as u32,
        )
    }
}

pub fn make_fht(env: &RomEnv) -> FirmwareHandoffTable {
    FirmwareHandoffTable {
        fht_marker: FHT_MARKER,
        fht_major_ver: FHT_MAJOR_VERSION,
        fht_minor_ver: FHT_MINOR_VERSION,
        manifest_load_addr: env.data_vault.manifest_addr(),
        fips_fw_load_addr_hdl: FHT_INVALID_HANDLE,
        rt_fw_load_addr_hdl: FhtDataStore::rt_fw_entry_point(),
        rt_fw_entry_point_hdl: FhtDataStore::rt_fw_entry_point(),
        fmc_cdi_kv_hdl: FhtDataStore::fmc_cdi_store(),
        fmc_priv_key_kv_hdl: FhtDataStore::fmc_priv_key_store(),
        fmc_pub_key_x_dv_hdl: FhtDataStore::fmc_pub_key_x_store(),
        fmc_pub_key_y_dv_hdl: FhtDataStore::fmc_pub_key_y_store(),
        fmc_cert_sig_r_dv_hdl: FhtDataStore::fmc_cert_sig_r_store(),
        fmc_cert_sig_s_dv_hdl: FhtDataStore::fmc_cert_sig_s_store(),
        fmc_tci_dv_hdl: FhtDataStore::fmc_tci_store(),
        fmc_svn_dv_hdl: FhtDataStore::fmc_svn_store(),
        rt_cdi_kv_hdl: FHT_INVALID_HANDLE,
        rt_priv_key_kv_hdl: FHT_INVALID_HANDLE,
        rt_pub_key_x_dv_hdl: FHT_INVALID_HANDLE,
        rt_pub_key_y_dv_hdl: FHT_INVALID_HANDLE,
        rt_cert_sig_r_dv_hdl: FHT_INVALID_HANDLE,
        rt_cert_sig_s_dv_hdl: FHT_INVALID_HANDLE,
        rt_tci_dv_hdl: FhtDataStore::rt_tci_data_store(),
        rt_svn_dv_hdl: FhtDataStore::rt_svn_data_store(),
        ..Default::default()
    }
}

pub fn load_fht(fht: FirmwareHandoffTable) {
    extern "C" {
        static mut FHT_ORG: u8;
    }

    let slice = unsafe {
        let ptr = &mut FHT_ORG as *mut u8;
        cprintln!("[fht] Loading FHT @ 0x{:08X}", ptr as u32);
        core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<FirmwareHandoffTable>())
    };
    caliptra_common::print_fht(&fht);
    slice.copy_from_slice(fht.as_bytes());
}

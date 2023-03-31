/*++

Licensed under the Apache-2.0 license.

File Name:

    fht.rs

Abstract:

    Firmware Handoff table creation and loading.

--*/

use caliptra_common::{FirmwareHandoffTable, FHT_MARKER};
use caliptra_drivers::{ColdResetEntry4, ColdResetEntry48, WarmResetEntry4, WarmResetEntry48};
use zerocopy::AsBytes;

use crate::{
    cprintln,
    flow::{KEY_ID_CDI, KEY_ID_PRIV_KEY},
    rom_env::RomEnv,
};

const FHT_MAJOR_VERSION: u16 = 1;
const FHT_MINOR_VERSION: u16 = 0;

pub fn make_fht(env: &RomEnv) -> FirmwareHandoffTable {
    FirmwareHandoffTable {
        fht_marker: FHT_MARKER,
        fht_major_ver: FHT_MAJOR_VERSION,
        fht_minor_ver: FHT_MINOR_VERSION,
        manifest_load_addr: env.data_vault().map(|d| d.manifest_addr()),
        fips_fw_load_addr_idx: u8::MAX,
        rt_fw_load_addr_idx: WarmResetEntry4::RtLoadAddr.into(),
        rt_fw_entry_point_idx: WarmResetEntry4::RtEntryPoint.into(),
        fmc_cdi_kv_idx: KEY_ID_CDI.into(),
        fmc_priv_key_kv_idx: KEY_ID_PRIV_KEY.into(),
        fmc_pub_key_x_dv_idx: ColdResetEntry48::FmcPubKeyX.into(),
        fmc_pub_key_y_dv_idx: ColdResetEntry48::FmcPubKeyY.into(),
        fmc_cert_sig_r_dv_idx: ColdResetEntry48::FmcDiceSigR.into(),
        fmc_cert_sig_s_dv_idx: ColdResetEntry48::FmcDiceSigS.into(),
        fmc_tci_dv_idx: ColdResetEntry48::FmcTci.into(),
        fmc_svn_dv_idx: ColdResetEntry4::FmcSvn.into(),
        rt_cdi_kv_idx: u8::MAX,
        rt_priv_key_kv_idx: u8::MAX,
        rt_pub_key_x_dv_idx: u8::MAX,
        rt_pub_key_y_dv_idx: u8::MAX,
        rt_cert_sig_r_dv_idx: u8::MAX,
        rt_cert_sig_s_dv_idx: u8::MAX,
        rt_tci_dv_idx: WarmResetEntry48::RtTci.into(),
        rt_svn_dv_idx: WarmResetEntry4::RtSvn.into(),
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

    slice.copy_from_slice(fht.as_bytes());
}

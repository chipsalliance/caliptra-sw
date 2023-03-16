// Licensed under the Apache-2.0 license.

use zerocopy::{AsBytes, FromBytes};

pub const FHT_MARKER: u32 = 0x54484643;
pub const FHT_INVALID_IDX: u8 = 0xff;

/// The Firmware Handoff Table is a data structure that is resident
/// at a well-known location in DCCM. It is initially populated by ROM and modified by FMC as a way to pass parameters and configuration information
/// from one firmware layer to the next.
#[repr(C)]
#[derive(Clone, Debug, Default, AsBytes, FromBytes)]
pub struct FirmwareHandoffTable {
    /// Magic Number marking start of table. Value must be 0x54484643
    /// (‘CFHT’ when viewed as little-endian ASCII).
    pub marker: u32,

    /// Major version of FHT.
    pub major_ver: u16,

    /// Minor version of FHT. Initially written by ROM but may be changed to
    /// a higher version by FMC.
    pub minor_ver: u16,

    /// Physical base address of Manifest in DCCM SRAM.
    pub manifest_base_addr: u32,

    /// Physical base address of FIPS Module in ROM or ICCM SRAM.
    /// May be NULL if there is no discrete module.
    pub fips_fw_load_addr: u32,

    /// Physical base address of Runtime FW Module in ICCM SRAM.
    pub rt_fw_load_addr: u32,

    /// Entry point of Runtime FW Module in ICCM SRAM.
    pub rt_fw_entry_point: u32,

    /// Index of FMC CDI value in the Key Vault. Value of 0xFF indicates not present.
    pub fmc_cdi_kv_idx: u8,

    /// Index of FMC Private Alias Key in the Key Vault.
    pub fmc_priv_key_kv_idx: u8,

    /// Index of FMC Public Alias Key X Coordinate in the Data Vault.
    pub fmc_pub_key_x_dv_idx: u8,

    /// Index of FMC Public Alias Key Y Coordinate in the Data Vault.
    pub fmc_pub_key_y_dv_idx: u8,

    /// Index of FMC Certificate Signature R Coordinate in the Data Vault.
    pub fmc_cert_sig_r_dv_idx: u8,

    /// Index of FMC Certificate Signature S Coordinate in the Data Vault.
    pub fmc_cert_sig_s_dv_idx: u8,

    /// FMC TCI
    pub fmc_tci_dv_idx: u8,

    /// FMC SVN
    pub fmc_svn_dv_idx: u8,

    /// Indenx of RT CDI value in the Key Vault.
    pub rt_cdi_kv_idx: u8,

    /// Index of RT Private Alias Key in the Key Vault.
    pub rt_priv_key_kv_idx: u8,

    /// Index of RT Public Alias Key X Coordinate in the Data Vault.
    pub rt_pub_key_x_dv_idx: u8,

    /// Index of RT Public Alias Key Y Coordinate in the Data Vault.
    pub rt_pub_key_y_dv_idx: u8,

    /// Index of RT Certificate Signature R Coordinate in the Data Vault.
    pub rt_cert_sig_r_dv_idx: u8,

    /// Index of RT Certificate Signature S Coordinate in the Data Vault.
    pub rt_cert_sig_s_dv_idx: u8,

    /// RT TCI
    pub rt_tci_dv_idx: u8,

    /// RT SVN
    pub rt_svn_dv_idx: u8,

    /// Reserved for future use.
    pub reserved: [u8; 20],
}

impl FirmwareHandoffTable {
    /// Perform valdity check of the table's data.
    pub fn is_valid(&self) -> bool {
        self.marker == FHT_MARKER && self.fmc_cdi_kv_idx != FHT_INVALID_IDX
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::mem;
    // FHT is currently defined to be 60 bytes in length.
    const FHT_SIZE: usize = 60;

    #[test]
    fn test_fht_is_valid() {
        let fht = FirmwareHandoffTable::default();
        assert!(!fht.is_valid());
        assert_eq!(FHT_SIZE, mem::size_of::<FirmwareHandoffTable>());
    }
}

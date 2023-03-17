// Licensed under the Apache-2.0 license.
const FHT_MAGIC: u32 = 0x54484643;
const FHT_INVALID_IDX: u8 = 0xff;

#[repr(C)]
#[derive(Clone, Debug, Default)]
/// The Firmware Handoff Table is a data structure that is resident
/// at a well-known location in DCCM. It is initially populated by ROM and modified by FMC as a way to pass parameters and configuration information
/// from one firmware layer to the next.
pub struct FirmwareHandoffTable {
    /// Magic Number marking start of table. Value must be 0x54484643
    /// (‘CFHT’ when viewed as little-endian ASCII).
    fht_marker: u32,
    /// Major version of FHT.
    fht_major_ver: u16,
    /// Minor version of FHT. Initially written by ROM but may be changed to
    /// a higher version by FMC.
    fht_minor_ver: u16,
    /// Physical base address of Manifest in DCCM SRAM.
    manifest_base_addr: u32,
    /// Physical base address of FIPS Module in ROM or ICCM SRAM.
    /// May be NULL if there is no discrete module.
    fips_fw_base_addr: u32,
    /// Physical base address of Runtime FW Module in ICCM SRAM.
    rt_fw_base_addr: u32,
    /// Index of FMC CDI value in the Key Vault. Value of 0xFF indicates not present.
    fmc_cdi_kv_idx: u8,
    /// Index of FMC Private Alias Key in the Key Vault.
    fmc_priv_key_kv_idx: u8,
    /// Index of FMC Public Alias Key in the Data Vault.
    fmc_pub_key_dv_idx: u8,
    /// Index of FMC Certificate Signature in the Data Vault.
    fmc_cert_dv_idx: u8,
    /// Index of RT CDI value in the Key Vault.
    rt_cdi_kv_idx: u8,
    /// Index of RT Private Alias Key in the Key Vault.
    rt_priv_key_kv_idx: u8,
    /// Index of RT Public Alias Key in the Data Vault.
    rt_pub_key_dv_idx: u8,
    /// Index of RT Certificate Signature in the Data Vault.
    rt_cert_dv_idx: u8,
    /// Reserved for future use.
    reserved: [u8; 20],
}

impl FirmwareHandoffTable {
    /// Perform valdity check of the table's data.
    pub fn is_valid(&self) -> bool {
        self.fht_marker == FHT_MAGIC && self.fmc_cdi_kv_idx != FHT_INVALID_IDX
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    // FHT is currently defined to be 48 bytes in length.
    const FHT_SIZE: usize = 48;

    #[test]
    fn test_fht_is_valid() {
        let fht = FirmwareHandoffTable::default();
        assert!(!fht.is_valid());
        assert_eq!(FHT_SIZE, mem::size_of::<FirmwareHandoffTable>());
    }
}

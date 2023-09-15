// Licensed under the Apache-2.0 license.

use crate::bounded_address::RomAddr;
use crate::{
    memory_layout, report_fw_error_non_fatal, ColdResetEntry4, ColdResetEntry48, Ecc384PubKey,
    Ecc384Signature, KeyId, ResetReason, WarmResetEntry4, WarmResetEntry48,
};
use crate::{memory_layout::FHT_ORG, soc_ifc};
use bitfield::{bitfield_bitrange, bitfield_fields};
use caliptra_error::CaliptraError;
use caliptra_image_types::RomInfo;
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

pub const FHT_MARKER: u32 = 0x54484643;
pub const FHT_INVALID_ADDRESS: u32 = u32::MAX;

#[repr(C)]
#[derive(AsBytes, Copy, Clone, Debug, FromBytes, PartialEq)]
pub struct HandOffDataHandle(pub u32);
pub const FHT_INVALID_HANDLE: HandOffDataHandle = HandOffDataHandle(u32::MAX);

bitfield_bitrange! {struct HandOffDataHandle(u32)}
impl HandOffDataHandle {
    bitfield_fields! {
       u32;
       reg_num, set_reg_num: 7, 0;
       reg_type, set_reg_type: 11, 8;
       vault, set_vault : 15, 12;
       reserved, _: 31, 16;
    }
    pub fn is_valid(&self) -> bool {
        self.0 != u32::MAX
    }
}

#[repr(u32)]
pub enum Vault {
    KeyVault = 1,
    PcrBank = 2,
    DataVault = 3,
}

impl From<Vault> for u32 {
    fn from(val: Vault) -> u32 {
        match val {
            Vault::KeyVault => 1,
            Vault::PcrBank => 2,
            Vault::DataVault => 3,
        }
    }
}

impl TryFrom<u32> for Vault {
    type Error = ();
    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match val {
            1_u32 => Ok(Vault::KeyVault),
            2_u32 => Ok(Vault::PcrBank),
            3_u32 => Ok(Vault::DataVault),
            _ => Err(()),
        }
    }
}

pub enum DataStore {
    KeyVaultSlot(KeyId),
    //PlatformConfigRegister(PcrId),
    DataVaultSticky4(ColdResetEntry4),
    DataVaultSticky48(ColdResetEntry48),
    DataVaultNonSticky4(WarmResetEntry4),
    DataVaultNonSticky48(WarmResetEntry48),
    Invalid,
}

impl From<HandOffDataHandle> for u32 {
    fn from(value: HandOffDataHandle) -> u32 {
        value.0
    }
}
#[allow(non_snake_case)]
pub enum DataVaultRegister {
    Sticky32BitReg = 1,
    Sticky384BitReg = 2,
    NonSticky32BitReg = 3,
    NonSticky384BitReg = 4,
}

impl TryInto<DataStore> for HandOffDataHandle {
    type Error = CaliptraError;
    fn try_into(self) -> Result<DataStore, Self::Error> {
        let vault = Vault::try_from(self.vault()).unwrap_or_else(|_| {
            report_handoff_error_and_halt(
                "Invalid Vault",
                CaliptraError::DRIVER_HANDOFF_INVALID_VAULT.into(),
            )
        });
        match vault {
            Vault::KeyVault => Ok(DataStore::KeyVaultSlot(
                KeyId::try_from(self.reg_num() as u8).unwrap_or_else(|_| {
                    report_handoff_error_and_halt(
                        "Invalid KeyId",
                        CaliptraError::DRIVER_HANDOFF_INVALID_KEY_ID.into(),
                    )
                }),
            )),
            Vault::DataVault => match self.reg_type() {
                1 => {
                    let entry = DataStore::DataVaultSticky4(
                        ColdResetEntry4::try_from(self.reg_num() as u8).unwrap_or_else(|_| {
                            report_handoff_error_and_halt(
                                "Invalid ColdResetEntry4",
                                CaliptraError::DRIVER_HANDOFF_INVALID_COLD_RESET_ENTRY4.into(),
                            )
                        }),
                    );
                    Ok(entry)
                }

                2 => {
                    let entry = DataStore::DataVaultSticky48(
                        ColdResetEntry48::try_from(self.reg_num() as u8).unwrap_or_else(|_| {
                            report_handoff_error_and_halt(
                                "Invalid ColdResetEntry48",
                                CaliptraError::DRIVER_HANDOFF_INVALID_COLD_RESET_ENTRY48.into(),
                            )
                        }),
                    );
                    Ok(entry)
                }

                3 => {
                    let entry =
                        WarmResetEntry4::try_from(self.reg_num() as u8).unwrap_or_else(|_| {
                            report_handoff_error_and_halt(
                                "Invalid WarmResetEntry4",
                                CaliptraError::DRIVER_HANDOFF_INVALID_WARM_RESET_ENTRY4.into(),
                            )
                        });

                    let ds = DataStore::DataVaultNonSticky4(entry);
                    Ok(ds)
                }

                4 => {
                    let entry = DataStore::DataVaultNonSticky48(
                        WarmResetEntry48::try_from(self.reg_num() as u8).unwrap_or_else(|_| {
                            report_handoff_error_and_halt(
                                "Invalid WarmResetEntry48",
                                CaliptraError::DRIVER_HANDOFF_INVALID_WARM_RESET_ENTRY48.into(),
                            )
                        }),
                    );
                    Ok(entry)
                }

                _ => Err(CaliptraError::DRIVER_BAD_DATASTORE_REG_TYPE),
            },
            _ => Err(CaliptraError::DRIVER_BAD_DATASTORE_VAULT_TYPE),
        }
    }
}

impl From<DataStore> for HandOffDataHandle {
    fn from(val: DataStore) -> HandOffDataHandle {
        match val {
            DataStore::KeyVaultSlot(key_id) => {
                let mut me = Self(0);
                me.set_vault(u32::from(Vault::KeyVault));
                me.set_reg_num(key_id.into());
                me
            }
            DataStore::DataVaultSticky4(entry_id) => {
                let mut me = Self(0);
                me.set_vault(u32::from(Vault::DataVault));
                me.set_reg_type(DataVaultRegister::Sticky32BitReg as u32);
                me.set_reg_num(entry_id.into());
                me
            }
            DataStore::DataVaultSticky48(entry_id) => {
                let mut me = Self(0);
                me.set_vault(Vault::DataVault as u32);
                me.set_reg_type(DataVaultRegister::Sticky384BitReg as u32);
                me.set_reg_num(entry_id.into());
                me
            }
            DataStore::DataVaultNonSticky4(entry_id) => {
                let mut me = Self(0);
                me.set_vault(Vault::DataVault as u32);
                me.set_reg_type(DataVaultRegister::NonSticky32BitReg as u32);
                me.set_reg_num(entry_id.into());
                me
            }
            DataStore::DataVaultNonSticky48(entry_id) => {
                let mut me = Self(0);
                me.set_vault(u32::from(Vault::DataVault));
                me.set_reg_type(DataVaultRegister::NonSticky384BitReg as u32);
                me.set_reg_num(entry_id.into());
                me
            }
            _ => {
                let mut me = Self(0);
                me.set_vault(0);
                me.set_reg_type(0);
                me.set_reg_num(0);
                me
            }
        }
    }
}

/// The Firmware Handoff Table is a data structure that is resident at a well-known
/// location in DCCM. It is initially populated by ROM and modified by FMC as a way
/// to pass parameters and configuration information from one firmware layer to the next.
const _: () = assert!(size_of::<FirmwareHandoffTable>() == 512);
const _: () = assert!(size_of::<FirmwareHandoffTable>() <= memory_layout::FHT_SIZE as usize);
#[repr(C)]
#[derive(Clone, Debug, AsBytes, FromBytes)]
pub struct FirmwareHandoffTable {
    /// Magic Number marking start of table. Value must be 0x54484643
    /// (‘CFHT’ when viewed as little-endian ASCII).
    pub fht_marker: u32,

    /// Major version of FHT.
    pub fht_major_ver: u16,

    /// Minor version of FHT. Initially written by ROM but may be changed to
    /// a higher version by FMC.
    pub fht_minor_ver: u16,

    /// Physical base address of Manifest in DCCM SRAM.
    pub manifest_load_addr: u32,

    /// Physical base address of FIPS Module in ROM or ICCM SRAM.
    /// May be NULL if there is no discrete module.
    pub fips_fw_load_addr_hdl: HandOffDataHandle,

    /// Entry point of Runtime FW Module in ICCM SRAM.
    pub rt_fw_entry_point_hdl: HandOffDataHandle,

    /// Index of FMC TCI value in the Data Vault.
    pub fmc_tci_dv_hdl: HandOffDataHandle,

    /// Index of FMC CDI value in the Key Vault. Value of 0xFF indicates not present.
    pub fmc_cdi_kv_hdl: HandOffDataHandle,

    /// Index of FMC Private Alias Key in the Key Vault.
    pub fmc_priv_key_kv_hdl: HandOffDataHandle,

    /// Index of FMC Public Alias Key X Coordinate in the Data Vault.
    pub fmc_pub_key_x_dv_hdl: HandOffDataHandle,

    /// Index of FMC Public Alias Key Y Coordinate in the Data Vault.
    pub fmc_pub_key_y_dv_hdl: HandOffDataHandle,

    /// Index of FMC Certificate Signature R Component in the Data Vault.
    pub fmc_cert_sig_r_dv_hdl: HandOffDataHandle,

    /// Index of FMC Certificate Signature S Component in the Data Vault.
    pub fmc_cert_sig_s_dv_hdl: HandOffDataHandle,

    /// Index of FMC SVN value in the Data Vault
    pub fmc_svn_dv_hdl: HandOffDataHandle,

    /// Index of RT TCI value in the Data Vault.
    pub rt_tci_dv_hdl: HandOffDataHandle,

    /// Index of RT CDI value in the Key Vault.
    pub rt_cdi_kv_hdl: HandOffDataHandle,

    /// Index of RT Private Alias Key in the Key Vault.
    pub rt_priv_key_kv_hdl: HandOffDataHandle,

    /// Index of RT SVN value in the Data Vault
    pub rt_svn_dv_hdl: HandOffDataHandle,

    /// Index of RT Min SVN value in the Data Vault
    pub rt_min_svn_dv_hdl: HandOffDataHandle,

    /// LdevId TBS Address
    pub ldevid_tbs_addr: u32,

    /// FmcAlias TBS Address
    pub fmcalias_tbs_addr: u32,

    /// LdevId TBS Size.
    pub ldevid_tbs_size: u16,

    /// FmcAlias TBS Size.
    pub fmcalias_tbs_size: u16,

    /// PCR log Address
    pub pcr_log_addr: u32,

    /// Last empty PCR log entry slot index
    pub pcr_log_index: u32,

    /// Fuse log Address
    pub fuse_log_addr: u32,

    pub rt_dice_pub_key: Ecc384PubKey,

    pub rt_dice_sign: Ecc384Signature,

    /// IDevID public key
    pub idev_dice_pub_key: Ecc384PubKey,

    // Address of RomInfo struct
    pub rom_info_addr: RomAddr<RomInfo>,

    /// RtAlias TBS Size.
    pub rtalias_tbs_size: u16,

    /// Reserved for future use.
    pub reserved: [u8; 122],
}

impl Default for FirmwareHandoffTable {
    fn default() -> Self {
        Self {
            fht_marker: 0,
            fht_major_ver: 0,
            fht_minor_ver: 0,
            manifest_load_addr: FHT_INVALID_ADDRESS,
            fips_fw_load_addr_hdl: FHT_INVALID_HANDLE,
            rt_fw_entry_point_hdl: FHT_INVALID_HANDLE,
            fmc_tci_dv_hdl: FHT_INVALID_HANDLE,
            fmc_cdi_kv_hdl: FHT_INVALID_HANDLE,
            fmc_priv_key_kv_hdl: FHT_INVALID_HANDLE,
            fmc_pub_key_x_dv_hdl: FHT_INVALID_HANDLE,
            fmc_pub_key_y_dv_hdl: FHT_INVALID_HANDLE,
            fmc_cert_sig_r_dv_hdl: FHT_INVALID_HANDLE,
            fmc_cert_sig_s_dv_hdl: FHT_INVALID_HANDLE,
            fmc_svn_dv_hdl: FHT_INVALID_HANDLE,
            rt_tci_dv_hdl: FHT_INVALID_HANDLE,
            rt_cdi_kv_hdl: FHT_INVALID_HANDLE,
            rt_priv_key_kv_hdl: FHT_INVALID_HANDLE,
            rt_svn_dv_hdl: FHT_INVALID_HANDLE,
            rt_min_svn_dv_hdl: FHT_INVALID_HANDLE,
            ldevid_tbs_size: 0,
            fmcalias_tbs_size: 0,
            rtalias_tbs_size: 0,
            reserved: [0u8; 122],
            ldevid_tbs_addr: 0,
            fmcalias_tbs_addr: 0,
            pcr_log_addr: 0,
            pcr_log_index: 0,
            fuse_log_addr: 0,
            rt_dice_sign: Ecc384Signature::default(),
            rt_dice_pub_key: Ecc384PubKey::default(),
            idev_dice_pub_key: Ecc384PubKey::default(),
            rom_info_addr: RomAddr::new(FHT_INVALID_ADDRESS),
        }
    }
}

/// Print the Firmware Handoff Table.
pub fn print_fht(fht: &FirmwareHandoffTable) {
    crate::cprintln!("Firmware Handoff Table");
    crate::cprintln!("----------------------");
    crate::cprintln!("FHT Marker: 0x{:08x}", fht.fht_marker);
    crate::cprintln!("FHT Major Version: {}", fht.fht_major_ver);
    crate::cprintln!("FHT Minor Version: {}", fht.fht_minor_ver);
    crate::cprintln!("Manifest Load Address: 0x{:08x}", fht.manifest_load_addr);
    crate::cprintln!(
        "FIPS FW Load Address: 0x{:08x}",
        fht.fips_fw_load_addr_hdl.0
    );
    crate::cprintln!(
        "Runtime FW Entry Point: 0x{:08x}",
        fht.rt_fw_entry_point_hdl.0
    );
    crate::cprintln!("FMC TCI DV Handle: 0x{:08x}", fht.fmc_tci_dv_hdl.0);
    crate::cprintln!("FMC CDI KV Handle: 0x{:08x}", fht.fmc_cdi_kv_hdl.0);
    crate::cprintln!(
        "FMC Private Key KV Handle: 0x{:08x}",
        fht.fmc_priv_key_kv_hdl.0
    );
    crate::cprintln!(
        "FMC Public Key X DV Handle: 0x{:08x}",
        fht.fmc_pub_key_x_dv_hdl.0
    );
    crate::cprintln!(
        "FMC Public Key Y DV Handle: 0x{:08x}",
        fht.fmc_pub_key_y_dv_hdl.0
    );
    crate::cprintln!(
        "FMC Certificate Signature R DV Handle: 0x{:08x}",
        fht.fmc_cert_sig_r_dv_hdl.0
    );
    crate::cprintln!(
        "FMC Certificate Signature S DV Handle: 0x{:08x}",
        fht.fmc_cert_sig_s_dv_hdl.0
    );
    crate::cprintln!("FMC SVN DV Handle: 0x{:08x}", fht.fmc_svn_dv_hdl.0);
    crate::cprintln!("RT TCI DV Handle: 0x{:08x}", fht.rt_tci_dv_hdl.0);
    crate::cprintln!("RT CDI KV Handle: 0x{:08x}", fht.rt_cdi_kv_hdl.0);
    crate::cprintln!(
        "RT Private Key KV Handle: 0x{:08x}",
        fht.rt_priv_key_kv_hdl.0
    );
    crate::cprintln!("RT SVN DV Handle: 0x{:08x}", fht.rt_svn_dv_hdl.0);
    crate::cprintln!("RT Min SVN DV Handle: 0x{:08x}", fht.rt_min_svn_dv_hdl.0);

    crate::cprintln!("LdevId TBS Address: 0x{:08x}", fht.ldevid_tbs_addr);
    crate::cprintln!("LdevId TBS Size: {} bytes", fht.ldevid_tbs_size);
    crate::cprintln!("FmcAlias TBS Address: 0x{:08x}", fht.fmcalias_tbs_addr);
    crate::cprintln!("FmcAlias TBS Size: {} bytes", fht.fmcalias_tbs_size);
    crate::cprintln!("RtAlias TBS Size: {} bytes", fht.rtalias_tbs_size);
    crate::cprintln!("PCR log Address: 0x{:08x}", fht.pcr_log_addr);
    crate::cprintln!("Fuse log Address: 0x{:08x}", fht.fuse_log_addr);
}

impl FirmwareHandoffTable {
    /// Perform valdity check of the table's data.
    /// The fields below should have been populated by ROM with
    /// valid data before it transfers control to mutable code.
    /// This function can only be called from non test case environment
    /// as this function accesses the registers to get the reset_reason.
    pub fn is_valid(&self) -> bool {
        let reset_reason = soc_ifc::reset_reason();

        let mut valid = self.fht_marker == FHT_MARKER
            && self.fmc_cdi_kv_hdl != FHT_INVALID_HANDLE
            && self.manifest_load_addr != FHT_INVALID_ADDRESS
            && self.fmc_pub_key_x_dv_hdl != FHT_INVALID_HANDLE
            && self.fmc_pub_key_y_dv_hdl != FHT_INVALID_HANDLE
            && self.fmc_cert_sig_r_dv_hdl != FHT_INVALID_HANDLE
            && self.fmc_cert_sig_s_dv_hdl != FHT_INVALID_HANDLE
            && self.rt_tci_dv_hdl != FHT_INVALID_HANDLE
            && self.rt_fw_entry_point_hdl != FHT_INVALID_HANDLE
            // This is for Gen1 POR.
            && self.fips_fw_load_addr_hdl == FHT_INVALID_HANDLE
            && self.ldevid_tbs_addr != 0
            && self.fmcalias_tbs_addr != 0
            && self.pcr_log_addr != 0
            && self.fuse_log_addr != 0
            && self.rom_info_addr.is_valid();

        if valid
            && reset_reason == ResetReason::ColdReset
            && (self.ldevid_tbs_size == 0 || self.fmcalias_tbs_size == 0)
        {
            valid = false;
        }

        valid
    }

    /// Load FHT from its fixed address and perform validity check of
    /// its data.
    ///
    /// # Safety
    ///
    /// This function must not be called while any references returned from
    /// PersistentDataAccessor are still around. Prefer to use
    /// PersistentDataAccessor over this function.
    pub unsafe fn try_load() -> Option<FirmwareHandoffTable> {
        let slice = unsafe {
            let ptr = FHT_ORG as *mut u32;
            core::slice::from_raw_parts_mut(
                ptr,
                core::mem::size_of::<FirmwareHandoffTable>() / core::mem::size_of::<u32>(),
            )
        };

        let fht = FirmwareHandoffTable::read_from(slice.as_bytes()).unwrap();

        if fht.is_valid() {
            print_fht(&fht);
            return Some(fht);
        }
        None
    }

    /// # Safety
    ///
    /// This function must not be called while any references returned from
    /// PersistentDataAccessor are still around. Prefer to use
    /// PersistentDataAccessor over this function.
    pub unsafe fn save(fht: &FirmwareHandoffTable) {
        let slice = unsafe {
            let ptr = FHT_ORG as *mut u8;
            crate::cprintln!("[fht] Saving FHT @ 0x{:08X}", ptr as u32);
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<FirmwareHandoffTable>())
        };
        slice.copy_from_slice(fht.as_bytes());
    }
}
/// Report a non fatal firmware error and halt.
#[allow(clippy::empty_loop)]
pub fn report_handoff_error_and_halt(msg: &str, code: u32) -> ! {
    crate::cprintln!("Handoff Error: {} 0x{:08X}", msg, code);
    report_fw_error_non_fatal(code);
    loop {}
}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;
    use core::mem;
    const FHT_SIZE: usize = 512;
    const KEY_ID_FMC_PRIV_KEY: KeyId = KeyId::KeyId5;

    fn rt_tci_store() -> HandOffDataHandle {
        HandOffDataHandle::from(DataStore::DataVaultNonSticky48(WarmResetEntry48::RtTci))
    }

    fn fmc_priv_key_store() -> HandOffDataHandle {
        HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_FMC_PRIV_KEY as u32)
    }

    fn fmc_priv_key(fht: &FirmwareHandoffTable) -> KeyId {
        let ds: DataStore = fht.fmc_priv_key_kv_hdl.try_into().unwrap();

        match ds {
            DataStore::KeyVaultSlot(key_id) => key_id,
            _ => panic!("Invalid FMC private key store"),
        }
    }

    #[test]
    fn test_fht_is_valid() {
        let fht = crate::hand_off::FirmwareHandoffTable::default();

        let valid = fht.fht_marker == FHT_MARKER
            && fht.fmc_cdi_kv_hdl != FHT_INVALID_HANDLE
            && fht.manifest_load_addr != FHT_INVALID_ADDRESS
            && fht.fmc_pub_key_x_dv_hdl != FHT_INVALID_HANDLE
            && fht.fmc_pub_key_y_dv_hdl != FHT_INVALID_HANDLE
            && fht.fmc_cert_sig_r_dv_hdl != FHT_INVALID_HANDLE
            && fht.fmc_cert_sig_s_dv_hdl != FHT_INVALID_HANDLE
            && fht.rt_tci_dv_hdl != FHT_INVALID_HANDLE
            && fht.rt_fw_entry_point_hdl != FHT_INVALID_HANDLE
            // This is for Gen1 POR.
            && fht.fips_fw_load_addr_hdl == FHT_INVALID_HANDLE
            && fht.ldevid_tbs_size == 0
            && fht.fmcalias_tbs_size == 0
            && fht.rtalias_tbs_size == 0
            && fht.ldevid_tbs_addr != 0
            && fht.fmcalias_tbs_addr != 0
            && fht.pcr_log_addr != 0
            && fht.fuse_log_addr != 0;

        assert!(!valid);
        assert_eq!(FHT_SIZE, mem::size_of::<FirmwareHandoffTable>());
    }

    #[test]
    fn test_dv_nonsticky_384bit_set() {
        let fht = crate::hand_off::FirmwareHandoffTable {
            rt_tci_dv_hdl: rt_tci_store(),
            ..Default::default()
        };
        assert_eq!(fht.rt_tci_dv_hdl.vault(), Vault::DataVault as u32);
        assert_eq!(
            fht.rt_tci_dv_hdl.reg_type(),
            DataVaultRegister::NonSticky384BitReg as u32
        );
    }

    #[test]
    fn test_fmc_priv_key_store() {
        let fht = crate::hand_off::FirmwareHandoffTable {
            fmc_priv_key_kv_hdl: fmc_priv_key_store(),
            ..Default::default()
        };
        // Check that the key is stored in the KeyVault.
        assert_eq!(fht.fmc_priv_key_kv_hdl.vault(), Vault::KeyVault as u32);
        // Check the key slot is correct
        assert_eq!(
            fht.fmc_priv_key_kv_hdl.reg_num(),
            KEY_ID_FMC_PRIV_KEY.into()
        );

        assert_eq!(fmc_priv_key(&fht), KEY_ID_FMC_PRIV_KEY);
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    data_vault.rs

Abstract:

    File contains API for the Data Vault registers.

--*/

use caliptra_registers::dv::DvReg;

use crate::{Array4x12, Ecc384PubKey, Ecc384Signature};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdResetEntry48 {
    LDevDiceSigR = 0,
    LDevDiceSigS = 1,
    LDevDicePubKeyX = 2,
    LDevDicePubKeyY = 3,
    FmcDiceSigR = 4,
    FmcDiceSigS = 5,
    FmcPubKeyX = 6,
    FmcPubKeyY = 7,
    FmcTci = 8,
    OwnerPubKeyHash = 9,
}

impl TryFrom<u8> for ColdResetEntry48 {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ColdResetEntry48::LDevDiceSigR),
            1 => Ok(ColdResetEntry48::LDevDiceSigS),
            2 => Ok(ColdResetEntry48::LDevDicePubKeyX),
            3 => Ok(ColdResetEntry48::LDevDicePubKeyY),
            4 => Ok(ColdResetEntry48::FmcDiceSigR),
            5 => Ok(ColdResetEntry48::FmcDiceSigS),
            6 => Ok(ColdResetEntry48::FmcPubKeyX),
            7 => Ok(ColdResetEntry48::FmcPubKeyY),
            8 => Ok(ColdResetEntry48::FmcTci),
            9 => Ok(ColdResetEntry48::OwnerPubKeyHash),
            _ => Err(()),
        }
    }
}

impl From<ColdResetEntry48> for u8 {
    fn from(value: ColdResetEntry48) -> Self {
        value as Self
    }
}

impl From<ColdResetEntry48> for u32 {
    fn from(value: ColdResetEntry48) -> Self {
        value as Self
    }
}

impl From<ColdResetEntry48> for usize {
    fn from(value: ColdResetEntry48) -> Self {
        value as Self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdResetEntry4 {
    FmcSvn = 0,
    RomColdBootStatus = 1,
    FmcEntryPoint = 2,
    EccVendorPubKeyIndex = 3,
    LmsVendorPubKeyIndex = 4,
}

impl TryFrom<u8> for ColdResetEntry4 {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::FmcSvn),
            2 => Ok(Self::FmcEntryPoint),
            3 => Ok(Self::EccVendorPubKeyIndex),
            4 => Ok(Self::LmsVendorPubKeyIndex),
            _ => Err(()),
        }
    }
}

impl From<ColdResetEntry4> for u8 {
    fn from(value: ColdResetEntry4) -> Self {
        value as Self
    }
}

impl From<ColdResetEntry4> for u32 {
    fn from(value: ColdResetEntry4) -> Self {
        value as Self
    }
}

impl From<ColdResetEntry4> for usize {
    fn from(value: ColdResetEntry4) -> Self {
        value as Self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmResetEntry48 {
    RtTci = 0,
}

impl From<WarmResetEntry48> for u8 {
    fn from(value: WarmResetEntry48) -> Self {
        value as Self
    }
}

impl From<WarmResetEntry48> for u32 {
    fn from(value: WarmResetEntry48) -> Self {
        value as Self
    }
}

impl From<WarmResetEntry48> for usize {
    fn from(value: WarmResetEntry48) -> Self {
        value as Self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmResetEntry4 {
    RtSvn = 0,
    RtEntryPoint = 1,
    ManifestAddr = 2,
    RtMinSvn = 3,
    RomUpdateResetStatus = 4,
}

impl From<WarmResetEntry4> for u8 {
    fn from(value: WarmResetEntry4) -> Self {
        value as Self
    }
}

impl From<WarmResetEntry4> for u32 {
    fn from(value: WarmResetEntry4) -> Self {
        value as Self
    }
}

impl From<WarmResetEntry4> for usize {
    fn from(value: WarmResetEntry4) -> Self {
        value as Self
    }
}

impl TryFrom<u8> for WarmResetEntry4 {
    type Error = ();
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
            0 => Ok(Self::RtSvn),
            1 => Ok(Self::RtEntryPoint),
            2 => Ok(Self::ManifestAddr),
            3 => Ok(Self::RtMinSvn),
            _ => Err(()),
        }
    }
}

impl TryFrom<u8> for WarmResetEntry48 {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::RtTci),
            _ => Err(()),
        }
    }
}

pub struct DataVault {
    dv: DvReg,
}

impl DataVault {
    pub fn new(dv: DvReg) -> Self {
        Self { dv }
    }
    /// Set the ldev dice signature.
    ///
    /// # Arguments
    /// * `sig` - ldev dice signature
    ///
    pub fn set_ldev_dice_signature(&mut self, sig: &Ecc384Signature) {
        self.write_lock_cold_reset_entry48(ColdResetEntry48::LDevDiceSigR, &sig.r);
        self.write_lock_cold_reset_entry48(ColdResetEntry48::LDevDiceSigS, &sig.s);
    }

    /// Get the ldev dice signature.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     ldev dice signature  
    ///
    pub fn ldev_dice_signature(&self) -> Ecc384Signature {
        Ecc384Signature {
            r: self.read_cold_reset_entry48(ColdResetEntry48::LDevDiceSigR),
            s: self.read_cold_reset_entry48(ColdResetEntry48::LDevDiceSigS),
        }
    }

    /// Set the ldev dice public key.
    ///
    /// # Arguments
    /// * `pub_key` - ldev dice public key
    ///
    pub fn set_ldev_dice_pub_key(&mut self, pub_key: &Ecc384PubKey) {
        self.write_lock_cold_reset_entry48(ColdResetEntry48::LDevDicePubKeyX, &pub_key.x);
        self.write_lock_cold_reset_entry48(ColdResetEntry48::LDevDicePubKeyY, &pub_key.y);
    }

    /// Get the ldev dice public key.
    ///
    /// # Returns
    /// * ldev dice public key
    ///
    pub fn ldev_dice_pub_key(&self) -> Ecc384PubKey {
        Ecc384PubKey {
            x: self.read_cold_reset_entry48(ColdResetEntry48::LDevDicePubKeyX),
            y: self.read_cold_reset_entry48(ColdResetEntry48::LDevDicePubKeyY),
        }
    }

    /// Set the fmc dice signature.
    ///
    /// # Arguments
    /// * `sig` - fmc dice signature
    ///
    pub fn set_fmc_dice_signature(&mut self, sig: &Ecc384Signature) {
        self.write_lock_cold_reset_entry48(ColdResetEntry48::FmcDiceSigR, &sig.r);
        self.write_lock_cold_reset_entry48(ColdResetEntry48::FmcDiceSigS, &sig.s);
    }

    /// Get the fmc dice signature.
    ///
    /// # Returns
    /// * fmc dice signature
    ///
    pub fn fmc_dice_signature(&self) -> Ecc384Signature {
        Ecc384Signature {
            r: self.read_cold_reset_entry48(ColdResetEntry48::FmcDiceSigR),
            s: self.read_cold_reset_entry48(ColdResetEntry48::FmcDiceSigS),
        }
    }

    /// Set the fmc public key.
    ///
    /// # Arguments
    /// * `pub_key` - fmc public key
    ///
    pub fn set_fmc_pub_key(&mut self, pub_key: &Ecc384PubKey) {
        self.write_lock_cold_reset_entry48(ColdResetEntry48::FmcPubKeyX, &pub_key.x);
        self.write_lock_cold_reset_entry48(ColdResetEntry48::FmcPubKeyY, &pub_key.y);
    }

    /// Get the fmc public key.
    ///
    /// # Returns
    /// * fmc public key
    ///
    pub fn fmc_pub_key(&self) -> Ecc384PubKey {
        Ecc384PubKey {
            x: self.read_cold_reset_entry48(ColdResetEntry48::FmcPubKeyX),
            y: self.read_cold_reset_entry48(ColdResetEntry48::FmcPubKeyY),
        }
    }

    /// Get the fmc tcb component identifier.
    ///
    /// # Returns
    /// * fmc tcb component identifier
    ///
    pub fn fmc_tci(&self) -> Array4x12 {
        self.read_cold_reset_entry48(ColdResetEntry48::FmcTci)
    }

    /// Get the owner public key hash
    ///
    /// # Returns
    ///
    /// * `Array4x12` - Owner public key hash
    ///
    pub fn owner_pk_hash(&self) -> Array4x12 {
        self.read_cold_reset_entry48(ColdResetEntry48::OwnerPubKeyHash)
    }

    /// Get the fmc security version number.
    ///
    /// # Returns
    /// * fmc security version number
    ///
    pub fn fmc_svn(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::FmcSvn)
    }

    /// Get the fmc entry.
    ///
    /// # Returns
    ///
    /// * fmc entry point
    pub fn fmc_entry_point(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint)
    }

    /// Get the Ecc vendor public key index used for image verification.
    ///
    /// # Returns
    ///
    /// * `u32` - Vendor public key index
    pub fn ecc_vendor_pk_index(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::EccVendorPubKeyIndex)
    }

    /// Get the Lms vendor public key index used for image verification.
    ///
    /// # Returns
    ///
    /// * `u32` - Vendor public key index
    pub fn lms_vendor_pk_index(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::LmsVendorPubKeyIndex)
    }

    /// Get the rom cold boot status.
    ///
    /// # Returns
    ///
    /// * `u32` - Rom Cold Boot Status
    pub fn rom_cold_boot_status(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::RomColdBootStatus)
    }

    /// Get the rom update reset status.
    ///
    /// # Returns
    ///
    /// * `u32` - Rom Update Reset Status
    pub fn rom_update_reset_status(&self) -> u32 {
        self.read_warm_reset_entry4(WarmResetEntry4::RomUpdateResetStatus)
    }

    /// Get the rt tcb component identifier.
    ///
    /// # Returns
    /// * rt tcb component identifier
    ///
    pub fn rt_tci(&self) -> Array4x12 {
        self.read_warm_reset_entry48(WarmResetEntry48::RtTci)
    }

    /// Get the rt security version number.
    ///
    /// # Returns
    /// * rt security version number
    ///
    pub fn rt_svn(&self) -> u32 {
        self.read_warm_reset_entry4(WarmResetEntry4::RtSvn)
    }

    /// Get the rt minimum security version number.
    ///
    /// # Returns
    /// * rt minimum security version number
    ///
    pub fn rt_min_svn(&self) -> u32 {
        self.read_warm_reset_entry4(WarmResetEntry4::RtMinSvn)
    }

    /// Get the rt entry.
    ///
    /// # Returns
    ///
    /// * rt entry point
    pub fn rt_entry_point(&self) -> u32 {
        self.read_warm_reset_entry4(WarmResetEntry4::RtEntryPoint)
    }

    /// Get the manifest address.
    ///
    /// # Returns
    ///
    /// * manifest address
    pub fn manifest_addr(&self) -> u32 {
        self.read_warm_reset_entry4(WarmResetEntry4::ManifestAddr)
    }

    /// Read the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    ///
    /// # Returns
    ///    cold reset entry value  
    ///
    pub fn read_cold_reset_entry48(&self, entry: ColdResetEntry48) -> Array4x12 {
        let dv = self.dv.regs();
        Array4x12::read_from_reg(dv.sticky_data_vault_entry().at(entry.into()))
    }

    /// Write and lock the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    /// * `value` - cold reset entry value
    ///
    fn write_lock_cold_reset_entry48(&mut self, entry: ColdResetEntry48, value: &Array4x12) {
        self.write_cold_reset_entry48(entry, value);
        self.lock_cold_reset_entry48(entry);
    }

    /// Write the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    /// * `value` - cold reset entry value
    ///
    pub fn write_cold_reset_entry48(&mut self, entry: ColdResetEntry48, value: &Array4x12) {
        let dv = self.dv.regs_mut();
        value.write_to_reg(dv.sticky_data_vault_entry().at(entry.into()));
    }

    /// Lock the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    ///
    pub fn lock_cold_reset_entry48(&mut self, entry: ColdResetEntry48) {
        let dv = self.dv.regs_mut();
        dv.sticky_data_vault_ctrl()
            .at(entry.into())
            .write(|w| w.lock_entry(true));
    }

    /// Read the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    ///
    /// # Returns
    ///    warm reset entry value  
    ///
    pub fn read_warm_reset_entry48(&self, entry: WarmResetEntry48) -> Array4x12 {
        let dv = self.dv.regs();
        Array4x12::read_from_reg(dv.data_vault_entry().at(entry.into()))
    }

    /// Write the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    /// * `value` - warm reset entry value
    ///
    pub fn write_warm_reset_entry48(&mut self, entry: WarmResetEntry48, value: &Array4x12) {
        let dv = self.dv.regs_mut();
        value.write_to_reg(dv.data_vault_entry().at(entry.into()));
    }

    /// Lock the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    ///
    pub fn lock_warm_reset_entry48(&mut self, entry: WarmResetEntry48) {
        let dv = self.dv.regs_mut();
        dv.data_vault_ctrl()
            .at(entry.into())
            .write(|w| w.lock_entry(true));
    }

    /// Read the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    ///
    /// # Returns
    ///    cold reset entry value  
    ///
    pub fn read_cold_reset_entry4(&self, entry: ColdResetEntry4) -> u32 {
        let dv = self.dv.regs();
        dv.sticky_lockable_scratch_reg().at(entry.into()).read()
    }

    /// Write and lock the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    /// * `value` - cold reset entry value
    ///
    pub fn write_lock_cold_reset_entry4(&mut self, entry: ColdResetEntry4, value: u32) {
        self.write_cold_reset_entry4(entry, value);
        self.lock_cold_reset_entry4(entry);
    }

    /// Write the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    /// * `value` - cold reset entry value
    ///
    pub fn write_cold_reset_entry4(&mut self, entry: ColdResetEntry4, value: u32) {
        let dv = self.dv.regs_mut();
        dv.sticky_lockable_scratch_reg()
            .at(entry.into())
            .write(|_| value);
    }

    /// Lock the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    ///
    pub fn lock_cold_reset_entry4(&mut self, entry: ColdResetEntry4) {
        let dv = self.dv.regs_mut();
        dv.sticky_lockable_scratch_reg_ctrl()
            .at(entry.into())
            .write(|w| w.lock_entry(true));
    }

    /// Read the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    ///
    /// # Returns
    ///    warm reset entry value  
    ///
    pub fn read_warm_reset_entry4(&self, entry: WarmResetEntry4) -> u32 {
        let dv = self.dv.regs();
        dv.lockable_scratch_reg().at(entry.into()).read()
    }

    /// Write and lock the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    /// * `value` - warm reset entry value
    pub fn write_lock_warm_reset_entry4(&mut self, entry: WarmResetEntry4, value: u32) {
        self.write_warm_reset_entry4(entry, value);
        self.lock_warm_reset_entry4(entry);
    }

    /// Write the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    /// * `value` - warm reset entry value
    pub fn write_warm_reset_entry4(&mut self, entry: WarmResetEntry4, value: u32) {
        let dv = self.dv.regs_mut();
        dv.lockable_scratch_reg().at(entry.into()).write(|_| value);
    }

    /// Lock the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    pub fn lock_warm_reset_entry4(&mut self, entry: WarmResetEntry4) {
        let dv = self.dv.regs_mut();
        dv.lockable_scratch_reg_ctrl()
            .at(entry.into())
            .write(|w| w.lock_entry(true));
    }
}

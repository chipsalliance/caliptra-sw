/*++

Licensed under the Apache-2.0 license.

File Name:

    data_vault.rs

Abstract:

    File contains API for the Data Vault registers.

--*/

use caliptra_registers::dv;

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

impl From<ColdResetEntry48> for u8 {
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
    FmcLoadAddr = 1,
    FmcEntryPoint = 2,
    VendorPubKeyIndex = 3,
}

impl From<ColdResetEntry4> for u8 {
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

impl From<WarmResetEntry48> for usize {
    fn from(value: WarmResetEntry48) -> Self {
        value as Self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmResetEntry4 {
    RtSvn = 0,
    RtLoadAddr = 1,
    RtEntryPoint = 2,
    ManifestAddr = 3,
}

impl From<WarmResetEntry4> for u8 {
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
            1 => Ok(Self::RtLoadAddr),
            2 => Ok(Self::RtEntryPoint),
            3 => Ok(Self::ManifestAddr),
            _ => Err(()),
        }
    }
}

#[derive(Default, Debug)]
pub struct DataVault {}

impl DataVault {
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

    /// Set the fmc tcb component identifier.
    ///
    /// # Arguments
    /// * `tci` - fmc tcb component identifier
    ///
    pub fn set_fmc_tci(&mut self, tci: &Array4x12) {
        self.write_lock_cold_reset_entry48(ColdResetEntry48::FmcTci, tci);
    }

    /// Get the fmc tcb component identifier.
    ///
    /// # Returns
    /// * fmc tcb component identifier
    ///
    pub fn fmc_tci(&self) -> Array4x12 {
        self.read_cold_reset_entry48(ColdResetEntry48::FmcTci)
    }

    /// Set the owner public key hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - Owner public key hash
    ///
    pub fn set_owner_pk_hash(&mut self, hash: &Array4x12) {
        self.write_lock_cold_reset_entry48(ColdResetEntry48::OwnerPubKeyHash, hash);
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

    /// Set the fmc security version number.
    ///
    /// # Arguments
    /// * `svn` - fmc security version number
    ///
    pub fn set_fmc_svn(&mut self, svn: u32) {
        self.write_lock_cold_reset_entry4(ColdResetEntry4::FmcSvn, svn);
    }

    /// Get the fmc security version number.
    ///
    /// # Returns
    /// * fmc security version number
    ///
    pub fn fmc_svn(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::FmcSvn)
    }

    /// Set the fmc load address.
    ///
    /// # Arguments
    ///
    /// * `load_addr` - fmc load address
    pub fn set_fmc_load_addr(&mut self, load_addr: u32) {
        self.write_lock_cold_reset_entry4(ColdResetEntry4::FmcLoadAddr, load_addr);
    }

    /// Get the fmc load address.
    ///
    /// # Returns
    ///
    /// * fmc load address
    pub fn fmc_load_addr(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::FmcLoadAddr)
    }

    /// Set the fmc entry point.
    ///
    /// # Arguments
    ///
    /// * `entry_point` - fmc entry point
    pub fn set_fmc_entry_point(&mut self, entry_point: u32) {
        self.write_lock_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint, entry_point);
    }

    /// Get the fmc entry.
    ///
    /// # Returns
    ///
    /// * fmc entry point
    pub fn fmc_entry_point(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint)
    }

    /// Set the vendor public key index used for image verification
    ///
    /// # Arguments
    ///
    /// * `pk_index` - Vendor public key index
    ///
    pub fn set_vendor_pk_index(&mut self, pk_index: u32) {
        self.write_lock_cold_reset_entry4(ColdResetEntry4::VendorPubKeyIndex, pk_index);
    }

    /// Get the vendor public key index used for image verification.
    ///
    /// # Returns
    ///
    /// * `u32` - Vendor public key index
    pub fn vendor_pk_index(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::VendorPubKeyIndex)
    }

    /// Set the rt tcb component identifier.
    ///
    /// # Arguments
    /// * `tci` - rt tcb component identifier
    ///
    pub fn set_rt_tci(&mut self, tci: &Array4x12) {
        self.write_lock_warm_reset_entry48(WarmResetEntry48::RtTci, tci);
    }

    /// Get the rt tcb component identifier.
    ///
    /// # Returns
    /// * rt tcb component identifier
    ///
    pub fn rt_tci(&self) -> Array4x12 {
        self.read_warm_reset_entry48(WarmResetEntry48::RtTci)
    }

    /// Set the rt security version number.
    ///
    /// # Arguments
    /// * `svn` - rt security version number
    ///
    pub fn set_rt_svn(&mut self, svn: u32) {
        self.write_lock_warm_reset_entry4(WarmResetEntry4::RtSvn, svn);
    }

    /// Get the rt security version number.
    ///
    /// # Returns
    /// * rt security version number
    ///
    pub fn rt_svn(&self) -> u32 {
        self.read_warm_reset_entry4(WarmResetEntry4::RtSvn)
    }

    /// Set the rt load address.
    ///
    /// # Arguments
    ///
    /// * `load_addr` - rt load address
    pub fn set_rt_load_addr(&mut self, load_addr: u32) {
        self.write_lock_warm_reset_entry4(WarmResetEntry4::RtLoadAddr, load_addr);
    }

    /// Get the rt load address.
    ///
    /// # Returns
    ///
    /// * rt load address
    pub fn rt_load_addr(&self) -> u32 {
        self.read_warm_reset_entry4(WarmResetEntry4::RtLoadAddr)
    }

    /// Set the rt entry point.
    ///
    /// # Arguments
    ///
    /// * `entry_point` - rt entry point
    pub fn set_rt_entry_point(&mut self, entry_point: u32) {
        self.write_lock_warm_reset_entry4(WarmResetEntry4::RtEntryPoint, entry_point);
    }

    /// Get the rt entry.
    ///
    /// # Returns
    ///
    /// * rt entry point
    pub fn rt_entry_point(&self) -> u32 {
        self.read_warm_reset_entry4(WarmResetEntry4::RtEntryPoint)
    }

    /// Set the manifest address.
    ///
    /// # Arguments
    ///
    /// * `manifest_addr` - manifest address
    pub fn set_manifest_addr(&mut self, manifest_addr: u32) {
        self.write_lock_warm_reset_entry4(WarmResetEntry4::ManifestAddr, manifest_addr);
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
    fn read_cold_reset_entry48(&self, entry: ColdResetEntry48) -> Array4x12 {
        let dv = dv::RegisterBlock::dv_reg();
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
        let dv = dv::RegisterBlock::dv_reg();
        value.write_to_reg(dv.sticky_data_vault_entry().at(entry.into()));
    }

    /// Lock the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    ///
    pub fn lock_cold_reset_entry48(&mut self, entry: ColdResetEntry48) {
        let dv = dv::RegisterBlock::dv_reg();
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
    fn read_warm_reset_entry48(&self, entry: WarmResetEntry48) -> Array4x12 {
        let dv = dv::RegisterBlock::dv_reg();
        Array4x12::read_from_reg(dv.nonsticky_data_vault_entry().at(entry.into()))
    }

    /// Write and lock the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    /// * `value` - warm reset entry value
    ///
    fn write_lock_warm_reset_entry48(&mut self, entry: WarmResetEntry48, value: &Array4x12) {
        self.write_warm_reset_entry48(entry, value);
        self.lock_warm_reset_entry48(entry);
    }

    /// Write the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    /// * `value` - warm reset entry value
    ///
    pub fn write_warm_reset_entry48(&mut self, entry: WarmResetEntry48, value: &Array4x12) {
        let dv = dv::RegisterBlock::dv_reg();
        value.write_to_reg(dv.nonsticky_data_vault_entry().at(entry.into()));
    }

    /// Lock the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    ///
    pub fn lock_warm_reset_entry48(&mut self, entry: WarmResetEntry48) {
        let dv = dv::RegisterBlock::dv_reg();
        dv.non_sticky_data_vault_ctrl()
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
    fn read_cold_reset_entry4(&self, entry: ColdResetEntry4) -> u32 {
        let dv = dv::RegisterBlock::dv_reg();
        dv.sticky_lockable_scratch_reg().at(entry.into()).read()
    }

    /// Write and lock the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    /// * `value` - cold reset entry value
    ///
    fn write_lock_cold_reset_entry4(&mut self, entry: ColdResetEntry4, value: u32) {
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
        let dv = dv::RegisterBlock::dv_reg();
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
        let dv = dv::RegisterBlock::dv_reg();
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
        let dv = dv::RegisterBlock::dv_reg();
        dv.non_sticky_lockable_scratch_reg().at(entry.into()).read()
    }

    /// Write and lock the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    /// * `value` - warm reset entry value
    fn write_lock_warm_reset_entry4(&mut self, entry: WarmResetEntry4, value: u32) {
        self.write_warm_reset_entry4(entry, value);
        self.lock_warm_reset_entry4(entry);
    }

    /// Write the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    /// * `value` - warm reset entry value
    pub fn write_warm_reset_entry4(&mut self, entry: WarmResetEntry4, value: u32) {
        let dv = dv::RegisterBlock::dv_reg();
        dv.non_sticky_lockable_scratch_reg()
            .at(entry.into())
            .write(|_| value);
    }

    /// Lock the warm reset entry.
    ///
    /// # Arguments
    /// * `entry` - warm reset entry
    pub fn lock_warm_reset_entry4(&mut self, entry: WarmResetEntry4) {
        let dv = dv::RegisterBlock::dv_reg();
        dv.non_sticky_lockable_scratch_reg_ctrl()
            .at(entry.into())
            .write(|w| w.lock_entry(true));
    }
}

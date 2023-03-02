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
enum ColdResetEntry48 {
    LDevDiceSigR = 0,
    LDevDiceSigS = 1,
    LDevDicePubKeyX = 2,
    LDevDicePubKeyY = 3,
    FmcDiceSigR = 4,
    FmcDiceSigS = 5,
    FmcPubKeyX = 6,
    FmcPubKeyY = 7,
    AliasFmcTci = 8,
}

impl From<ColdResetEntry48> for usize {
    fn from(value: ColdResetEntry48) -> Self {
        value as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColdResetEntry4 {
    AliasFmcSvn = 0,
}

impl From<ColdResetEntry4> for usize {
    fn from(value: ColdResetEntry4) -> Self {
        value as usize
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
        self.write_lock_cold_reset_entry48(ColdResetEntry48::AliasFmcTci, tci);
    }

    /// Get the fmc tcb component identifier.
    ///
    /// # Returns
    /// * fmc tcb component identifier
    ///
    pub fn fmc_tci(&self) -> Array4x12 {
        self.read_cold_reset_entry48(ColdResetEntry48::AliasFmcTci)
    }

    /// Set the fmc security version number.
    ///
    /// # Arguments
    /// * `svn` - fmc security version number
    ///
    pub fn set_fmc_svn(&mut self, svn: u32) {
        self.write_lock_cold_reset_entry4(ColdResetEntry4::AliasFmcSvn, svn);
    }

    /// Get the fmc security version number.
    ///
    /// # Returns
    /// * fmc security version number
    ///
    pub fn fmc_svn(&self) -> u32 {
        self.read_cold_reset_entry4(ColdResetEntry4::AliasFmcSvn)
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
    fn write_cold_reset_entry48(&mut self, entry: ColdResetEntry48, value: &Array4x12) {
        let dv = dv::RegisterBlock::dv_reg();
        value.write_to_reg(dv.sticky_data_vault_entry().at(entry.into()));
    }

    /// Lock the cold reset entry.
    ///
    /// # Arguments
    /// * `entry` - cold reset entry
    ///
    fn lock_cold_reset_entry48(&mut self, entry: ColdResetEntry48) {
        let dv = dv::RegisterBlock::dv_reg();
        dv.sticky_data_vault_ctrl()
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
    fn write_cold_reset_entry4(&mut self, entry: ColdResetEntry4, value: u32) {
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
    fn lock_cold_reset_entry4(&mut self, entry: ColdResetEntry4) {
        let dv = dv::RegisterBlock::dv_reg();
        dv.sticky_lockable_scratch_reg_ctrl()
            .at(entry.into())
            .write(|w| w.lock_entry(true));
    }
}

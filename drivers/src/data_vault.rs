/*++

Licensed under the Apache-2.0 license.

File Name:

    data_vault.rs

Abstract:

    File contains API for the Data Vault.

--*/

use crate::{Array4x12, Ecc384PubKey, Ecc384Signature, Mldsa87PubKey, Mldsa87Signature};
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

#[repr(C)]
#[derive(FromBytes, AsBytes, Zeroize, Default)]
pub struct ColdResetEntries {
    ldev_dice_ecc_sig: Ecc384Signature,
    ldev_dice_ecc_pk: Ecc384PubKey,
    ldev_dice_mldsa_sig: Mldsa87Signature,
    ldev_dice_mldsa_pk: Mldsa87PubKey,
    fmc_dice_ecc_sig: Ecc384Signature,
    fmc_ecc_pk: Ecc384PubKey,
    fmc_dice_mldsa_sig: Mldsa87Signature,
    fmc_mldsa_pk: Mldsa87PubKey,
    fmc_tci: Array4x12,
    owner_pk_hash: Array4x12,
    fmc_svn: u32,
    rom_cold_boot_status: u32,
    fmc_entry_point: u32,
    vendor_ecc_pk_index: u32,
    vendor_pqc_pk_index: u32,
}

#[repr(C)]
#[derive(FromBytes, AsBytes, Zeroize, Default)]
pub struct WarmResetEntries {
    rt_tci: Array4x12,
    rt_svn: u32,
    rt_entry_point: u32,
    manifest_addr: u32,
    rt_min_svn: u32,
    rom_update_reset_status: u32,
}

#[repr(C)]
#[derive(FromBytes, AsBytes, Zeroize, Default)]
pub struct DataVault {
    cold_reset_entries: ColdResetEntries,
    warm_reset_entries: WarmResetEntries,
}

impl DataVault {
    /// Set the ldev dice ECC signature.
    ///
    /// # Arguments
    /// * `sig` - ldev dice ECC signature
    ///
    pub fn set_ldev_dice_ecc_signature(&mut self, sig: &Ecc384Signature) {
        self.cold_reset_entries.ldev_dice_ecc_sig = *sig;
    }

    /// Get the ldev dice ECC signature.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     ldev dice ECC signature
    ///
    pub fn ldev_dice_ecc_signature(&self) -> Ecc384Signature {
        self.cold_reset_entries.ldev_dice_ecc_sig
    }

    /// Set the ldev dice ECC public key.
    ///
    /// # Arguments
    /// * `pub_key` - ldev dice ECC public key
    ///
    pub fn set_ldev_dice_ecc_pub_key(&mut self, pub_key: &Ecc384PubKey) {
        self.cold_reset_entries.ldev_dice_ecc_pk = *pub_key;
    }

    /// Get the ldev dice ECC public key.
    ///
    /// # Returns
    /// * ldev dice ECC public key
    ///
    pub fn ldev_dice_ecc_pub_key(&self) -> Ecc384PubKey {
        self.cold_reset_entries.ldev_dice_ecc_pk
    }

    /// Set the fmc dice ECC signature.
    ///
    /// # Arguments
    /// * `sig` - fmc dice ECC signature
    ///
    pub fn set_fmc_dice_ecc_signature(&mut self, sig: &Ecc384Signature) {
        self.cold_reset_entries.fmc_dice_ecc_sig = *sig;
    }

    /// Get the fmc dice ECC signature.
    ///
    /// # Returns
    /// * fmc dice ECC signature
    ///
    pub fn fmc_dice_ecc_signature(&self) -> Ecc384Signature {
        self.cold_reset_entries.fmc_dice_ecc_sig
    }

    /// Set the fmc ECC public key.
    ///
    /// # Arguments
    /// * `pub_key` - fmc ECC public key
    ///
    pub fn set_fmc_ecc_pub_key(&mut self, pub_key: &Ecc384PubKey) {
        self.cold_reset_entries.fmc_ecc_pk = *pub_key;
    }

    /// Get the fmc ECC public key.
    ///
    /// # Returns
    /// * fmc ECC public key
    ///
    pub fn fmc_ecc_pub_key(&self) -> Ecc384PubKey {
        self.cold_reset_entries.fmc_ecc_pk
    }

    /// Set the fmc MLDSA public key.
    ///
    /// # Arguments
    /// * `pub_key` - fmc MLDSA public key
    ///
    pub fn set_fmc_mldsa_pub_key(&mut self, pub_key: &Mldsa87PubKey) {
        self.cold_reset_entries.fmc_mldsa_pk = *pub_key;
    }

    /// Get the fmc MLDSA public key.
    ///
    /// # Returns
    /// * fmc MLDSA public key
    ///
    pub fn fmc_mldsa_pub_key(&self) -> Mldsa87PubKey {
        self.cold_reset_entries.fmc_mldsa_pk
    }

    /// Set the fmc tcb component identifier.
    ///
    /// # Arguments
    /// * `tci` - fmc tcb component identifier
    ///
    pub fn set_fmc_tci(&mut self, tci: &Array4x12) {
        self.cold_reset_entries.fmc_tci = *tci;
    }

    /// Get the fmc tcb component identifier.
    ///
    /// # Returns
    /// * fmc tcb component identifier
    ///
    pub fn fmc_tci(&self) -> Array4x12 {
        self.cold_reset_entries.fmc_tci
    }

    /// Set the owner public keys hash
    ///
    /// # Arguments
    ///
    /// * `hash` - Owner public keys hash
    ///
    pub fn set_owner_pk_hash(&mut self, hash: &Array4x12) {
        self.cold_reset_entries.owner_pk_hash = *hash;
    }

    /// Get the owner public keys hash
    ///
    /// # Returns
    ///
    /// * `Array4x12` - Owner public keys hash
    ///
    pub fn owner_pk_hash(&self) -> Array4x12 {
        self.cold_reset_entries.owner_pk_hash
    }

    /// Set the fmc security version number.
    ///
    /// # Arguments
    /// * `svn` - fmc security version number
    ///
    pub fn set_fmc_svn(&mut self, svn: u32) {
        self.cold_reset_entries.fmc_svn = svn;
    }

    /// Get the fmc security version number.
    ///
    /// # Returns
    /// * fmc security version number
    ///
    pub fn fmc_svn(&self) -> u32 {
        self.cold_reset_entries.fmc_svn
    }

    /// Set the fmc entry point.
    ///
    /// # Arguments
    ///
    /// * `entry_point` - fmc entry point
    pub fn set_fmc_entry_point(&mut self, entry_point: u32) {
        self.cold_reset_entries.fmc_entry_point = entry_point;
    }

    /// Get the fmc entry point.
    ///
    /// # Returns
    ///
    /// * fmc entry point
    pub fn fmc_entry_point(&self) -> u32 {
        self.cold_reset_entries.fmc_entry_point
    }

    /// Set the vendor ECC public key index used for image verification.
    ///
    /// # Arguments
    ///
    /// * `index` - Vendor ECC public key index
    pub fn set_vendor_ecc_pk_index(&mut self, index: u32) {
        self.cold_reset_entries.vendor_ecc_pk_index = index;
    }

    /// Get the vendor ECC public key index used for image verification.
    ///
    /// # Returns
    ///
    /// * `u32` - Vendor ECC public key index
    pub fn vendor_ecc_pk_index(&self) -> u32 {
        self.cold_reset_entries.vendor_ecc_pk_index
    }

    /// Set the vendor LMS public key index used for image verification.
    ///
    /// # Arguments
    ///
    /// * `index` - Vendor LMS public key index
    pub fn set_vendor_pqc_pk_index(&mut self, index: u32) {
        self.cold_reset_entries.vendor_pqc_pk_index = index;
    }

    /// Get the PQC (LMS or MLDSA) vendor public key index used for image verification.
    ///
    /// # Returns
    ///
    /// * `u32` - Vendor public key index
    pub fn vendor_pqc_pk_index(&self) -> u32 {
        self.cold_reset_entries.vendor_pqc_pk_index
    }

    /// Set the rom cold boot status.
    ///
    /// # Arguments
    ///
    /// * `status` - Rom Cold Boot Status
    pub fn set_rom_cold_boot_status(&mut self, status: u32) {
        self.cold_reset_entries.rom_cold_boot_status = status;
    }

    /// Get the rom cold boot status.
    ///
    /// # Returns
    ///
    /// * `u32` - Rom Cold Boot Status
    pub fn rom_cold_boot_status(&self) -> u32 {
        self.cold_reset_entries.rom_cold_boot_status
    }

    /// Set the rom update reset status.
    ///
    /// # Arguments
    ///
    /// * `status` - Rom Update Reset Status
    pub fn set_rom_update_reset_status(&mut self, status: u32) {
        self.warm_reset_entries.rom_update_reset_status = status;
    }

    /// Get the rom update reset status.
    ///
    /// # Returns
    ///
    /// * `u32` - Rom Update Reset Status
    pub fn rom_update_reset_status(&self) -> u32 {
        self.warm_reset_entries.rom_update_reset_status
    }

    /// Set the rt tcb component identifier.
    ///
    /// # Arguments
    /// * `tci` - rt tcb component identifier
    ///
    pub fn set_rt_tci(&mut self, tci: &Array4x12) {
        self.warm_reset_entries.rt_tci = *tci;
    }

    /// Get the rt tcb component identifier.
    ///
    /// # Returns
    /// * rt tcb component identifier
    ///
    pub fn rt_tci(&self) -> Array4x12 {
        self.warm_reset_entries.rt_tci
    }

    /// Set the rt security version number.
    ///
    /// # Arguments
    /// * `svn` - rt security version number
    ///
    pub fn set_rt_svn(&mut self, svn: u32) {
        self.warm_reset_entries.rt_svn = svn;
    }

    /// Get the rt security version number.
    ///
    /// # Returns
    /// * rt security version number
    ///
    pub fn rt_svn(&self) -> u32 {
        self.warm_reset_entries.rt_svn
    }

    /// Set the rt minimum security version number.
    ///
    /// # Arguments
    /// * `svn` - rt minimum security version number
    ///
    pub fn set_rt_min_svn(&mut self, svn: u32) {
        self.warm_reset_entries.rt_min_svn = svn;
    }

    /// Get the rt minimum security version number.
    ///
    /// # Returns
    /// * rt minimum security version number
    ///
    pub fn rt_min_svn(&self) -> u32 {
        self.warm_reset_entries.rt_min_svn
    }

    /// Set the rt entry.
    ///
    /// # Arguments
    /// * `entry_point` - rt entry point
    pub fn set_rt_entry_point(&mut self, entry_point: u32) {
        self.warm_reset_entries.rt_entry_point = entry_point;
    }

    /// Get the rt entry.
    ///
    /// # Returns
    ///
    /// * rt entry point
    pub fn rt_entry_point(&self) -> u32 {
        self.warm_reset_entries.rt_entry_point
    }

    /// Set the manifest address.
    ///
    /// # Arguments
    /// * `addr` - manifest address
    pub fn set_manifest_addr(&mut self, addr: u32) {
        self.warm_reset_entries.manifest_addr = addr;
    }

    /// Get the manifest address.
    ///
    /// # Returns
    ///
    /// * manifest address
    pub fn manifest_addr(&self) -> u32 {
        self.warm_reset_entries.manifest_addr
    }
}

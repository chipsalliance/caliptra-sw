/*++

Licensed under the Apache-2.0 license.

File Name:

    key_vault.rs

Abstract:

    File contains API for controlling the Key Vault

--*/

use bitfield::bitfield;

use crate::{caliptra_err_def, CaliptraResult};
use caliptra_registers::kv;

/// Key Identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyId {
    KeyId0 = 0,
    KeyId1 = 1,
    KeyId2 = 2,
    KeyId3 = 3,
    KeyId4 = 4,
    KeyId5 = 5,
    KeyId6 = 6,
    KeyId7 = 7,
    KeyId8 = 8,
    KeyId9 = 9,
    KeyId10 = 10,
    KeyId11 = 11,
    KeyId12 = 12,
    KeyId13 = 13,
    KeyId14 = 14,
    KeyId15 = 15,
    KeyId16 = 16,
    KeyId17 = 17,
    KeyId18 = 18,
    KeyId19 = 19,
    KeyId20 = 20,
    KeyId21 = 21,
    KeyId22 = 22,
    KeyId23 = 23,
    KeyId24 = 24,
    KeyId25 = 25,
    KeyId26 = 26,
    KeyId27 = 27,
    KeyId28 = 28,
    KeyId29 = 29,
    KeyId30 = 30,
    KeyId31 = 31,
}

impl From<KeyId> for u32 {
    /// Converts to this type from the input type.
    fn from(key_id: KeyId) -> Self {
        key_id as Self
    }
}

impl From<KeyId> for usize {
    /// Converts to this type from the input type.
    fn from(key_id: KeyId) -> Self {
        key_id as Self
    }
}

bitfield! {
    /// Key Usage
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    pub struct KeyUsage(u32);

    /// Flag indicating if the key can be used as HMAC key
    pub hmac_key, set_hmac_key: 0;

    /// Flag indicating if the key can be used as HMAC data
    pub hmac_data, set_hmac_data: 1;

    /// Flag indicating if the key can be used as SHA data
    pub sha_data, set_sha_data: 2;

    /// Flag indicating if the key can be used aas ECC Private Key
    pub ecc_private_key, set_ecc_private_key: 3;

    /// Flag indicating if the key can be used aas ECC Key Generation Seed
    pub ecc_key_gen_seed, set_ecc_key_gen_seed: 4;

    /// Flag indicating if the key can be used aas ECC data part of signature
    /// generation and verification process
    pub ecc_data, set_ecc_data:5;
}

caliptra_err_def! {
    KeyVault,
    KeyVaultErr
    {
        // Erase failed due to use lock was set
        EraseUseLockSetFailure = 0x01,

        // Erase failed due to write lock st
        EraseWriteLockSetFailure = 0x02,
    }
}

/// Caliptra Key Vault
#[derive(Default, Debug)]
pub struct KeyVault {}

impl KeyVault {
    /// Erase all the keys in the key vault
    ///
    /// Note: The keys that have "use" or "write" lock set will not be erased
    pub fn erase_all_keys(&mut self) {
        const KEY_IDS: [KeyId; 32] = [
            KeyId::KeyId0,
            KeyId::KeyId1,
            KeyId::KeyId2,
            KeyId::KeyId3,
            KeyId::KeyId4,
            KeyId::KeyId5,
            KeyId::KeyId6,
            KeyId::KeyId7,
            KeyId::KeyId8,
            KeyId::KeyId9,
            KeyId::KeyId10,
            KeyId::KeyId11,
            KeyId::KeyId12,
            KeyId::KeyId13,
            KeyId::KeyId14,
            KeyId::KeyId15,
            KeyId::KeyId16,
            KeyId::KeyId17,
            KeyId::KeyId18,
            KeyId::KeyId19,
            KeyId::KeyId20,
            KeyId::KeyId21,
            KeyId::KeyId22,
            KeyId::KeyId23,
            KeyId::KeyId24,
            KeyId::KeyId25,
            KeyId::KeyId26,
            KeyId::KeyId27,
            KeyId::KeyId28,
            KeyId::KeyId29,
            KeyId::KeyId30,
            KeyId::KeyId31,
        ];

        let kv = kv::RegisterBlock::kv_reg();

        for id in KEY_IDS {
            if !self.key_use_lock(id) && !self.key_write_lock(id) {
                kv.key_ctrl().at(id.into()).write(|w| w.clear(true));
            }
        }
    }

    /// Erase specified key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID to erase
    pub fn erase_key(&mut self, id: KeyId) -> CaliptraResult<()> {
        if self.key_use_lock(id) {
            raise_err!(EraseUseLockSetFailure)
        }

        if self.key_write_lock(id) {
            raise_err!(EraseWriteLockSetFailure)
        }

        let kv = kv::RegisterBlock::kv_reg();
        kv.key_ctrl().at(id.into()).write(|w| w.clear(true));
        Ok(())
    }

    /// Retrieve the write lock status for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    ///
    /// # Returns
    /// * `true` - If the key is write locked
    /// * `false` - If the Key is not write locked
    pub fn key_write_lock(&self, id: KeyId) -> bool {
        let kv = kv::RegisterBlock::kv_reg();
        kv.key_ctrl().at(id.into()).read().lock_wr()
    }

    /// Set the write lock for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    pub fn set_key_write_lock(&mut self, id: KeyId) {
        let kv = kv::RegisterBlock::kv_reg();
        kv.key_ctrl().at(id.into()).write(|w| w.lock_wr(true))
    }

    /// Clear the write lock for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    pub fn clear_key_write_lock(&mut self, id: KeyId) {
        let kv = kv::RegisterBlock::kv_reg();
        kv.key_ctrl().at(id.into()).write(|w| w.lock_wr(false))
    }

    /// Retrieve the use lock status for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    ///
    /// # Returns
    /// * `true` - If the key is use locked
    /// * `false` - If the Key is not use locked
    pub fn key_use_lock(&self, id: KeyId) -> bool {
        let kv = kv::RegisterBlock::kv_reg();
        kv.key_ctrl().at(id.into()).read().lock_use()
    }

    /// Set the use lock for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    pub fn set_key_use_lock(&mut self, id: KeyId) {
        let kv = kv::RegisterBlock::kv_reg();
        kv.key_ctrl().at(id.into()).write(|w| w.lock_use(true))
    }

    /// Clear the use lock for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    pub fn clear_key_use_lock(&mut self, id: KeyId) {
        let kv = kv::RegisterBlock::kv_reg();
        kv.key_ctrl().at(id.into()).write(|w| w.lock_use(false))
    }

    /// Retrieve the Key usage for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    ///
    /// # Returns
    /// * `KeyUsage` - Key Usage
    pub fn key_usage(&self, id: KeyId) -> KeyUsage {
        let kv = kv::RegisterBlock::kv_reg();
        let val = kv.key_ctrl().at(id.into()).read();
        KeyUsage(val.dest_valid())
    }
}

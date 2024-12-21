/*++

Licensed under the Apache-2.0 license.

File Name:

    key_vault.rs

Abstract:

    File contains API for controlling the Key Vault

--*/

use bitfield::bitfield;

use crate::{CaliptraError, CaliptraResult};
use caliptra_registers::kv::KvReg;

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
}

impl TryFrom<u8> for KeyId {
    type Error = ();
    fn try_from(original: u8) -> Result<Self, Self::Error> {
        match original {
            0 => Ok(Self::KeyId0),
            1 => Ok(Self::KeyId1),
            2 => Ok(Self::KeyId2),
            3 => Ok(Self::KeyId3),
            4 => Ok(Self::KeyId4),
            5 => Ok(Self::KeyId5),
            6 => Ok(Self::KeyId6),
            7 => Ok(Self::KeyId7),
            8 => Ok(Self::KeyId8),
            9 => Ok(Self::KeyId9),
            10 => Ok(Self::KeyId10),
            11 => Ok(Self::KeyId11),
            12 => Ok(Self::KeyId12),
            13 => Ok(Self::KeyId13),
            14 => Ok(Self::KeyId14),
            15 => Ok(Self::KeyId15),
            16 => Ok(Self::KeyId16),
            17 => Ok(Self::KeyId17),
            18 => Ok(Self::KeyId18),
            19 => Ok(Self::KeyId19),
            20 => Ok(Self::KeyId20),
            21 => Ok(Self::KeyId21),
            22 => Ok(Self::KeyId22),
            23 => Ok(Self::KeyId23),
            _ => Err(()),
        }
    }
}

impl From<KeyId> for u8 {
    /// Converts to this type from the input type.
    fn from(key_id: KeyId) -> Self {
        key_id as Self
    }
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

    /// Flag indicating if the key can be used as MLDSA Key Generation seed
    pub mldsa_seed, set_mldsa_key_gen_seed: 2;

    /// Flag indicating if the key can be used as ECC Private Key
    pub ecc_private_key, set_ecc_private_key: 3;

    /// Flag indicating if the key can be used as ECC Key Generation Seed
    pub ecc_key_gen_seed, set_ecc_key_gen_seed: 4;

    /// Flag indicating if the key can be used as ECC data part of signature
    /// generation and verification process
    pub ecc_data, set_ecc_data:5;
}

impl KeyUsage {
    pub fn set_hmac_key_en(&mut self) -> KeyUsage {
        self.set_hmac_key(true);
        *self
    }
    pub fn set_hmac_data_en(&mut self) -> KeyUsage {
        self.set_hmac_data(true);
        *self
    }
    pub fn set_mldsa_key_gen_seed_en(&mut self) -> KeyUsage {
        self.set_mldsa_key_gen_seed(true);
        *self
    }
    pub fn set_ecc_private_key_en(&mut self) -> KeyUsage {
        self.set_ecc_private_key(true);
        *self
    }
    pub fn set_ecc_key_gen_seed_en(&mut self) -> KeyUsage {
        self.set_ecc_key_gen_seed(true);
        *self
    }
    pub fn set_ecc_data_en(&mut self) -> KeyUsage {
        self.set_ecc_data(true);
        *self
    }
}

/// Caliptra Key Vault
pub struct KeyVault {
    kv: KvReg,
}

impl KeyVault {
    pub fn new(kv: KvReg) -> Self {
        KeyVault { kv }
    }
    /// Erase all the keys in the key vault
    ///
    /// Note: The keys that have "use" or "write" lock set will not be erased
    pub fn erase_all_keys(&mut self) {
        const KEY_IDS: [KeyId; 24] = [
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
        ];

        for id in KEY_IDS {
            if !self.key_use_lock(id) && !self.key_write_lock(id) {
                let kv = self.kv.regs_mut();
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
            return Err(CaliptraError::DRIVER_KV_ERASE_USE_LOCK_SET_FAILURE);
        }

        if self.key_write_lock(id) {
            return Err(CaliptraError::DRIVER_KV_ERASE_WRITE_LOCK_SET_FAILURE);
        }

        let kv = self.kv.regs_mut();
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
        let kv = self.kv.regs();
        kv.key_ctrl().at(id.into()).read().lock_wr()
    }

    /// Set the write lock for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    pub fn set_key_write_lock(&mut self, id: KeyId) {
        let kv = self.kv.regs_mut();
        kv.key_ctrl().at(id.into()).write(|w| w.lock_wr(true))
    }

    /// Clear the write lock for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    pub fn clear_key_write_lock(&mut self, id: KeyId) {
        let kv = self.kv.regs_mut();
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
    pub fn key_use_lock(&mut self, id: KeyId) -> bool {
        let kv = self.kv.regs_mut();
        kv.key_ctrl().at(id.into()).read().lock_use()
    }

    /// Set the use lock for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    pub fn set_key_use_lock(&mut self, id: KeyId) {
        let kv = self.kv.regs_mut();
        kv.key_ctrl().at(id.into()).write(|w| w.lock_use(true))
    }

    /// Clear the use lock for a key
    ///
    /// # Arguments
    ///
    /// * `id` - Key ID
    pub fn clear_key_use_lock(&mut self, id: KeyId) {
        let kv = self.kv.regs_mut();
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
    pub fn key_usage(&mut self, id: KeyId) -> KeyUsage {
        let kv = self.kv.regs_mut();
        let val = kv.key_ctrl().at(id.into()).read();
        KeyUsage(val.dest_valid())
    }

    /// Erase the key vault
    /// This is useful to call from a fatal-error-handling routine.
    ///
    /// # Safety
    ///
    /// The caller must be certain that the results of any pending cryptographic
    /// operations will not be used after this function is called.
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn zeroize() {
        KeyVault::new(unsafe { KvReg::new() }).erase_all_keys()
    }
}

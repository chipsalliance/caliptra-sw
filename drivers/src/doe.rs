/*++

Licensed under the Apache-2.0 license.

File Name:

    doe.rs

Abstract:

    File contains API for Deobfuscation Engine

--*/

use crate::reg::doe_regs::*;
use crate::slice::CopyFromByteSlice;
use crate::KeyId;
use tock_registers::interfaces::{ReadWriteable, Readable};

/// Initialization Vector size
const DOE_IV_SIZE: usize = 16;

pub enum Doe {}

impl Doe {
    /// Decrypt Unique Device Secret (UDS)
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector
    /// * `key_id` - Key vault key to store the decrypted UDS in
    pub fn decrypt_uds(iv: &[u8; DOE_IV_SIZE], key_id: KeyId) {
        Self::_execute_cmd(CONTROL::CMD::DECRYPT_UDS.value, Some(iv), Some(key_id));
    }

    /// Decrypt Field Entropy
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector
    /// * `key_id` - Key vault key to store the decrypted field entropy in
    pub fn decrypt_field_entropy(iv: &[u8; DOE_IV_SIZE], key_id: KeyId) {
        Self::_execute_cmd(
            CONTROL::CMD::DECRYPT_FIELD_ENTROPY.value,
            Some(iv),
            Some(key_id),
        );
    }

    /// Clear loaded secrets
    ///
    /// This command clears following secrets from the hardware
    /// * Deobfuscation Key
    /// * Encrypted UDS
    /// * Encrypted Field entropy
    pub fn clear_secrets() {
        Self::_execute_cmd(CONTROL::CMD::CLEAR_SECRETS.value, None, None);
    }

    fn _execute_cmd(cmd: u32, iv: Option<&[u8; DOE_IV_SIZE]>, key_id: Option<KeyId>) {
        // Copy the initialization vector
        if let Some(iv) = iv {
            DOE_REGS.iv.copy_from_byte_slice(iv);
        }

        // Program the control register
        if let Some(key_id) = key_id {
            DOE_REGS
                .control
                .modify(CONTROL::CMD.val(cmd) + CONTROL::DEST.val(key_id.into()))
        } else {
            DOE_REGS.control.modify(CONTROL::CMD.val(cmd));
        }

        // Wait for operation to finish
        // [TODO] Remove the if check once the RTL is updated to set the Valid bit for clear command.
        if cmd != CONTROL::CMD::CLEAR_SECRETS.value {
            while !DOE_REGS.status.is_set(STATUS::VALID) {}
        }
    }
}

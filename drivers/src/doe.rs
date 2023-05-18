/*++

Licensed under the Apache-2.0 license.

File Name:

    doe.rs

Abstract:

    File contains API for Deobfuscation Engine

--*/

use crate::{wait, Array4x4, CaliptraResult, KeyId};
use caliptra_registers::doe;

#[derive(Default, Debug)]
pub struct DeobfuscationEngine {}

impl DeobfuscationEngine {
    /// Decrypt Unique Device Secret (UDS)
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector
    /// * `key_id` - Key vault key to store the decrypted UDS in
    pub fn decrypt_uds(&mut self, iv: &Array4x4, key_id: KeyId) -> CaliptraResult<()> {
        let doe = doe::RegisterBlock::doe_reg();

        // Wait for hardware ready
        wait::until(|| doe.status().read().ready());

        // Copy the initialization vector
        iv.write_to_reg(doe.iv());

        // Trigger the command by programming the command and destination
        doe.ctrl()
            .write(|w| w.cmd(|w| w.doe_uds()).dest(key_id.into()));

        // Wait for command to complete
        wait::until(|| doe.status().read().valid());

        Ok(())
    }

    /// Decrypt Field Entropy
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector
    /// * `key_id` - Key vault key to store the decrypted field entropy in
    pub fn decrypt_field_entropy(&mut self, iv: &Array4x4, key_id: KeyId) -> CaliptraResult<()> {
        let doe = doe::RegisterBlock::doe_reg();

        // Wait for hardware ready
        wait::until(|| doe.status().read().ready());

        // Copy the initialization vector
        iv.write_to_reg(doe.iv());

        // Trigger the command by programming the command and destination
        doe.ctrl()
            .write(|w| w.cmd(|w| w.doe_fe()).dest(key_id.into()));

        // Wait for command to complete
        wait::until(|| doe.status().read().valid());

        Ok(())
    }

    /// Clear loaded secrets
    ///
    /// This command clears following secrets from the hardware
    /// * Deobfuscation Key
    /// * Encrypted UDS
    /// * Encrypted Field entropy
    pub fn clear_secrets(&mut self) -> CaliptraResult<()> {
        // Self::_execute_cmd(CONTROL::CMD::CLEAR_SECRETS.value, None, None);
        let doe = doe::RegisterBlock::doe_reg();

        // Wait for hardware ready
        wait::until(|| doe.status().read().ready());

        // Trigger the command by programming the command and destination
        doe.ctrl().write(|w| w.cmd(|w| w.doe_clear_obf_secrets()));

        // Wait for command to complete
        //
        // TODO: Uncomment following once the RTL is updated to set the
        // valid bit for clear command.
        // wait::until(|| doe.status().read().valid());

        Ok(())
    }
}

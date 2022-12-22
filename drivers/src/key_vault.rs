/*++

Licensed under the Apache-2.0 license.

File Name:

    key_vault.rs

Abstract:

    File contains API for KeyVault

--*/

/// Key Identifier
pub enum KeyId {
    KeyId0 = 0,
    KeyId1 = 1,
    KeyId2 = 2,
    KeyId3 = 3,
    KeyId4 = 4,
    KeyId5 = 5,
    KeyId6 = 6,
    KeyId7 = 7,
}

impl From<KeyId> for u32 {
    /// Converts to this type from the input type.
    fn from(key_id: KeyId) -> Self {
        key_id as u32
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    error.rs

Abstract:

    File contains API and macros used by the library for error handling

--*/

/// Caliptra Component
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CaliptraComponent {
    /// Deobfuscation Engine Component
    DeobfuscationEngine = 1,

    /// SHA-256 Component
    Sha256 = 2,

    /// SHA-384 Component
    Sha384 = 3,

    /// HMAC-384 Component
    Hmac384 = 4,

    /// ECC-384 Component
    Ecc384 = 5,

    /// Key Vault
    KeyVault = 6,

    /// PCR Bank
    PcrBank = 7,

    /// Mailbox
    Mailbox = 8,

    /// SHA384 Accelerator
    Sha384Acc = 9,

    /// SHA1
    Sha1 = 10,
}

#[macro_export]
macro_rules! caliptra_err_def {
    ($comp_name:ident, $enum_name: ident { $($field_name: ident = $field_val: literal,)* }) => {

        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub enum $enum_name {
            $($field_name = $field_val,)*
        }

        impl From<$enum_name> for u32 {
            fn from(val: $enum_name) -> Self {
                ((($crate::error::CaliptraComponent::$comp_name) as Self) << 24) | (val as Self)
            }
        }

        #[allow(unused_macros)]
        macro_rules! kv_err {
            ($name: ident, $err_code: literal) => (
                paste::paste! {
                    [<$name>_HwReadyTimeout] = $err_code,
                    [<$name>_HwValidTimeout] = $err_code + 1,
                }
            )
        }

        #[allow(unused_macros)]
        macro_rules! raise_err { ($comp_err: ident) => {
            Err(((($crate::error::CaliptraComponent::$comp_name) as u32) << 24) | ($enum_name::$comp_err as u32))?
        } }

        #[allow(unused_macros)]
        macro_rules! err { ($comp_err: ident) => {
            Result::<(), u32>::Err(((($crate::error::CaliptraComponent::$comp_name) as u32) << 24) | ($enum_name::$comp_err as u32))
        } }

        #[allow(unused_macros)]
        macro_rules! err_u32 { ($comp_err: ident) => {
            ((($crate::error::CalptraComponent::$comp_name) as u32) << 24) | ($enum_name::$comp_err as u32)
        } }
    };
}

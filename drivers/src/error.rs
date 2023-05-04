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

    /// ImageVerifier
    ImageVerifier = 11,

    /// LMS
    Lms = 12,

    /// CSRNG
    Csrng = 13,

    /// Runtime firmware
    /// TODO: Once https://github.com/chipsalliance/caliptra-sw/pull/220 is
    /// merged remove this and use RT error mechanism instead.
    Runtime = 14,
}

#[macro_export]
macro_rules! caliptra_err_def {
    ($comp_name:ident, $enum_name: ident { $($field_name: ident = $field_val: literal,)* }) => {

        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        #[allow(clippy::enum_variant_names)]
        pub enum $enum_name {
            $($field_name = $field_val,)*
        }

        impl From<$enum_name> for core::num::NonZeroU32 {
            fn from(val: $enum_name) -> Self {
                // Panic is impossible as long as the enums don't define zero.
                core::num::NonZeroU32::new(((($crate::error::CaliptraComponent::$comp_name) as u32) << 24) | (val as u32)).unwrap()
            }
        }
        impl From<$enum_name> for u32 {
            fn from(val: $enum_name) -> u32 {
                core::num::NonZeroU32::from(val).into()
            }
        }

        #[allow(unused_macros)]
        macro_rules! raise_err { ($comp_err: ident) => {
            Err(core::num::NonZeroU32::from($enum_name::$comp_err))?
        } }

        #[allow(unused_macros)]
        macro_rules! err { ($comp_err: ident) => {
            Result::<(), u32>::Err(core::num::NonZeroU32::from($enum_name::$comp_err))
        } }

        #[allow(unused_macros)]
        macro_rules! err_u32 { ($comp_err: ident) => {
            core::num::NonZeroU32::from($enum_name::$comp_err)
        } }
    };
}

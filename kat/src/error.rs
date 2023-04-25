/*++

Licensed under the Apache-2.0 license.

File Name:

    error.rs

Abstract:

    File contains enum and macros used by the KAT library for error handling

--*/

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CaliptraKat {
    /// SHA-256 KAT
    Sha256Kat = 0x9001,

    /// SHA-384 KAT
    Sha384Kat = 0x9002,

    /// HMAC-384 KAT
    Hmac384Kat = 0x9003,

    /// ECC-384 KAT
    Ecc384Kat = 0x9004,

    /// SHA384 Accelerator KAT
    Sha384AccKat = 0x9005,

    /// SHA1 KAT
    Sha1Kat = 0x9006,
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
                core::num::NonZeroU32::new(((($crate::error::CaliptraKat::$comp_name) as u32) << 16) | (val as u32)).unwrap()
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

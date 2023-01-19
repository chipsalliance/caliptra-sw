/*++

Licensed under the Apache-2.0 license.

File Name:

    error.rs

Abstract:

    File contains API and macros used by the library for error handling

--*/

/// Caliptra Component
pub enum CptrComponent {
    /// SHA-384 Component
    Sha384 = 1,

    /// SHA-256 Component
    Sha256 = 2,

    Hmac384 = 3,

    Mailbox = 4,

    KeyVault = 5,
}

#[macro_export]
macro_rules! cptr_err_def {
    ($comp_name:ident, $enum_name: ident { $($field_name: ident = $field_val: literal,)* }) => {

        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub enum $enum_name {
            $($field_name = $field_val,)*
        }

        macro_rules! raise_err { ($comp_err: ident) => {
            Err((((crate::error::CptrComponent::$comp_name) as u32) << 24) | ($enum_name::$comp_err as u32))?
        } }

    };
}

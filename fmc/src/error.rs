/*++

Licensed under the Apache-2.0 license.

File Name:

    error.rs

Abstract:

    File contains API and macros used by the ROM for error handling

--*/

/// Caliptra Component
pub enum FmcComponent {
    /// Global Error
    Global = 0x11,
}

#[macro_export]
macro_rules! fmc_err_def {
    ($comp_name:ident, $enum_name: ident { $($field_name: ident = $field_val: literal,)* }) => {

        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        #[allow(clippy::enum_variant_names)]
        pub enum $enum_name {
            $($field_name = $field_val,)*
        }

        impl From<$enum_name> for u32 {
            fn from(val: $enum_name) -> Self {
                ((($crate::error::FmcComponent::$comp_name) as Self) << 16) | (val as Self)
            }
        }

        #[allow(unused_macros)]
        macro_rules! raise_err { ($comp_err: ident) => {
            Err(((($crate::error::FmcComponent::$comp_name) as u32) << 16) | ($enum_name::$comp_err as u32))?
        } }

        #[allow(unused_macros)]
        macro_rules! err { ($comp_err: ident) => {
            Result::<(), u32>::Err(((($crate::error::FmcComponent::$comp_name) as u32) << 16) | ($enum_name::$comp_err as u32))
        } }

        #[allow(unused_macros)]
        macro_rules! err_u32 { ($comp_err: ident) => {
            ((($crate::error::FmcComponent::$comp_name) as u32) << 16) | ($enum_name::$comp_err as u32)
        } }
    };
}

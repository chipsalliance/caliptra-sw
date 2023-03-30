/*++

Licensed under the Apache-2.0 license.

File Name:

    error.rs

Abstract:

    File contains API and macros used by the ROM for error handling

--*/

/// Caliptra Component
pub enum RomComponent {
    /// Initial Device ID Layer
    InitDevId = 0x100,

    /// Local Device ID Layer
    LocalDevId = 0x101,

    /// FMC Alias Layer
    FmcAlias = 0x102,

    /// Update Reset Errors
    UpdateReset = 0x103,

    /// Global Error
    Global = 0x104,
}

#[macro_export]
macro_rules! rom_err_def {
    ($comp_name:ident, $enum_name: ident { $($field_name: ident = $field_val: literal,)* }) => {

        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        #[allow(clippy::enum_variant_names)]
        pub enum $enum_name {
            $($field_name = $field_val,)*
        }

        impl From<$enum_name> for u32 {
            fn from(val: $enum_name) -> Self {
                ((($crate::error::RomComponent::$comp_name) as Self) << 24) | (val as Self)
            }
        }

        #[allow(unused_macros)]
        macro_rules! raise_err { ($comp_err: ident) => {
            Err(((($crate::error::RomComponent::$comp_name) as u32) << 24) | ($enum_name::$comp_err as u32))?
        } }

        #[allow(unused_macros)]
        macro_rules! err { ($comp_err: ident) => {
            Result::<(), u32>::Err(((($crate::error::RomComponent::$comp_name) as u32) << 24) | ($enum_name::$comp_err as u32))
        } }

        #[allow(unused_macros)]
        macro_rules! err_u32 { ($comp_err: ident) => {
            ((($crate::error::RomComponent::$comp_name) as u32) << 24) | ($enum_name::$comp_err as u32)
        } }
    };
}

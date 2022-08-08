/*++

Licensed under the Apache-2.0 license.

File Name:

    macros.rs

Abstract:

    Macros used by the project

--*/

#[macro_export]
macro_rules! emu_enum {
    (
        $(#[$($enum_attrs:tt)*])*
        $vis:vis $enum_name:ident;
        $type:ty;
        {
            $(
                $(#[$($attrs:tt)*])*
                $name:ident = $value:literal,
            )*
        };
        $invalid:ident
    ) => {
        $(#[$($enum_attrs)*])*
        $vis enum $enum_name {
            $(
                $(#[$($attrs)*])*
                $name = $value,
            )*
            $invalid
        }

        impl From<$enum_name> for $type {
            fn from(val: $enum_name) -> $type {
                match val {
                    $($enum_name::$name => $value,)*
                    $enum_name::$invalid => panic!(),
                }
            }
        }

        impl From<$type> for $enum_name {
            fn from(val: $type) -> $enum_name{
                match val {
                    $($value => $enum_name::$name,)*
                    _ => $enum_name::$invalid,
                }
            }
        }

        impl std::fmt::Display for $enum_name{
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    $($enum_name::$name => write!(f, stringify!($name)),)*
                    _ => write!(f, stringify!($invalid)),
                }
            }
        }
    };
}

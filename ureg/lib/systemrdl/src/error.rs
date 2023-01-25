/*++
Licensed under the Apache-2.0 license.
--*/
use std::fmt::Display;

use caliptra_systemrdl as systemrdl;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    UnexpectedScopeType {
        expected: systemrdl::ScopeType,
        actual: systemrdl::ScopeType,
    },
    AddressTooLarge(u64),
    OffsetNotDefined,
    WidthNotDefined,
    ValueNotDefined,
    FieldsCannotHaveMultipleDimensions,
    UnsupportedRegWidth(u64),
    AccessTypeNaUnsupported,
    RdlError(systemrdl::RdlError<'static>),
    BlockError {
        block_name: String,
        err: Box<Error>,
    },
    FieldError {
        field_name: String,
        err: Box<Error>,
    },
    RegisterError {
        register_name: String,
        err: Box<Error>,
    },
    RegisterTypeError {
        register_type_name: String,
        err: Box<Error>,
    },
    EnumError {
        enum_name: String,
        err: Box<Error>,
    },
    EnumVariantError {
        variant_name: String,
        err: Box<Error>,
    },
}
impl Error {
    pub fn root_cause(&self) -> &Error {
        match self {
            Self::BlockError { err, .. } => err.root_cause(),
            Self::FieldError { err, .. } => err.root_cause(),
            Self::RegisterError { err, .. } => err.root_cause(),
            Self::RegisterTypeError { err, .. } => err.root_cause(),
            Self::EnumError { err, .. } => err.root_cause(),
            Self::EnumVariantError { err, .. } => err.root_cause(),
            err => err,
        }
    }
}
impl std::error::Error for Error {}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedScopeType { expected, actual } => {
                write!(f, "Expect scope of type {expected:?} but was {actual:?}")
            }
            Self::AddressTooLarge(addr) => write!(f, "Address {addr:#x?} too large"),
            Self::OffsetNotDefined => write!(f, "offset was not defined"),
            Self::WidthNotDefined => write!(f, "width was not defined"),
            Self::ValueNotDefined => write!(f, "value was not defined"),
            Self::FieldsCannotHaveMultipleDimensions => {
                write!(f, "fields cannot have multiple dimensions")
            }
            Self::UnsupportedRegWidth(w) => write!(f, "Unsupported register width {w}"),
            Self::AccessTypeNaUnsupported => write!(f, "AccessType 'na' is not supported"),
            Self::RdlError(err) => write!(f, "systemrdl error: {err}"),
            Self::BlockError { block_name, err } => write!(f, "block {block_name:?} {err}"),
            Self::FieldError { field_name, err } => write!(f, "field {field_name:?} {err}"),
            Self::RegisterError { register_name, err } => {
                write!(f, "register {register_name:?} {err}")
            }
            Self::RegisterTypeError {
                register_type_name,
                err,
            } => {
                write!(f, "reg_type {register_type_name:?} {err}")
            }
            Self::EnumError { enum_name, err } => write!(f, "enum {enum_name:?} {err}"),
            Self::EnumVariantError { variant_name, err } => {
                write!(f, "variant {variant_name:?} {err}")
            }
        }
    }
}

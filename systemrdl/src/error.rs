/*++
Licensed under the Apache-2.0 license.
--*/
use std::{error::Error, fmt::Display};

use crate::{token::Token, value::PropertyType, ComponentType, Value};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RdlError<'a> {
    UnexpectedToken(Token<'a>),
    UnknownIdentifier(&'a str),
    DuplicateInstanceName(String),
    DuplicateTypeName(&'a str),
    DuplicatePropertyName(&'a str),
    DuplicateParameterName(&'a str),
    UnknownTypeName(&'a str),
    UnknownPropertyName(&'a str),
    UnknownInstanceName(&'a str),
    CantSetPropertyInRootScope,
    BadStringLiteral,
    ExpectedPropertyNotFound(&'a str),
    UnexpectedPropertyType {
        expected_type: PropertyType,
        value: Value,
    },
    NotImplemented,
    MsbLessThanLsb,
    ComponentTypeCantBeInstantiated(ComponentType),
    RootCantBeInstantiated,

    DefaultPropertiesMustBeDefinedBeforeComponents,
    StrideIsLessThanElementSize,
    MultidimensionalFieldsNotSupported,
    BadTernaryExpression(String),
}

impl Error for RdlError<'_> {}

impl Display for RdlError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadTernaryExpression(v) => write!(
                f,
                "Ternary expression takes boolean value for first argument but bot {v:?}"
            ),
            Self::UnexpectedToken(t) => write!(f, "Unexpected token {t:?}"),
            Self::UnknownIdentifier(s) => write!(f, "Unexpected identifier {s:?}"),
            Self::DuplicateInstanceName(s) => write!(f, "Dupicate instance name {s:?}"),
            Self::DuplicateTypeName(s) => write!(f, "Dupicate type name {s:?}"),
            Self::DuplicatePropertyName(s) => write!(f, "Dupicate property name {s:?}"),
            Self::DuplicateParameterName(s) => write!(f, "Dupicate parameter name {s:?}"),
            Self::UnknownTypeName(s) => write!(f, "Unknown type name {s:?}"),
            Self::UnknownPropertyName(s) => write!(f, "Unknown property name {s:?}"),
            Self::UnknownInstanceName(s) => write!(f, "Unknown instance name {s:?}"),
            Self::CantSetPropertyInRootScope => write!(f, "Can't set property in root scope"),
            Self::BadStringLiteral => write!(f, "Bad string literal"),
            Self::ExpectedPropertyNotFound(s) => {
                write!(f, "Required property {s:?} wasn't defined")
            }
            Self::UnexpectedPropertyType {
                expected_type,
                value,
            } => write!(
                f,
                "Expected property of type {expected_type:?}, found {value:?}"
            ),
            Self::NotImplemented => write!(f, "NOT IMPLEMENTED"),
            Self::MsbLessThanLsb => write!(f, "msb less than lsb; big-endian not supported"),
            Self::StrideIsLessThanElementSize => write!(f, "stride is less than element size"),
            Self::DefaultPropertiesMustBeDefinedBeforeComponents => {
                write!(f, "default properties must be defined before components")
            }
            Self::MultidimensionalFieldsNotSupported => {
                write!(f, "Multidimensional fields not supported")
            }
            Self::ComponentTypeCantBeInstantiated(ty) => {
                write!(f, "Component type {ty:?} can't be instantiated")
            }
            Self::RootCantBeInstantiated => write!(f, "Root can't be instantiated"),
        }
    }
}

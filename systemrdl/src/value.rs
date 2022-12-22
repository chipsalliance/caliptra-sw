/*++
Licensed under the Apache-2.0 license.
--*/

use crate::{token::Token, token_iter::TokenIter, Bits, RdlError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    U64(u64),
    Bool(bool),
    Bits(Bits),
    String(String),
    EnumReference(String),
    Reference(Reference),
    PrecedenceType(PrecedenceType),
    AccessType(AccessType),
    OnReadType(OnReadType),
    OnWriteType(OnWriteType),
    AddressingType(AddressingType),
    InterruptType(InterruptType),
}
impl From<u64> for Value {
    fn from(val: u64) -> Self {
        Value::U64(val)
    }
}
impl From<bool> for Value {
    fn from(val: bool) -> Self {
        Value::Bool(val)
    }
}
impl From<Bits> for Value {
    fn from(val: Bits) -> Self {
        Value::Bits(val)
    }
}
impl From<String> for Value {
    fn from(val: String) -> Self {
        Value::String(val)
    }
}
impl From<EnumReference> for Value {
    fn from(val: EnumReference) -> Self {
        Value::EnumReference(val.0)
    }
}
impl From<&str> for Value {
    fn from(val: &str) -> Self {
        Value::String(val.into())
    }
}
impl From<Reference> for Value {
    fn from(val: Reference) -> Self {
        Value::Reference(val)
    }
}
impl From<PrecedenceType> for Value {
    fn from(val: PrecedenceType) -> Self {
        Value::PrecedenceType(val)
    }
}
impl From<AccessType> for Value {
    fn from(val: AccessType) -> Self {
        Value::AccessType(val)
    }
}
impl From<OnReadType> for Value {
    fn from(val: OnReadType) -> Self {
        Value::OnReadType(val)
    }
}
impl From<OnWriteType> for Value {
    fn from(val: OnWriteType) -> Self {
        Value::OnWriteType(val)
    }
}
impl From<AddressingType> for Value {
    fn from(val: AddressingType) -> Self {
        Value::AddressingType(val)
    }
}
impl From<InterruptType> for Value {
    fn from(val: InterruptType) -> Self {
        Value::InterruptType(val)
    }
}
impl TryFrom<Value> for u64 {
    type Error = RdlError<'static>;
    fn try_from(value: Value) -> Result<'static, Self> {
        match value {
            Value::U64(value) => Ok(value),
            _ => Err(RdlError::UnexpectedPropertyType {
                expected_type: PropertyType::U64,
                value,
            }),
        }
    }
}
impl TryFrom<Value> for bool {
    type Error = RdlError<'static>;
    fn try_from(value: Value) -> Result<'static, Self> {
        match value {
            Value::Bool(value) => Ok(value),
            _ => Err(RdlError::UnexpectedPropertyType {
                expected_type: PropertyType::Boolean,
                value,
            }),
        }
    }
}
impl TryFrom<Value> for Bits {
    type Error = RdlError<'static>;
    fn try_from(value: Value) -> Result<'static, Self> {
        match value {
            Value::Bits(value) => Ok(value),
            _ => Err(RdlError::UnexpectedPropertyType {
                expected_type: PropertyType::Bits,
                value,
            }),
        }
    }
}
impl TryFrom<Value> for String {
    type Error = RdlError<'static>;
    fn try_from(value: Value) -> Result<'static, Self> {
        match value {
            Value::String(value) => Ok(value),
            _ => Err(RdlError::UnexpectedPropertyType {
                expected_type: PropertyType::String,
                value,
            }),
        }
    }
}
impl TryFrom<Value> for EnumReference {
    type Error = RdlError<'static>;
    fn try_from(value: Value) -> Result<'static, Self> {
        match value {
            Value::EnumReference(value) => Ok(EnumReference(value)),
            _ => Err(RdlError::UnexpectedPropertyType {
                expected_type: PropertyType::String,
                value,
            }),
        }
    }
}
impl TryFrom<Value> for AddressingType {
    type Error = RdlError<'static>;
    fn try_from(value: Value) -> Result<'static, Self> {
        match value {
            Value::AddressingType(value) => Ok(value),
            _ => Err(RdlError::UnexpectedPropertyType {
                expected_type: PropertyType::AddressingType,
                value,
            }),
        }
    }
}
impl TryFrom<Value> for AccessType {
    type Error = RdlError<'static>;
    fn try_from(value: Value) -> Result<'static, Self> {
        match value {
            Value::AccessType(value) => Ok(value),
            _ => Err(RdlError::UnexpectedPropertyType {
                expected_type: PropertyType::AccessType,
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reference {
    path: Vec<String>,
    property: Option<String>,
}
impl Reference {
    pub fn new(path: Vec<String>) -> Self {
        Self {
            path,
            property: None,
        }
    }
    pub fn parse<'a>(tokens: &mut TokenIter<'a>) -> Result<'a, Self> {
        let mut path = vec![];
        loop {
            path.push(tokens.expect_identifier()?.to_string());
            if *tokens.peek(0) != Token::Period {
                break;
            }
            tokens.next();
        }

        let property = if *tokens.peek(0) == Token::Pointer {
            tokens.next();
            Some(tokens.expect_identifier()?.to_string())
        } else {
            None
        };
        Ok(Self { path, property })
    }
}

pub struct EnumReference(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrecedenceType {
    Hw,
    Sw,
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum AccessType {
    #[default]
    Rw,
    R,
    W,
    Rw1,
    W1,
    Na,
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnReadType {
    RClr,
    RSet,
    RUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnWriteType {
    WoSet,
    WoClr,
    Wot,
    Wzs,
    Wzc,
    Wzt,
    WClr,
    WSet,
    WUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressingType {
    Compact,
    RegAlign,
    FullAlign,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum InterruptType {
    #[default]
    Level,
    PosEdge,
    NegEdge,
    BothEdge,
    NonSticky,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentType {
    Field,
    Reg,
    RegFile,
    AddrMap,
    Signal,
    Enum,
    EnumVariant,
    Mem,
    Constraint,
}
impl From<ComponentType> for ScopeType {
    fn from(ty: ComponentType) -> Self {
        ScopeType::Component(ty)
    }
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum ScopeType {
    #[default]
    Root,
    Component(ComponentType),
}

fn parse_str_literal(s: &str) -> Result<String> {
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return Err(RdlError::BadStringLiteral);
    }
    Ok(s[1..s.len() - 1]
        .replace("\\\"", "\"")
        .replace("\\\\", "\\"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyType {
    U64,
    Bits,
    Boolean,
    BooleanOrReference,
    BitOrReference,
    EnumReference,
    // has posedge | negedge | bothedge | level | nonsticky modifiers
    FieldInterrupt,
    PrecedenceType,
    String,
    AccessType,
    Reference,
    OnReadType,
    OnWriteType,
    AddressingType,
}
impl PropertyType {
    pub fn parse<'a>(self, tokens: &mut TokenIter<'a>) -> Result<'a, Value> {
        match self {
            PropertyType::U64 => Ok(tokens.expect_number()?.into()),
            PropertyType::Bits => Ok(tokens.expect_bits()?.into()),
            PropertyType::Boolean => match tokens.next() {
                Token::Number(0) => Ok(false.into()),
                Token::Number(1) => Ok(true.into()),
                Token::Identifier("false") => Ok(false.into()),
                Token::Identifier("true") => Ok(true.into()),
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::String => Ok(parse_str_literal(tokens.expect_string()?)?.into()),
            PropertyType::Reference => Ok(Reference::parse(tokens)?.into()),
            PropertyType::AccessType => match tokens.next() {
                Token::Identifier("na") => Ok(AccessType::Na.into()),
                Token::Identifier("r") => Ok(AccessType::R.into()),
                Token::Identifier("rw") => Ok(AccessType::Rw.into()),
                Token::Identifier("rw1") => Ok(AccessType::Rw1.into()),
                Token::Identifier("w") => Ok(AccessType::W.into()),
                Token::Identifier("w1") => Ok(AccessType::W1.into()),
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::OnReadType => todo!(),
            PropertyType::OnWriteType => todo!(),
            PropertyType::AddressingType => match tokens.next() {
                Token::Identifier("compact") => Ok(AddressingType::Compact.into()),
                Token::Identifier("fullalign") => Ok(AddressingType::FullAlign.into()),
                Token::Identifier("regalign") => Ok(AddressingType::RegAlign.into()),
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::BooleanOrReference => match tokens.peek(0) {
                Token::Identifier(_) => PropertyType::Reference.parse(tokens),
                _ => PropertyType::Boolean.parse(tokens),
            },
            PropertyType::BitOrReference => match tokens.peek(0) {
                Token::Identifier(_) => PropertyType::Reference.parse(tokens),
                Token::Number(_) => PropertyType::U64.parse(tokens),
                _ => PropertyType::Bits.parse(tokens),
            },
            PropertyType::EnumReference => {
                let ident = tokens.expect_identifier()?;
                // TODO: ensure that enum exists?
                Ok(Value::EnumReference(ident.into()))
            }
            PropertyType::FieldInterrupt => todo!(),
            PropertyType::PrecedenceType => match tokens.next() {
                Token::Identifier("hw") => Ok(PrecedenceType::Hw.into()),
                Token::Identifier("sw") => Ok(PrecedenceType::Sw.into()),
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
        }
    }
}

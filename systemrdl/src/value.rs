/*++
Licensed under the Apache-2.0 license.
--*/

use crate::{
    scope::{lookup_parameter_of_type, ParameterScope},
    token::Token,
    token_iter::TokenIter,
    Bits, RdlError, Result,
};

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
impl Value {
    pub fn property_type(&self) -> PropertyType {
        match self {
            Value::U64(_) => PropertyType::U64,
            Value::Bool(_) => PropertyType::Boolean,
            Value::Bits(_) => PropertyType::Bits,
            Value::String(_) => PropertyType::String,
            Value::EnumReference(_) => PropertyType::EnumReference,
            Value::Reference(_) => PropertyType::Reference,
            Value::PrecedenceType(_) => PropertyType::PrecedenceType,
            Value::AccessType(_) => PropertyType::AccessType,
            Value::OnReadType(_) => PropertyType::OnReadType,
            Value::OnWriteType(_) => PropertyType::OnWriteType,
            Value::AddressingType(_) => PropertyType::AddressingType,
            Value::InterruptType(_) => PropertyType::FieldInterrupt,
        }
    }
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
    Sticky,
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

pub fn parse_str_literal(s: &str) -> Result<String> {
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return Err(RdlError::BadStringLiteral);
    }
    Ok(s[1..s.len() - 1]
        .replace("\\\"", "\"")
        .replace("\\\\", "\\"))
}

fn to_bool<'a>(v: Value, parameters: Option<&'_ ParameterScope<'_>>) -> Result<'a, bool> {
    match v {
        Value::Bool(b) => Ok(b),
        Value::Reference(r) => {
            let r = r.path[0].clone();
            match lookup_parameter_of_type(parameters, &r, PropertyType::Boolean) {
                Ok(Value::Bool(b)) => Ok(*b),
                _ => Err(RdlError::UnexpectedPropertyType {
                    expected_type: PropertyType::Boolean,
                    value: Value::Bool(false),
                }),
            }
        }
        _ => Err(RdlError::UnexpectedPropertyType {
            expected_type: PropertyType::Boolean,
            value: v,
        }),
    }
}

fn to_bit<'a>(v: Value, parameters: Option<&'_ ParameterScope<'_>>) -> Result<'a, Bits> {
    match v {
        Value::Bits(b) => Ok(b),
        Value::Reference(r) => {
            let r = r.path[0].clone();
            match lookup_parameter_of_type(parameters, &r, PropertyType::Bits) {
                Ok(Value::Bits(b)) => Ok(*b),
                _ => Err(RdlError::UnexpectedPropertyType {
                    expected_type: PropertyType::Bits,
                    value: Value::Bool(false),
                }),
            }
        }
        _ => Err(RdlError::UnexpectedPropertyType {
            expected_type: PropertyType::Bits,
            value: v,
        }),
    }
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
    pub fn parse_type<'a>(tokens: &mut TokenIter<'a>) -> Result<'a, PropertyType> {
        match tokens.next() {
            Token::Identifier("boolean") => Ok(PropertyType::Boolean),
            Token::Identifier("string") => Ok(PropertyType::String),
            Token::Identifier("bit") => Ok(PropertyType::Bits),
            Token::Identifier("longint") => {
                tokens.expect(Token::Identifier("unsigned"))?;
                Ok(PropertyType::U64)
            }
            Token::Identifier("accesstype") => Ok(PropertyType::AccessType),
            Token::Identifier("addressingtype") => Ok(PropertyType::AddressingType),
            Token::Identifier("onreadtype") => Ok(PropertyType::OnReadType),
            Token::Identifier("onwritetype") => Ok(PropertyType::OnWriteType),
            Token::Identifier("precedencetype") => Ok(PropertyType::PrecedenceType),
            unexpected => Err(RdlError::UnexpectedToken(unexpected)),
        }
    }

    /// Special case expression parser and evaluator that only supports singleton, ternary, &&, and != expressions.
    pub fn eval<'a>(
        self,
        tokens: &mut TokenIter<'a>,
        parameters: Option<&'_ ParameterScope<'_>>,
    ) -> Result<'a, Value> {
        let first = tokens.peek(0).clone();
        if *tokens.peek(1) == Token::NotEquals {
            match self {
                PropertyType::BitOrReference => {}
                _ => {
                    return Err(RdlError::UnexpectedPropertyType {
                        expected_type: PropertyType::Boolean,
                        value: self.parse_or_lookup(tokens, parameters)?,
                    })
                }
            }
            let a = to_bit(self.parse_or_lookup(tokens, parameters)?, parameters)?;
            tokens.expect(Token::NotEquals)?;
            let b = to_bit(self.parse_or_lookup(tokens, parameters)?, parameters)?;
            Ok(Value::Bool(a != b))
        } else if *tokens.peek(1) == Token::And {
            match self {
                PropertyType::Boolean => {}
                PropertyType::BitOrReference => {}
                _ => {
                    return Err(RdlError::UnexpectedPropertyType {
                        expected_type: PropertyType::Boolean,
                        value: self.parse_or_lookup(tokens, parameters)?,
                    })
                }
            }
            let a = to_bool(self.parse_or_lookup(tokens, parameters)?, parameters)?;
            tokens.expect(Token::And)?;
            let b = to_bool(self.parse_or_lookup(tokens, parameters)?, parameters)?;
            Ok(Value::Bool(a && b))
        } else if *tokens.peek(1) == Token::QuestionMark && *tokens.peek(3) == Token::Colon {
            tokens.next();
            tokens.next();
            let name = match first {
                Token::Identifier(name) => name,
                _ => Err(RdlError::BadTernaryExpression(format!(
                    "Expected identifier but got {:?}",
                    first
                )))?,
            };
            let cond = lookup_parameter_of_type(parameters, name, PropertyType::Boolean)?;
            match cond {
                Value::Bool(true) => {
                    let ret = self.parse_or_lookup(tokens, parameters);
                    tokens.expect(Token::Colon)?;
                    tokens.next();
                    ret
                }
                Value::Bool(false) => {
                    tokens.next();
                    tokens.expect(Token::Colon)?;
                    let ret = self.parse_or_lookup(tokens, parameters);
                    ret
                }
                _ => Err(RdlError::BadTernaryExpression(format!(
                    "Expected boolean but got {:?}",
                    name
                )))?,
            }
        } else {
            self.parse_or_lookup(tokens, parameters)
        }
    }

    pub fn parse_or_lookup<'a>(
        self,
        tokens: &mut TokenIter<'a>,
        parameters: Option<&'_ ParameterScope<'_>>,
    ) -> Result<'a, Value> {
        match self {
            PropertyType::U64 => match tokens.next() {
                Token::Number(val) => Ok(val.into()),
                Token::Identifier(ident) => {
                    Ok(lookup_parameter_of_type(parameters, ident, self)?.clone())
                }
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::Bits => match tokens.next() {
                Token::Bits(val) => Ok(val.into()),
                Token::Number(val) => Ok(val.into()),
                Token::Identifier(ident) => {
                    Ok(lookup_parameter_of_type(parameters, ident, self)?.clone())
                }
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::Boolean => match tokens.next() {
                Token::Number(0) => Ok(false.into()),
                Token::Number(1) => Ok(true.into()),
                Token::Identifier("false") => Ok(false.into()),
                Token::Identifier("true") => Ok(true.into()),
                Token::Identifier(ident) => {
                    Ok(lookup_parameter_of_type(parameters, ident, self)?.clone())
                }
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
                Token::Identifier(ident) => {
                    Ok(lookup_parameter_of_type(parameters, ident, self)?.clone())
                }
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::OnReadType => match tokens.next() {
                Token::Identifier("rclr") => Ok(OnReadType::RClr.into()),
                Token::Identifier("rset") => Ok(OnReadType::RSet.into()),
                Token::Identifier("ruser") => Ok(OnReadType::RUser.into()),
                Token::Identifier(ident) => {
                    Ok(lookup_parameter_of_type(parameters, ident, self)?.clone())
                }
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::OnWriteType => match tokens.next() {
                Token::Identifier("woset") => Ok(OnWriteType::WoSet.into()),
                Token::Identifier("woclr") => Ok(OnWriteType::WoClr.into()),
                Token::Identifier("wot") => Ok(OnWriteType::Wot.into()),
                Token::Identifier("wzs") => Ok(OnWriteType::Wzs.into()),
                Token::Identifier("wzc") => Ok(OnWriteType::Wzc.into()),
                Token::Identifier("wzt") => Ok(OnWriteType::Wzt.into()),
                Token::Identifier("wclr") => Ok(OnWriteType::WClr.into()),
                Token::Identifier("wset") => Ok(OnWriteType::WSet.into()),
                Token::Identifier("wuser") => Ok(OnWriteType::WUser.into()),
                Token::Identifier(ident) => {
                    Ok(lookup_parameter_of_type(parameters, ident, self)?.clone())
                }
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::AddressingType => match tokens.next() {
                Token::Identifier("compact") => Ok(AddressingType::Compact.into()),
                Token::Identifier("fullalign") => Ok(AddressingType::FullAlign.into()),
                Token::Identifier("regalign") => Ok(AddressingType::RegAlign.into()),
                Token::Identifier(ident) => {
                    Ok(lookup_parameter_of_type(parameters, ident, self)?.clone())
                }
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
            PropertyType::BooleanOrReference => match tokens.peek(0) {
                Token::Identifier(_) => PropertyType::Reference.parse_or_lookup(tokens, parameters),
                _ => PropertyType::Boolean.parse_or_lookup(tokens, parameters),
            },
            PropertyType::BitOrReference => match tokens.peek(0) {
                Token::Identifier(_) => PropertyType::Reference.parse_or_lookup(tokens, parameters),
                Token::Number(_) => PropertyType::U64.parse_or_lookup(tokens, parameters),
                _ => PropertyType::Bits.parse_or_lookup(tokens, parameters),
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
                Token::Identifier(ident) => {
                    Ok(lookup_parameter_of_type(parameters, ident, self)?.clone())
                }
                unexpected => Err(RdlError::UnexpectedToken(unexpected)),
            },
        }
    }
}

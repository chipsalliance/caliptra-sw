/*++
Licensed under the Apache-2.0 license.
--*/

use crate::Bits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Token<'a> {
    Field,
    Reg,
    RegFile,
    AddrMap,
    Signal,
    Enum,
    Mem,
    Constraint,

    BraceOpen,
    BraceClose,
    BracketOpen,
    BracketClose,
    Semicolon,
    Comma,
    Period,
    Equals,
    At,
    Colon,

    Pointer,
    PlusEqual,
    PercentEqual,

    Identifier(&'a str),
    StringLiteral(&'a str),
    Number(u64),
    Bits(Bits),

    EndOfFile,
    Skip,

    PreprocInclude,
    UnableToOpenFile(&'a str),
    IncludeDepthLimitReached,

    Error,
}

impl Token<'_> {
    pub fn is_identifier(&self) -> bool {
        matches!(self, Self::Identifier(_))
    }
}

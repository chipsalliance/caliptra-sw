/*++
Licensed under the Apache-2.0 license.
--*/

use crate::Bits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Token<'a> {
    Field,
    External,
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
    ParenOpen,
    ParenClose,
    Semicolon,
    Comma,
    Period,
    Equals,
    NotEquals,
    At,
    Colon,
    Hash,

    Pointer,
    PlusEqual,
    PercentEqual,
    QuestionMark,
    And,

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

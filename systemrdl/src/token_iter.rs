/*++
Licensed under the Apache-2.0 license.
--*/

use std::collections::VecDeque;

use crate::lexer::{Lexer, Span};
use crate::token::Token;
use crate::{Bits, RdlError, Result};

pub struct TokenIter<'a> {
    lex: Lexer<'a>,
    fifo: VecDeque<(Token<'a>, Span)>,
    last_span: Span,
}
impl<'a> TokenIter<'a> {
    pub fn new(lex: Lexer<'a>) -> Self {
        Self {
            lex,
            fifo: VecDeque::new(),
            last_span: 0..0,
        }
    }
    pub fn from_str(s: &'a str) -> Self {
        let lex = Lexer::new(s);
        Self::new(lex)
    }
    pub fn peek(&mut self, lookahead: usize) -> &Token<'a> {
        while self.fifo.len() < lookahead + 1 {
            self.fifo
                .push_back((self.lex.next().unwrap_or(Token::EndOfFile), self.lex.span()));
        }
        &self.fifo[lookahead].0
    }
    pub fn next(&mut self) -> Token<'a> {
        let next = if self.fifo.is_empty() {
            (self.lex.next().unwrap_or(Token::EndOfFile), self.lex.span())
        } else {
            self.fifo.pop_front().unwrap()
        };
        self.last_span = next.1.clone();
        next.0
    }
    pub fn expect(&mut self, expected: Token) -> Result<'a, ()> {
        let token = self.next();
        if token != expected {
            return Err(RdlError::UnexpectedToken(token));
        }
        Ok(())
    }
    pub fn expect_identifier(&mut self) -> Result<'a, &'a str> {
        match self.next() {
            Token::Identifier(name) => Ok(name),
            token => Err(RdlError::UnexpectedToken(token)),
        }
    }
    pub fn expect_number(&mut self) -> Result<'a, u64> {
        match self.next() {
            Token::Number(val) => Ok(val),
            token => Err(RdlError::UnexpectedToken(token)),
        }
    }
    pub fn expect_string(&mut self) -> Result<'a, &'a str> {
        match self.next() {
            Token::StringLiteral(val) => Ok(val),
            token => Err(RdlError::UnexpectedToken(token)),
        }
    }
    pub fn expect_bits(&mut self) -> Result<'a, Bits> {
        match self.next() {
            Token::Bits(bits) => Ok(bits),
            token => Err(RdlError::UnexpectedToken(token)),
        }
    }
    pub fn last_span(&self) -> &Span {
        &self.last_span
    }
}

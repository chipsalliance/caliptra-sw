/*++
Licensed under the Apache-2.0 license.
--*/

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use crate::file_source::FileSource;
use crate::lexer::{Lexer, Span};
use crate::token::Token;
use crate::value::parse_str_literal;
use crate::{Bits, RdlError, Result};

struct IncludeStackEntry<'a> {
    lex: Lexer<'a>,
    file_path: PathBuf,
    file_contents: &'a str,
}

pub struct TokenIter<'a> {
    lex: Lexer<'a>,
    fifo: VecDeque<(Token<'a>, Span)>,
    last_span: Span,

    current_file_contents: &'a str,
    current_file_path: PathBuf,
    file_source: Option<&'a dyn FileSource>,
    iter_stack: Vec<IncludeStackEntry<'a>>,
}
impl<'a> TokenIter<'a> {
    pub fn from_path(file_source: &'a dyn FileSource, file_path: &Path) -> std::io::Result<Self> {
        let file_contents = file_source.read_to_string(file_path)?;
        let lex = Lexer::new(file_contents);
        Ok(Self {
            lex,
            fifo: VecDeque::new(),
            last_span: 0..0,

            current_file_path: file_path.into(),
            current_file_contents: file_contents,
            iter_stack: Vec::new(),
            file_source: Some(file_source),
        })
    }
    pub fn from_str(s: &'a str) -> Self {
        Self {
            lex: Lexer::new(s),
            fifo: Default::default(),
            last_span: Default::default(),

            current_file_path: Default::default(),
            current_file_contents: s,
            file_source: Default::default(),
            iter_stack: Default::default(),
        }
    }

    fn lex_next(&mut self) -> Option<Token<'a>> {
        const INCLUDE_DEPTH_LIMIT: usize = 100;

        loop {
            match self.lex.next() {
                Some(Token::PreprocInclude) => {
                    let Some(Token::StringLiteral(filename)) = self.lex.next() else {
                        return Some(Token::Error);
                    };
                    let Some(file_source) = self.file_source else {
                        return Some(Token::UnableToOpenFile(filename));
                    };
                    let Ok(parsed_filename) = parse_str_literal(filename) else {
                        return Some(Token::UnableToOpenFile(filename));
                    };
                    let file_path = if let Some(parent) = self.current_file_path.parent() {
                        parent.join(parsed_filename)
                    } else {
                        PathBuf::from(parsed_filename)
                    };

                    let Ok(file_contents) = file_source.read_to_string(&file_path) else {
                        return Some(Token::UnableToOpenFile(filename));
                    };
                    if self.iter_stack.len() >= INCLUDE_DEPTH_LIMIT {
                        return Some(Token::IncludeDepthLimitReached);
                    }
                    let old_lex = std::mem::replace(&mut self.lex, Lexer::new(file_contents));
                    let old_file_path =
                        std::mem::replace(&mut self.current_file_path, filename.into());
                    let old_file_contents =
                        std::mem::replace(&mut self.current_file_contents, file_contents);
                    self.iter_stack.push(IncludeStackEntry {
                        lex: old_lex,
                        file_path: old_file_path,
                        file_contents: old_file_contents,
                    });
                    self.current_file_path = file_path;
                    // Retry with new lexer
                    continue;
                }
                None => {
                    let stack_entry = self.iter_stack.pop()?;
                    // this file was included from another file; resume
                    // processing the original file.
                    self.lex = stack_entry.lex;
                    self.current_file_path = stack_entry.file_path;
                    self.current_file_contents = stack_entry.file_contents;
                    continue;
                }
                token => return token,
            }
        }
    }
    pub fn peek(&mut self, lookahead: usize) -> &Token<'a> {
        while self.fifo.len() < lookahead + 1 {
            let token = self.lex_next().unwrap_or(Token::EndOfFile);
            self.fifo.push_back((token, self.lex.span()));
        }
        &self.fifo[lookahead].0
    }
    pub fn next(&mut self) -> Token<'a> {
        let next = if self.fifo.is_empty() {
            (self.lex_next().unwrap_or(Token::EndOfFile), self.lex.span())
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
    pub fn current_file_contents(&self) -> &'a str {
        self.current_file_contents
    }
    pub fn current_file_path(&self) -> &Path {
        &self.current_file_path
    }
}

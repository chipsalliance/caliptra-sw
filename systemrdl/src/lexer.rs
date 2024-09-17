/*++
Licensed under the Apache-2.0 license.
--*/

use std::str::{Chars, FromStr};

use crate::{token::Token, Bits};

pub type Span = std::ops::Range<usize>;

pub struct Lexer<'a> {
    start_ptr: *const u8,
    token_start_ptr: *const u8,
    iter: std::str::Chars<'a>,
}
impl<'a> Lexer<'a> {
    pub fn new(s: &'a str) -> Self {
        Self {
            start_ptr: s.as_bytes().as_ptr(),
            token_start_ptr: s.as_bytes().as_ptr(),
            iter: s.chars(),
        }
    }

    pub fn span(&self) -> Span {
        Span {
            start: self.token_start_ptr as usize - self.start_ptr as usize,
            end: self.iter.as_str().as_ptr() as usize - self.start_ptr as usize,
        }
    }
}
impl<'a> Iterator for Lexer<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        let mut iter = self.iter.clone();
        loop {
            let result = match iter.next() {
                Some(' ' | '\t' | '\n' | '\r') => Some(Token::Skip),
                Some('/') => {
                    match iter.next() {
                        Some('*') => {
                            // skip comments
                            loop {
                                match iter.next() {
                                    Some('*') => match iter.next() {
                                        Some('/') => break Some(Token::Skip),
                                        Some(_) => continue,
                                        None => break Some(Token::Error),
                                    },
                                    Some(_) => continue,
                                    None => break Some(Token::Error),
                                }
                            }
                        }
                        Some('/') => loop {
                            match iter.next() {
                                Some('\n') => break Some(Token::Skip),
                                Some(_) => continue,
                                None => break None,
                            }
                        },
                        _ => Some(Token::Error),
                    }
                }
                Some('"') => loop {
                    match iter.next() {
                        Some('"') => {
                            break Some(Token::StringLiteral(str_between(&self.iter, &iter)))
                        }
                        Some('\\') => match iter.next() {
                            Some(_) => continue,
                            None => break Some(Token::Error),
                        },
                        Some(_) => continue,
                        None => break Some(Token::Error),
                    }
                },
                Some(ch) if ch.is_ascii_alphabetic() || ch == '_' => {
                    next_while(&mut iter, |ch| ch.is_ascii_alphanumeric() || ch == '_');
                    match str_between(&self.iter, &iter) {
                        "field" => Some(Token::Field),
                        "external" => Some(Token::External),
                        "reg" => Some(Token::Reg),
                        "regfile" => Some(Token::RegFile),
                        "addrmap" => Some(Token::AddrMap),
                        "signal" => Some(Token::Signal),
                        "enum" => Some(Token::Enum),
                        "mem" => Some(Token::Mem),
                        "constraint" => Some(Token::Constraint),
                        ident => Some(Token::Identifier(ident)),
                    }
                }
                Some(ch) if ch.is_ascii_digit() => {
                    if ch == '0' && iter.peek() == Some('x') {
                        iter.next();
                        let num_start = iter.clone();
                        next_while(&mut iter, |ch| ch.is_ascii_hexdigit() || ch == '_');
                        Some(parse_num(str_between(&num_start, &iter), 16))
                    } else {
                        next_while(&mut iter, |ch| ch.is_ascii_digit() || ch == '_');
                        let mut peek = iter.clone();
                        if let Some('\'') = peek.next() {
                            iter = peek;
                            next_while(&mut iter, |ch| {
                                ch == 'b' || ch == 'o' || ch == 'd' || ch == 'h'
                            });
                            next_while(&mut iter, |ch| ch.is_ascii_hexdigit() || ch == '_');
                            match Bits::from_str(str_between(&self.iter, &iter)) {
                                Ok(bits) => Some(Token::Bits(bits)),
                                Err(_) => Some(Token::Error),
                            }
                        } else {
                            Some(parse_num(str_between(&self.iter, &iter), 10))
                        }
                    }
                }
                Some('!') => match iter.next() {
                    Some('=') => Some(Token::NotEquals),
                    _ => Some(Token::Error),
                },
                Some('&') => match iter.next() {
                    Some('&') => Some(Token::And),
                    _ => Some(Token::Error),
                },
                Some('{') => Some(Token::BraceOpen),
                Some('}') => Some(Token::BraceClose),
                Some('[') => Some(Token::BracketOpen),
                Some(']') => Some(Token::BracketClose),
                Some('(') => Some(Token::ParenOpen),
                Some(')') => Some(Token::ParenClose),
                Some(';') => Some(Token::Semicolon),
                Some(',') => Some(Token::Comma),
                Some('.') => Some(Token::Period),
                Some('=') => Some(Token::Equals),
                Some('@') => Some(Token::At),
                Some('#') => Some(Token::Hash),
                Some(':') => Some(Token::Colon),
                Some('?') => Some(Token::QuestionMark),
                Some('`') => {
                    let keyword_start = iter.clone();
                    next_while(&mut iter, |ch| ch.is_ascii_alphabetic() || ch == '_');
                    match str_between(&keyword_start, &iter) {
                        "include" => Some(Token::PreprocInclude),
                        _ => Some(Token::Error),
                    }
                }
                Some('+') => match iter.next() {
                    Some('=') => Some(Token::PlusEqual),
                    _ => return Some(Token::Error),
                },
                Some('%') => match iter.next() {
                    Some('=') => Some(Token::PercentEqual),
                    _ => Some(Token::Error),
                },
                Some('-') => match iter.next() {
                    Some('>') => Some(Token::Pointer),
                    _ => Some(Token::Error),
                },
                None => None,
                _ => Some(Token::Error),
            };
            match result {
                Some(Token::Skip) => {
                    self.iter = iter.clone();
                    continue;
                }
                Some(token) => {
                    self.token_start_ptr = self.iter.as_str().as_ptr();
                    self.iter = iter;
                    return Some(token);
                }
                None => return None,
            }
        }
    }
}

fn next_while(iter: &mut Chars, mut f: impl FnMut(char) -> bool) {
    loop {
        let mut peek = iter.clone();
        if let Some(ch) = peek.next() {
            if f(ch) {
                *iter = peek;
                continue;
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

fn parse_num(s: &str, radix: u32) -> Token {
    let replaced;
    let s = if s.contains('_') {
        replaced = s.replace('_', "");
        &replaced
    } else {
        s
    };
    if let Ok(val) = u64::from_str_radix(s, radix) {
        Token::Number(val)
    } else {
        Token::Error
    }
}

trait PeekableChar {
    fn peek(&self) -> Option<char>;
}
impl PeekableChar for std::str::Chars<'_> {
    fn peek(&self) -> Option<char> {
        self.clone().next()
    }
}
fn str_between<'a>(start: &Chars<'a>, end: &Chars<'a>) -> &'a str {
    let first_ptr = start.as_str().as_ptr();
    let second_ptr = end.as_str().as_ptr();
    &start.as_str()[0..second_ptr as usize - first_ptr as usize]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_foo() {
        let tokens: Vec<Token> = Lexer::new("!= && ? __id external field 35\tiDentifier2_ 0x24\n\r 0xf00_bad 100_200 2'b01 5'o27 4'd9 16'h1caf 32'h3CAB_FFB0 /* ignore comment */ %= // line comment\n += \"string 1\" \"string\\\"2\" {}[]();:,.=@#reg field regfile addrmap signal enum mem constraint").take(42).collect();
        assert_eq!(
            tokens,
            vec![
                Token::NotEquals,
                Token::And,
                Token::QuestionMark,
                Token::Identifier("__id"),
                Token::External,
                Token::Field,
                Token::Number(35),
                Token::Identifier("iDentifier2_"),
                Token::Number(0x24),
                Token::Number(0xf00bad),
                Token::Number(100_200),
                Token::Bits(Bits::new(2, 1)),
                Token::Bits(Bits::new(5, 0o27)),
                Token::Bits(Bits::new(4, 9)),
                Token::Bits(Bits::new(16, 0x1caf)),
                Token::Bits(Bits::new(32, 0x3cab_ffb0)),
                Token::PercentEqual,
                Token::PlusEqual,
                Token::StringLiteral("\"string 1\""),
                Token::StringLiteral("\"string\\\"2\""),
                Token::BraceOpen,
                Token::BraceClose,
                Token::BracketOpen,
                Token::BracketClose,
                Token::ParenOpen,
                Token::ParenClose,
                Token::Semicolon,
                Token::Colon,
                Token::Comma,
                Token::Period,
                Token::Equals,
                Token::At,
                Token::Hash,
                Token::Reg,
                Token::Field,
                Token::RegFile,
                Token::AddrMap,
                Token::Signal,
                Token::Enum,
                Token::Mem,
                Token::Constraint,
            ]
        );
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    literal.rs

Abstract:

    General-purpose functions for manipulating literal tokens.

--*/
use std::str::FromStr;

use proc_macro2::{Literal, TokenTree};

use crate::util::token_iter::DisplayToken;

pub fn parse_usize(literal: &TokenTree) -> usize {
    if let TokenTree::Literal(literal) = literal {
        let s = literal.to_string();
        if let Some(s) = s.strip_prefix("0x") {
            if let Ok(val) = usize::from_str_radix(&s.replace('_', ""), 16) {
                return val;
            }
        }
        if let Ok(val) = usize::from_str(&s.replace('_', "")) {
            return val;
        }
    }
    panic!(
        "Can't parse {} as hex",
        &DisplayToken(&Some(literal.clone()))
    );
}

pub fn parse_hex_u32(literal: TokenTree) -> u32 {
    if let TokenTree::Literal(literal) = &literal {
        let s = literal.to_string();
        if let Some(s) = s.strip_prefix("0x") {
            if let Ok(val) = u32::from_str_radix(&s.replace('_', ""), 16) {
                return val;
            }
        }
    }
    panic!("Can't parse {} as hex", &DisplayToken(&Some(literal)));
}

pub fn hex_literal_u32(val: u32) -> TokenTree {
    TokenTree::Literal(
        Literal::from_str(&format!("0x{:04x}_{:04x}", val >> 16, val & 0xffff)).unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use proc_macro2::{Ident, Span};

    use super::*;

    #[test]
    fn test_parse_usize() {
        assert_eq!(42, parse_usize(&Literal::from_str("42").unwrap().into()));
        assert_eq!(0, parse_usize(&Literal::from_str("0").unwrap().into()));
        assert_eq!(
            33_000,
            parse_usize(&Literal::from_str("33_000").unwrap().into())
        );
        assert_eq!(
            0x1234,
            parse_usize(&Literal::from_str("0x1234").unwrap().into())
        );
        assert_eq!(
            0x1234_5678,
            parse_usize(&Literal::from_str("0x1234_5678").unwrap().into())
        );
    }

    #[test]
    fn test_parse_hex_u32() {
        assert_eq!(0x0, parse_hex_u32(Literal::from_str("0x0").unwrap().into()));
        assert_eq!(
            0xabcd1234,
            parse_hex_u32(Literal::from_str("0xabcd1234").unwrap().into())
        );
        assert_eq!(
            0xabcd1234,
            parse_hex_u32(Literal::from_str("0xabcd_1234").unwrap().into())
        );
        assert_eq!(
            0xabcd1234,
            parse_hex_u32(Literal::from_str("0xAB_cd_12_34").unwrap().into())
        );
    }
    #[test]
    #[should_panic(expected = "Can't parse literal 0 as hex")]
    fn test_parse_hex_u32_panic1() {
        parse_hex_u32(Literal::from_str("0").unwrap().into());
    }
    #[test]
    #[should_panic(expected = "Can't parse literal 0o0 as hex")]
    fn test_parse_hex_u32_panic2() {
        parse_hex_u32(Literal::from_str("0o0").unwrap().into());
    }
    #[test]
    #[should_panic(expected = "Can't parse identifier foo as hex")]
    fn test_parse_hex_u32_panic3() {
        parse_hex_u32(Ident::new("foo", Span::call_site()).into());
    }

    #[test]
    fn test_hex_literal_u32() {
        assert_eq!("0x0000_0000", hex_literal_u32(0).to_string());
        assert_eq!("0x1234_abcd", hex_literal_u32(0x1234abcd).to_string());
    }
}

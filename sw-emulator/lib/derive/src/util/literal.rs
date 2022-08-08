/*++

Licensed under the Apache-2.0 license.

File Name:

    literal.rs

Abstract:

    General-purpose functions for manipulating literal tokens.

--*/
use std::str::FromStr;

#[cfg(not(test))]
use proc_macro::{Literal, TokenTree};
#[cfg(test)]
use proc_macro2::{Literal, TokenTree};

pub fn parse_hex_u32(literal: Literal) -> u32 {
    let s = literal.to_string();
    if s.starts_with("0x") {
        if let Ok(val) = u32::from_str_radix(&s[2..].replace("_", ""), 16) {
            return val;
        }
    }
    panic!("Can't parse hex literal {:?}", s)
}

pub fn hex_literal_u32(val: u32) -> TokenTree {
    TokenTree::Literal(
        Literal::from_str(&format!("0x{:04x}_{:04x}", val >> 16, val & 0xffff)).unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_u32() {
        assert_eq!(0x0, parse_hex_u32(Literal::from_str("0x0").unwrap()));
        assert_eq!(
            0xabcd1234,
            parse_hex_u32(Literal::from_str("0xabcd1234").unwrap())
        );
        assert_eq!(
            0xabcd1234,
            parse_hex_u32(Literal::from_str("0xabcd_1234").unwrap())
        );
        assert_eq!(
            0xabcd1234,
            parse_hex_u32(Literal::from_str("0xAB_cd_12_34").unwrap())
        );
    }
    #[test]
    #[should_panic(expected = "Can't parse hex literal \"0\"")]
    fn test_parse_hex_u32_panic1() {
        parse_hex_u32(Literal::from_str("0").unwrap());
    }
    #[test]
    #[should_panic(expected = "Can't parse hex literal \"0o0\"")]
    fn test_parse_hex_u32_panic2() {
        parse_hex_u32(Literal::from_str("0o0").unwrap());
    }

    #[test]
    fn test_hex_literal_u32() {
        assert_eq!("0x0000_0000", hex_literal_u32(0).to_string());
        assert_eq!("0x1234_abcd", hex_literal_u32(0x1234abcd).to_string());
    }
}

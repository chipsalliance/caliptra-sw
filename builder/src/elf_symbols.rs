// Licensed under the Apache-2.0 license

use std::io;

use elf::endian::LittleEndian;

use super::other_err;

pub fn elf_symbols(elf_bytes: &[u8]) -> io::Result<Vec<Symbol>> {
    let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).map_err(other_err)?;
    let Some((symbols, strings)) = elf.symbol_table().map_err(other_err)? else {
        return Ok(vec![]);
    };
    let mut result = vec![];
    for sym in symbols.iter() {
        let sym_name = strings.get(sym.st_name as usize).map_err(|e| {
            other_err(format!(
                "Could not parse symbol string at index {}: {e}",
                sym.st_name
            ))
        })?;
        result.push(Symbol {
            name: sym_name,
            size: sym.st_size,
            value: sym.st_value,

            // Unwrap cannot panic because st_vis is only 2 bits
            visibility: SymbolVisibility::try_from(sym.st_vis()).unwrap(),

            // Unwrap cannot panic because st_symtype is only 4 bits
            ty: SymbolType::try_from(sym.st_symtype()).unwrap(),

            // Unwrap cannot panic because st_bind is only 4 bits
            bind: SymbolBind::try_from(sym.st_bind()).unwrap(),
        });
    }
    Ok(result)
}

#[derive(Debug, Eq, PartialEq)]
pub struct Symbol<'a> {
    pub name: &'a str,
    pub size: u64,
    pub value: u64,
    pub ty: SymbolType,
    pub visibility: SymbolVisibility,
    pub bind: SymbolBind,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SymbolType {
    None = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
    Common = 5,
    Tls = 6,
    Reserved7 = 7,
    Reserved8 = 8,
    Reserved9 = 9,
    Os10 = 10,
    Os11 = 11,
    Os12 = 12,
    Proc13 = 13,
    Proc14 = 14,
    Proc15 = 15,
}
impl TryFrom<u8> for SymbolType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Object),
            2 => Ok(Self::Func),
            3 => Ok(Self::Section),
            4 => Ok(Self::File),
            5 => Ok(Self::Common),
            6 => Ok(Self::Tls),
            7 => Ok(Self::Reserved7),
            8 => Ok(Self::Reserved8),
            9 => Ok(Self::Reserved9),
            10 => Ok(Self::Os10),
            11 => Ok(Self::Os11),
            12 => Ok(Self::Os12),
            13 => Ok(Self::Proc13),
            14 => Ok(Self::Proc14),
            15 => Ok(Self::Proc15),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SymbolVisibility {
    Default = 0,
    Internal = 1,
    Hidden = 2,
    Protected = 3,
}
impl TryFrom<u8> for SymbolVisibility {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Default),
            1 => Ok(Self::Internal),
            2 => Ok(Self::Hidden),
            3 => Ok(Self::Protected),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SymbolBind {
    Local = 0,
    Global = 1,
    Weak = 2,
    Reserved3 = 3,
    Reserved4 = 4,
    Reserved5 = 5,
    Reserved6 = 6,
    Reserved7 = 7,
    Reserved8 = 8,
    Reserved9 = 9,
    Os10 = 10,
    Os11 = 11,
    Os12 = 12,
    Proc13 = 13,
    Proc14 = 14,
    Proc15 = 15,
}
impl TryFrom<u8> for SymbolBind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Local),
            1 => Ok(Self::Global),
            2 => Ok(Self::Weak),
            3 => Ok(Self::Reserved3),
            4 => Ok(Self::Reserved4),
            5 => Ok(Self::Reserved5),
            6 => Ok(Self::Reserved6),
            7 => Ok(Self::Reserved7),
            8 => Ok(Self::Reserved8),
            9 => Ok(Self::Reserved9),
            10 => Ok(Self::Os10),
            11 => Ok(Self::Os11),
            12 => Ok(Self::Os12),
            13 => Ok(Self::Proc13),
            14 => Ok(Self::Proc14),
            15 => Ok(Self::Proc15),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{self as caliptra_builder, SymbolBind, SymbolType, SymbolVisibility};

    #[test]
    fn test_elf_symbols() {
        let symbols =
            caliptra_builder::elf_symbols(include_bytes!("testdata/example.elf")).unwrap();
        let bss_start = symbols.iter().find(|s| s.name == "BSS_START");
        assert_eq!(
            bss_start,
            Some(&caliptra_builder::elf_symbols::Symbol {
                name: "BSS_START",
                size: 0,
                value: 0x50000000,
                ty: SymbolType::None,
                visibility: SymbolVisibility::Default,
                bind: SymbolBind::Global,
            })
        );
        println!("{:?}", symbols);
    }
}

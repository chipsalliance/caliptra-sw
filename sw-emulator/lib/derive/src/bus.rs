/*++

Licensed under the Apache-2.0 license.

File Name:

    bus.rs

Abstract:

    Implements #[derive(Bus)], used for dispatching Bus::read() Bus::write() to
    fields of a struct.

--*/
use std::{collections::HashMap, str::FromStr};

#[cfg(not(test))]
use proc_macro::{Delimiter, Group, Ident, Span, TokenStream, TokenTree};
#[cfg(test)]
use proc_macro2::{Delimiter, Group, Ident, Span, TokenStream, TokenTree};

use crate::util::literal::{self, hex_literal_u32};
use crate::util::sort::sorted_by_key;
use crate::util::token_iter::{
    expect_ident, skip_to_field_with_attributes, skip_to_group, skip_to_struct,
};

pub fn derive_bus(input: TokenStream) -> TokenStream {
    let mut iter = input.into_iter();
    skip_to_struct(&mut iter);
    let struct_name = expect_ident(&mut iter);
    let struct_fields = skip_to_group(&mut iter, Delimiter::Brace);
    let peripheral_fields = parse_peripheral_fields(struct_fields.stream());

    let mask_matches = build_match_tree_from_fields(&peripheral_fields);
    drop(peripheral_fields);

    let mut result = TokenStream::new();
    result.extend(TokenStream::from_str("impl caliptra_emu_cpu::Bus for").unwrap());
    result.extend([TokenTree::from(struct_name)]);

    let mut impl_body = TokenStream::new();
    {
        impl_body.extend(
            TokenStream::from_str("fn read(&self, size: caliptra_emu_cpu::RvSize, addr: caliptra_emu_cpu::RvAddr) -> Result<caliptra_emu_cpu::RvData, caliptra_emu_cpu::RvException>").unwrap());

        let mut fn_body = TokenStream::new();
        if let Some(mask_matches) = &mask_matches {
            fn_body.extend(gen_match_tokens(mask_matches, AccessType::Read));
        }
        fn_body.extend(
            TokenStream::from_str("Err(caliptra_emu_cpu::RvException::load_access_fault(addr))")
                .unwrap(),
        );
        impl_body.extend([TokenTree::from(Group::new(Delimiter::Brace, fn_body))]);
    }
    {
        impl_body.extend(
            TokenStream::from_str("fn write(&mut self, size: caliptra_emu_cpu::RvSize, addr: caliptra_emu_cpu::RvAddr, val: caliptra_emu_cpu::RvData) -> Result<(), caliptra_emu_cpu::RvException>").unwrap());

        let mut fn_body = TokenStream::new();
        if let Some(mask_matches) = &mask_matches {
            fn_body.extend(gen_match_tokens(mask_matches, AccessType::Write));
        }
        fn_body.extend(
            TokenStream::from_str("Err(caliptra_emu_cpu::RvException::store_access_fault(addr))")
                .unwrap(),
        );
        impl_body.extend([TokenTree::from(Group::new(Delimiter::Brace, fn_body))]);
    }

    result.extend([TokenTree::from(Group::new(Delimiter::Brace, impl_body))]);

    result
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeripheralField {
    name: String,
    offset: u32,
    mask: u32,
}

fn parse_peripheral_fields(stream: TokenStream) -> Vec<PeripheralField> {
    let mut iter = stream.into_iter();
    let mut result = Vec::new();
    while let Some(field) = skip_to_field_with_attributes(&mut iter, "peripheral") {
        if field.attributes.is_empty() {
            continue;
        }
        if field.attributes.len() > 1 {
            panic!("More than one #[peripheral] attribute attached to field");
        }
        let attr = &field.attributes[0];
        if let (Some(offset), Some(mask)) = (
            attr.args.get("offset").cloned(),
            attr.args.get("mask").cloned(),
        ) {
            result.push(PeripheralField {
                name: field.name.to_string(),
                offset: literal::parse_hex_u32(offset),
                mask: literal::parse_hex_u32(mask),
            })
        } else {
            panic!("peripheral attribute must have offset and mask parameters and be placed before a field offset={:?} mask={:?}", attr.args.get("offset"), attr.args.get("mask"));
        }
    }
    result
}

#[derive(Debug, Eq, PartialEq)]
struct MaskMatchBlock {
    /// The mask used in the scrutinee of the match block.
    mask: u32,

    /// The arms of the match block.
    match_arms: Vec<MatchArm>,
}

#[derive(Debug, Eq, PartialEq)]
enum MatchBody {
    /// The body should be a read or write to a field with name `String`.
    Field(String),

    /// The body should be another match block.
    SubMatchBlock(MaskMatchBlock),
}

/// Represents a match arm of the form `offset` => `body`.
#[derive(Debug, Eq, PartialEq)]
struct MatchArm {
    /// The offset used in the pattern of a mask arm.
    offset: u32,

    /// The expression right of "=>" in the match arm.
    body: MatchBody,
}

/// Given a list of fields (with their peripheral arguments), generate a tree of
/// masked-offset match blocks (to be converted to Rust tokens later).
fn build_match_tree_from_fields(fields: &[PeripheralField]) -> Option<MaskMatchBlock> {
    let mut fields_by_mask: HashMap<u32, Vec<PeripheralField>> = HashMap::new();
    for field in fields.iter() {
        if !lsbs_contiguous(field.mask) {
            panic!("Field {} has an invalid peripheral mask (must be equal to a power of two minus 1) {:#010x}", field.name, field.mask);
        }
        fields_by_mask
            .entry(field.mask)
            .or_default()
            .push(field.clone());
    }

    fn recurse(
        mut iter: impl Iterator<Item = (u32, Vec<PeripheralField>)>,
    ) -> Option<MaskMatchBlock> {
        if let Some((mask, fields)) = iter.next() {
            let mut result = MaskMatchBlock {
                mask: !mask,
                match_arms: Vec::new(),
            };
            for field in fields.into_iter() {
                result.match_arms.push(MatchArm {
                    offset: field.offset,
                    body: MatchBody::Field(field.name),
                });
            }
            if let Some(sub_matches) = recurse(iter) {
                let mut map: HashMap<u32, Vec<MatchArm>> = HashMap::new();
                for m in sub_matches.match_arms.into_iter() {
                    map.entry(m.offset & !mask).or_default().push(m);
                }
                for (masked_offset, matches) in sorted_by_key(map.into_iter(), |p| p.0) {
                    if !matches.is_empty() {
                        result.match_arms.push(MatchArm {
                            offset: masked_offset,
                            body: MatchBody::SubMatchBlock(MaskMatchBlock {
                                mask: sub_matches.mask,
                                match_arms: matches,
                            }),
                        });
                    }
                }
            }
            Some(result)
        } else {
            None
        }
    }
    recurse(sorted_by_key(fields_by_mask.into_iter(), |p| p.0).rev())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccessType {
    Read,
    Write,
}

fn lsbs_contiguous(mask: u32) -> bool {
    mask != 0 && (u64::from(mask) + 1).is_power_of_two()
}

/// Serialize `mask_matches` into a stream of Rust tokens. `access_type`
/// influences whether the generated code calls [`Bus::read()`] or [`Bus::write()`] on
/// the matching peripheral field.
fn gen_match_tokens(mask_matches: &MaskMatchBlock, access_type: AccessType) -> TokenStream {
    let mut result = TokenStream::new();
    result.extend(TokenStream::from_str("match addr & ").unwrap());
    result.extend([hex_literal_u32(mask_matches.mask)]);
    let mut match_body = TokenStream::new();
    for m in mask_matches.match_arms.iter() {
        match_body.extend([hex_literal_u32(m.offset)]);
        match_body.extend(TokenStream::from_str(" => "));
        match m.body {
            MatchBody::Field(ref field_name) => {
                match_body
                    .extend(TokenStream::from_str("return caliptra_emu_cpu::Device::").unwrap());
                match access_type {
                    AccessType::Read => match_body.extend(TokenStream::from_str("read").unwrap()),
                    AccessType::Write => match_body.extend(TokenStream::from_str("write").unwrap()),
                }
                let mut params_body = TokenStream::new();
                match access_type {
                    AccessType::Read => {
                        params_body.extend(TokenStream::from_str("&self.").unwrap())
                    }
                    AccessType::Write => {
                        params_body.extend(TokenStream::from_str("&mut self.").unwrap())
                    }
                }
                params_body.extend([TokenTree::from(Ident::new(&field_name, Span::call_site()))]);
                params_body.extend(TokenStream::from_str(", size, addr & ").unwrap());
                params_body.extend([hex_literal_u32(!mask_matches.mask)]);
                if access_type == AccessType::Write {
                    params_body.extend(TokenStream::from_str(", val").unwrap());
                }
                match_body.extend([TokenTree::from(Group::new(
                    Delimiter::Parenthesis,
                    params_body,
                ))]);
            }
            MatchBody::SubMatchBlock(ref sub_mask_matches) => {
                match_body.extend(gen_match_tokens(&sub_mask_matches, access_type));
            }
        }
        match_body.extend(TokenStream::from_str(",").unwrap());
    }
    match_body.extend(TokenStream::from_str("_ => {}").unwrap());
    result.extend([TokenTree::from(Group::new(Delimiter::Brace, match_body))]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_lsbs_contiguous() {
        assert!(lsbs_contiguous(0x0000_0001));
        assert!(lsbs_contiguous(0x0000_00ff));
        assert!(lsbs_contiguous(0x1fff_ffff));
        assert!(lsbs_contiguous(0xffff_ffff));

        assert!(!lsbs_contiguous(0));
        assert!(!lsbs_contiguous(0x2));
        assert!(!lsbs_contiguous(0xff00_0000));
        assert!(!lsbs_contiguous(0x5555_5555));
    }

    #[test]
    fn test_parse_peripheral_fields() {
        let tokens = parse_peripheral_fields(
            TokenStream::from_str(
                r#"
                ignore_me: u32,

                #[peripheral(offset = 0x3000_0000, mask = 0x0fff_ffff)]
                #[ignore_me(foo = bar)]
                ram: Ram,

                #[peripheral(offset = 0x6000_0000, mask = 0x0fff_ffff)]
                pub uart: Uart,

        "#,
            )
            .unwrap(),
        );
        assert_eq!(
            tokens,
            vec![
                PeripheralField {
                    name: "ram".into(),
                    offset: 0x3000_0000,
                    mask: 0x0fff_ffff
                },
                PeripheralField {
                    name: "uart".into(),
                    offset: 0x6000_0000,
                    mask: 0x0fff_ffff
                },
            ]
        );
    }

    #[test]
    #[should_panic(expected = "More than one #[peripheral] attribute attached to field")]
    fn test_parse_peripheral_fields_duplicate() {
        parse_peripheral_fields(
            TokenStream::from_str(
                r#"

                #[peripheral(offset = 0x3000_0000, mask = 0x0fff_ffff)]
                #[peripheral(offset = 0x4000_0000, mask = 0x0fff_ffff)]
                ram: Ram,
        "#,
            )
            .unwrap(),
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_organize_fields_by_mask() {
        let foo = build_match_tree_from_fields(&[
            PeripheralField { name: "rom".into(), offset: 0x0000_0000, mask: 0x0fff_ffff },
            PeripheralField { name: "sram".into(), offset: 0x1000_0000, mask: 0x0fff_ffff },
            PeripheralField { name: "dram".into(), offset: 0x2000_0000, mask: 0x0fff_ffff },
            PeripheralField { name: "uart0".into(), offset: 0xaa00_0000, mask: 0x0000_ffff },
            PeripheralField { name: "uart1".into(), offset: 0xaa01_0000, mask: 0x0000_ffff },
            PeripheralField { name: "i2c0".into(), offset: 0xaa02_0000, mask: 0x0000_00ff },
            PeripheralField { name: "i2c1".into(), offset: 0xaa02_0040, mask: 0x0000_00ff },
            PeripheralField { name: "i2c2".into(), offset: 0xaa02_0080, mask: 0x0000_00ff },
            PeripheralField { name: "spi0".into(), offset: 0xbb42_0000, mask: 0x0000_ffff },
            ]);
        assert_eq!(foo, Some(MaskMatchBlock {
            mask: 0xf0000000,
            match_arms: vec![
                MatchArm { offset: 0x00000000, body: MatchBody::Field("rom".into()) },
                MatchArm { offset: 0x10000000, body: MatchBody::Field("sram".into()) },
                MatchArm { offset: 0x20000000, body: MatchBody::Field("dram".into()) },
                MatchArm { offset: 0xa0000000, body: MatchBody::SubMatchBlock(MaskMatchBlock {
                    mask: 0xffff0000,
                    match_arms: vec![
                        MatchArm { offset: 0xaa00_0000, body: MatchBody::Field("uart0".into()) },
                        MatchArm { offset: 0xaa01_0000, body: MatchBody::Field("uart1".into()) },
                        MatchArm { offset: 0xaa02_0000, body: MatchBody::SubMatchBlock(MaskMatchBlock {
                            mask: 0xffff_ff00,
                            match_arms: vec![
                                MatchArm { offset: 0xaa02_0000, body: MatchBody::Field("i2c0".into()) },
                                MatchArm { offset: 0xaa02_0040, body: MatchBody::Field("i2c1".into()) },
                                MatchArm { offset: 0xaa02_0080, body: MatchBody::Field("i2c2".into()) },
                            ],
                        })}
                    ],
                })},
                MatchArm {
                    offset: 0xb0000000,
                    body: MatchBody::SubMatchBlock(
                        MaskMatchBlock {
                            mask: 0xffff0000,
                            match_arms: vec![
                                MatchArm { offset: 0xbb420000, body: MatchBody::Field("spi0".into()) },
                            ],
                        },
                    ),
                },
            ],
        }));
    }

    #[test]
    fn test_derive_bus() {
        let tokens = derive_bus(
            TokenStream::from_str(
                r#"
            struct MyBus {
                #[peripheral(offset = 0x0000_0000, mask = 0x0fff_ffff)]
                pub rom: Rom,

                #[peripheral(offset = 0x1000_0000, mask = 0x0fff_ffff)]
                pub sram: Ram,

                #[peripheral(offset = 0x2000_0000, mask = 0x0fff_ffff)]
                pub dram: Ram,

                #[peripheral(offset = 0xaa00_0000, mask = 0x0000_ffff)]
                pub uart0: Uart,

                #[peripheral(offset = 0xaa01_0000, mask = 0x0000_ffff)]
                pub uart1: Uart,

                #[peripheral(offset = 0xaa02_0000, mask = 0x0000_00ff)]
                pub i2c0: I2c,

                #[peripheral(offset = 0xaa02_0400, mask = 0x0000_00ff)]
                pub i2c1: I2c,

                #[peripheral(offset = 0xaa02_0800, mask = 0x0000_00ff)]
                pub i2c2: I2c,

                #[peripheral(offset = 0xbb42_0000, mask = 0x0000_ffff)]
                pub spi0: Spi,
            }
        "#,
            )
            .unwrap(),
        );

        assert_eq!(tokens.to_string(),
            TokenStream::from_str(r#"
            impl caliptra_emu_cpu::Bus for MyBus {
                fn read(&self, size: caliptra_emu_cpu::RvSize, addr: caliptra_emu_cpu::RvAddr) -> Result<caliptra_emu_cpu::RvData, caliptra_emu_cpu::RvException> {
                    match addr & 0xf000_0000 {
                        0x0000_0000 => return caliptra_emu_cpu::Device::read(&self.rom, size, addr & 0x0fff_ffff),
                        0x1000_0000 => return caliptra_emu_cpu::Device::read(&self.sram, size, addr & 0x0fff_ffff),
                        0x2000_0000 => return caliptra_emu_cpu::Device::read(&self.dram, size, addr & 0x0fff_ffff),
                        0xa000_0000 => match addr & 0xffff_0000 {
                            0xaa00_0000 => return caliptra_emu_cpu::Device::read(&self.uart0, size, addr & 0x0000_ffff),
                            0xaa01_0000 => return caliptra_emu_cpu::Device::read(&self.uart1, size, addr & 0x0000_ffff),
                            0xaa02_0000 => match addr & 0xffff_ff00 {
                                0xaa02_0000 => return caliptra_emu_cpu::Device::read(&self.i2c0, size, addr & 0x0000_00ff),
                                0xaa02_0400 => return caliptra_emu_cpu::Device::read(&self.i2c1, size, addr & 0x0000_00ff),
                                0xaa02_0800 => return caliptra_emu_cpu::Device::read(&self.i2c2, size, addr & 0x0000_00ff),
                                _ => {}
                            },
                            _ => {}
                        },
                        0xb000_0000 => match addr & 0xffff_0000 {
                            0xbb42_0000 => return caliptra_emu_cpu::Device::read(&self.spi0, size, addr & 0x0000_ffff),
                            _ => {}
                        },
                        _ => {}
                    }
                    Err(caliptra_emu_cpu::RvException::load_access_fault(addr))
                }
                fn write(&mut self, size: caliptra_emu_cpu::RvSize, addr: caliptra_emu_cpu::RvAddr, val: caliptra_emu_cpu::RvData) -> Result<(), caliptra_emu_cpu::RvException> {
                    match addr & 0xf000_0000 {
                        0x0000_0000 => return caliptra_emu_cpu::Device::write(&mut self.rom, size, addr & 0x0fff_ffff, val),
                        0x1000_0000 => return caliptra_emu_cpu::Device::write(&mut self.sram, size, addr & 0x0fff_ffff, val),
                        0x2000_0000 => return caliptra_emu_cpu::Device::write(&mut self.dram, size, addr & 0x0fff_ffff, val),
                        0xa000_0000 => match addr & 0xffff_0000 {
                            0xaa00_0000 => return caliptra_emu_cpu::Device::write(&mut self.uart0, size, addr & 0x0000_ffff, val),
                            0xaa01_0000 => return caliptra_emu_cpu::Device::write(&mut self.uart1, size, addr & 0x0000_ffff, val),
                            0xaa02_0000 => match addr & 0xffff_ff00 {
                                0xaa02_0000 => return caliptra_emu_cpu::Device::write(&mut self.i2c0, size, addr & 0x0000_00ff, val),
                                0xaa02_0400 => return caliptra_emu_cpu::Device::write(&mut self.i2c1, size, addr & 0x0000_00ff, val),
                                0xaa02_0800 => return caliptra_emu_cpu::Device::write(&mut self.i2c2, size, addr & 0x0000_00ff, val),
                                _ => {}
                            },
                            _ => {}
                        },
                        0xb000_0000 => match addr & 0xffff_0000 {
                            0xbb42_0000 => return caliptra_emu_cpu::Device::write(&mut self.spi0, size, addr & 0x0000_ffff, val),
                            _ => {}
                        },
                        _ => {}
                    }
                    Err(caliptra_emu_cpu::RvException::store_access_fault(addr))
                }
            }
            "#).unwrap().to_string());
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    bus.rs

Abstract:

    Implements #[derive(Bus)], used for dispatching Bus::read() Bus::write() to
    fields of a struct.

--*/
use std::collections::HashMap;

use proc_macro2::{Delimiter, Group, Ident, Span, TokenStream, TokenTree};

use quote::{format_ident, quote};

use crate::util::literal::{self, hex_literal_u32};
use crate::util::sort::sorted_by_key;
use crate::util::token_iter::{
    expect_ident, skip_to_field_with_attributes, skip_to_group, skip_to_struct_with_attributes,
    Attribute,
};

pub fn derive_bus(input: TokenStream) -> TokenStream {
    let mut iter = input.into_iter();
    let struct_attrs = skip_to_struct_with_attributes(&mut iter);
    let poll_fn = get_poll_fn(&struct_attrs);
    let warm_reset_fn = get_warm_reset_fn(&struct_attrs);
    let update_reset_fn = get_update_reset_fn(&struct_attrs);
    let handle_dma_fn = get_handle_dma_fn(&struct_attrs);
    let struct_name = expect_ident(&mut iter);
    let struct_fields = skip_to_group(&mut iter, Delimiter::Brace);
    let peripheral_fields = parse_peripheral_fields(struct_fields.stream());
    let register_fields = parse_register_fields(struct_fields.stream());

    let mask_matches = build_match_tree_from_fields(&peripheral_fields);

    let read_bus_match_tokens = if let Some(mask_matches) = &mask_matches {
        gen_bus_match_tokens(mask_matches, AccessType::Read)
    } else {
        quote! {}
    };
    let write_bus_match_tokens = if let Some(mask_matches) = &mask_matches {
        gen_bus_match_tokens(mask_matches, AccessType::Write)
    } else {
        quote! {}
    };
    let read_reg_match_tokens = gen_register_match_tokens(&register_fields, AccessType::Read);
    let write_reg_match_tokens = gen_register_match_tokens(&register_fields, AccessType::Write);
    let self_poll_tokens = if let Some(poll_fn) = &poll_fn {
        let poll_fn = Ident::new(poll_fn, Span::call_site());
        quote! { Self::#poll_fn(self); }
    } else {
        quote! {}
    };
    let self_warm_reset_tokens = if let Some(warm_reset_fn) = &warm_reset_fn {
        let warm_reset_fn = Ident::new(warm_reset_fn, Span::call_site());
        quote! { Self::#warm_reset_fn(self); }
    } else {
        quote! {}
    };
    let self_update_reset_tokens = if let Some(update_reset_fn) = &update_reset_fn {
        let update_reset_fn = Ident::new(update_reset_fn, Span::call_site());
        quote! { Self::#update_reset_fn(self); }
    } else {
        quote! {}
    };
    let self_handle_dma_tokens = if let Some(handle_dma_fn) = &handle_dma_fn {
        let handle_dma_fn = Ident::new(handle_dma_fn, Span::call_site());
        quote! { Self::#handle_dma_fn(self); }
    } else {
        quote! {}
    };

    let field_idents: Vec<_> = peripheral_fields
        .iter()
        .map(|f| Ident::new(&f.name, Span::call_site()))
        .collect();

    quote! {
        impl caliptra_emu_bus::Bus for #struct_name {
            fn read(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr) -> Result<caliptra_emu_types::RvData, caliptra_emu_bus::BusError> {
                #read_reg_match_tokens
                #read_bus_match_tokens
                Err(caliptra_emu_bus::BusError::LoadAccessFault)
            }
            fn write(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr, val: caliptra_emu_types::RvData) -> Result<(), caliptra_emu_bus::BusError> {
                #write_reg_match_tokens
                #write_bus_match_tokens
                Err(caliptra_emu_bus::BusError::StoreAccessFault)
            }
            fn poll(&mut self) {
                #(self.#field_idents.poll();)*
                #self_poll_tokens
            }
            fn warm_reset(&mut self) {
                #(self.#field_idents.warm_reset();)*
                #self_warm_reset_tokens
            }
            fn update_reset(&mut self) {
                #(self.#field_idents.update_reset();)*
                #self_update_reset_tokens
            }
            fn handle_dma(&mut self) {
                #(self.#field_idents.handle_dma();)*
                #self_handle_dma_tokens
            }

        }
    }
}

fn get_poll_fn(struct_attrs: &[Group]) -> Option<String> {
    for attr in struct_attrs {
        let mut iter = attr.stream().into_iter();
        if let Some(TokenTree::Ident(ident)) = iter.next() {
            if ident == "poll_fn" {
                if let Some(TokenTree::Group(group)) = iter.next() {
                    if let Some(TokenTree::Ident(ident)) = group.stream().into_iter().next() {
                        return Some(ident.to_string());
                    }
                }
            }
        }
    }
    None
}

fn get_warm_reset_fn(struct_attrs: &[Group]) -> Option<String> {
    for attr in struct_attrs {
        let mut iter = attr.stream().into_iter();
        if let Some(TokenTree::Ident(ident)) = iter.next() {
            if ident == "warm_reset_fn" {
                if let Some(TokenTree::Group(group)) = iter.next() {
                    if let Some(TokenTree::Ident(ident)) = group.stream().into_iter().next() {
                        return Some(ident.to_string());
                    }
                }
            }
        }
    }
    None
}

fn get_update_reset_fn(struct_attrs: &[Group]) -> Option<String> {
    for attr in struct_attrs {
        let mut iter = attr.stream().into_iter();
        if let Some(TokenTree::Ident(ident)) = iter.next() {
            if ident == "update_reset_fn" {
                if let Some(TokenTree::Group(group)) = iter.next() {
                    if let Some(TokenTree::Ident(ident)) = group.stream().into_iter().next() {
                        return Some(ident.to_string());
                    }
                }
            }
        }
    }
    None
}

fn get_handle_dma_fn(struct_attrs: &[Group]) -> Option<String> {
    for attr in struct_attrs {
        let mut iter = attr.stream().into_iter();
        if let Some(TokenTree::Ident(ident)) = iter.next() {
            if ident == "handle_dma_fn" {
                if let Some(TokenTree::Group(group)) = iter.next() {
                    if let Some(TokenTree::Ident(ident)) = group.stream().into_iter().next() {
                        return Some(ident.to_string());
                    }
                }
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
struct RegisterField {
    // If this is None, read_fn and write_fn will be Some
    name: Option<String>,
    ty_tokens: TokenStream,
    offset: u32,
    read_fn: Option<String>,
    write_fn: Option<String>,
    is_array: bool,

    // Only used if ty_tokens is empty
    array_item_size: Option<usize>,

    // Only used if ty_tokens is empty
    array_len: Option<usize>,
}
fn has_read_and_write_fn(attr: &Attribute) -> bool {
    attr.args.contains_key("read_fn") && attr.args.contains_key("write_fn")
}

fn parse_register_fields(stream: TokenStream) -> Vec<RegisterField> {
    let mut iter = stream.into_iter();
    let mut result = Vec::new();
    while let Some(field) = skip_to_field_with_attributes(
        &mut iter,
        |name| name == "register" || name == "register_array",
        has_read_and_write_fn,
    ) {
        if field.attributes.is_empty() {
            continue;
        }
        if field.attributes.len() > 1 {
            panic!("More than one #[peripheral] attribute attached to field");
        }
        let attr = &field.attributes[0];
        if let Some(offset) = attr.args.get("offset").cloned() {
            result.push(RegisterField {
                name: field.field_name.map(|i| i.to_string()),
                ty_tokens: field.field_type,
                offset: literal::parse_hex_u32(offset),
                read_fn: attr.args.get("read_fn").map(|t| t.to_string()),
                write_fn: attr.args.get("write_fn").map(|t| t.to_string()),
                is_array: field.attr_name == "register_array",
                array_len: attr.args.get("len").map(literal::parse_usize),
                array_item_size: attr.args.get("item_size").map(literal::parse_usize),
            })
        } else {
            panic!(
                "register attribute on field {} must have offset parameter",
                field
                    .field_name
                    .map(|i| i.to_string())
                    .unwrap_or(attr.args.get("read_fn").unwrap().to_string())
            );
        }
    }
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
    while let Some(field) =
        skip_to_field_with_attributes(&mut iter, |name| name == "peripheral", |_| false)
    {
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
                name: field.field_name.unwrap().to_string(),
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
fn gen_bus_match_tokens(mask_matches: &MaskMatchBlock, access_type: AccessType) -> TokenStream {
    let match_mask = hex_literal_u32(mask_matches.mask);
    let addr_mask = hex_literal_u32(!mask_matches.mask);
    let match_arms = mask_matches.match_arms.iter().map(|m| {
        let offset = hex_literal_u32(m.offset);
        match (&m.body, access_type) {
            (MatchBody::Field(field_name), AccessType::Read) => {
                let field_name = Ident::new(field_name, Span::call_site());
                quote! {
                    #offset => return caliptra_emu_bus::Bus::read(&mut self.#field_name, size, addr & #addr_mask),
                }
            },
            (MatchBody::Field(field_name), AccessType::Write) => {
                let field_name = Ident::new(field_name, Span::call_site());
                quote! {
                    #offset => return caliptra_emu_bus::Bus::write(&mut self.#field_name, size, addr & #addr_mask, val),
                }
            },
            (MatchBody::SubMatchBlock(ref sub_mask_matches), _) => {
                let submatch_tokens = gen_bus_match_tokens(sub_mask_matches, access_type);
                quote! {
                    #offset => #submatch_tokens,
                }
            },
        }
    });
    quote! {
        match addr & #match_mask {
            #(#match_arms)*
            _ => {}
        }
    }
}

fn gen_register_match_tokens(registers: &[RegisterField], access_type: AccessType) -> TokenStream {
    let mut constant_tokens = TokenStream::new();
    let mut next_const_id = 0usize;
    let mut add_constant = |expr: TokenStream| -> Ident {
        let const_ident = format_ident!("CONST{}", next_const_id);
        next_const_id += 1;
        constant_tokens.extend(quote! {
            const #const_ident: u32 = #expr;
        });
        const_ident
    };

    if registers.is_empty() {
        return quote! {};
    }
    let match_arms: Vec<_> = registers.iter().map(|reg| {
        let offset = hex_literal_u32(reg.offset);

        let ty = &reg.ty_tokens;
        let item_size =  || {
            if reg.ty_tokens.is_empty() {
                let item_size = reg.array_item_size.unwrap_or_else(|| panic!("item_size must be defined for register_array at offset 0x{:08x}", reg.offset));
                quote! { #item_size }
            } else {
                quote! { <#ty as caliptra_emu_bus::RegisterArray>::ITEM_SIZE }
            }
        };
        let mut array_match_pattern = || -> TokenStream {
            let item_size = item_size();
            let len = if reg.ty_tokens.is_empty() {
                let array_len = reg.array_len.unwrap_or_else(|| panic!("len must be defined for register_array at offset 0x{:08x}", reg.offset));
                quote! { #array_len }
            } else {
                quote! { <#ty as caliptra_emu_bus::RegisterArray>::LEN }
            };
            let end_offset = add_constant(quote! { (#offset + (#len - 1) * #item_size) as u32 });
            quote! {
                #offset..=#end_offset if (addr as usize) % #item_size == 0
            }
        };
        let array_index = || {
            let item_size = item_size();
            quote! {
                (addr - #offset) as usize / #item_size
            }
        };

        match access_type {
            AccessType::Read => {
                if let Some(ref read_fn) = reg.read_fn {
                    let read_fn = Ident::new(read_fn, Span::call_site());
                    if reg.is_array {
                        let pattern = array_match_pattern();
                        let array_index = array_index();
                        quote! {
                            #pattern => return std::result::Result::Ok(
                                std::convert::Into::<caliptra_emu_types::RvAddr>::into(
                                    self.#read_fn(size, #array_index)?
                                )
                            ),
                        }
                    } else {
                        quote! {
                            #offset => return std::result::Result::Ok(
                                std::convert::Into::<caliptra_emu_types::RvAddr>::into(
                                    self.#read_fn(size)?
                                )
                            ),
                        }
                    }
                } else if let Some(ref reg_name) = reg.name {
                    let reg_name = Ident::new(reg_name, Span::call_site());
                    if reg.is_array {
                        let pattern = array_match_pattern();
                        let array_index = array_index();
                        quote! {
                            #pattern => return caliptra_emu_bus::Register::read(&self.#reg_name[#array_index], size),
                        }
                    } else {
                        quote! {
                            #offset => return caliptra_emu_bus::Register::read(&self.#reg_name, size),
                        }
                    }
                } else {
                    unreachable!();
                }
            },
            AccessType::Write => {
                if let Some(ref write_fn) = reg.write_fn {
                    let write_fn = Ident::new(write_fn, Span::call_site());
                    if reg.is_array {
                        let pattern = array_match_pattern();
                        let array_index = array_index();
                        quote! {
                            #pattern => return self.#write_fn(size, #array_index, std::convert::From::<caliptra_emu_types::RvAddr>::from(val)),
                        }
                    } else {
                        quote! {
                            #offset => return self.#write_fn(size, std::convert::From::<caliptra_emu_types::RvAddr>::from(val)),
                        }
                    }
                } else if let Some(ref reg_name) = reg.name {
                    let reg_name = Ident::new(reg_name, Span::call_site());
                    if reg.is_array {
                        let pattern = array_match_pattern();
                        let array_index = array_index();
                        quote! {
                           #pattern => return caliptra_emu_bus::Register::write(&mut self.#reg_name[#array_index], size, val),
                        }
                    } else {
                        quote! {
                            #offset => return caliptra_emu_bus::Register::write(&mut self.#reg_name, size, val),
                        }
                    }
                } else {
                    unreachable!();
                }
            }
        }
    }).collect();

    quote! {
        #constant_tokens
        match addr {
            #(#match_arms)*
            _ => {}
        }
    }
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
        let tokens = parse_peripheral_fields(quote! {
            ignore_me: u32,

            #[peripheral(offset = 0x3000_0000, mask = 0x0fff_ffff)]
            #[ignore_me(foo = bar)]
            ram: Ram,

            #[peripheral(offset = 0x6000_0000, mask = 0x0fff_ffff)]
            pub uart: Uart,
        });
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
        parse_peripheral_fields(quote! {

            #[peripheral(offset = 0x3000_0000, mask = 0x0fff_ffff)]
            #[peripheral(offset = 0x4000_0000, mask = 0x0fff_ffff)]
            ram: Ram,
        });
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
        let tokens = derive_bus(quote! {
            #[poll_fn(bus_poll)]
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

                #[register(offset = 0xcafe_f0d0)]
                pub reg_u32: u32,

                #[register(offset = 0xcafe_f0d4)]
                pub reg_u16: u16,

                #[register(offset = 0xcafe_f0d8)]
                pub reg_u8: u8,

                #[register(offset = 0xcafe_f0e0, read_fn = reg_action0_read)]
                pub reg_action0: u32,

                #[register(offset = 0xcafe_f0e4, write_fn = reg_action1_write)]
                pub reg_action1: u32,

                #[register_array(offset = 0xcafe_f0f4)]
                pub reg_array: [u32; 5],

                #[register_array(offset = 0xcafe_f114, read_fn = reg_array_action0_read)]
                pub reg_array_action0: [u32; 2],

                #[register_array(offset = 0xcafe_f11c, write_fn = reg_array_action1_write)]
                pub reg_array_action1: [u32; 2],

                #[register(offset = 0xcafe_f0e8, read_fn = reg_action2_read, write_fn = reg_action2_write)]
                #[register(offset = 0xcafe_f0ec, read_fn = reg_action3_read, write_fn = reg_action3_write)]
                #[register_array(offset = 0xcafe_f134, item_size = 4, len = 5, read_fn = reg_array_action2_read, write_fn = reg_array_action2_write)]
                _fieldless_regs: (),
            }
        });

        assert_eq!(tokens.to_string(),
            quote! {
                impl caliptra_emu_bus::Bus for MyBus {
                    fn read(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr) -> Result<caliptra_emu_types::RvData, caliptra_emu_bus::BusError> {
                        const CONST0: u32 = (0xcafe_f0f4 + (<[u32; 5] as caliptra_emu_bus::RegisterArray>::LEN - 1) * <[u32; 5] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE) as u32;
                        const CONST1: u32 = (0xcafe_f114 + (<[u32; 2] as caliptra_emu_bus::RegisterArray>::LEN - 1) * <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE) as u32;
                        const CONST2: u32 = (0xcafe_f11c + (<[u32; 2] as caliptra_emu_bus::RegisterArray>::LEN - 1) * <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE) as u32;
                        const CONST3: u32 = (0xcafe_f134 + (5usize - 1) * 4usize) as u32;
                        match addr {
                            0xcafe_f0d0 => return caliptra_emu_bus::Register::read(&self.reg_u32, size),
                            0xcafe_f0d4 => return caliptra_emu_bus::Register::read(&self.reg_u16, size),
                            0xcafe_f0d8 => return caliptra_emu_bus::Register::read(&self.reg_u8, size),
                            0xcafe_f0e0 => return std::result::Result::Ok(std::convert::Into::<caliptra_emu_types::RvAddr>::into(self.reg_action0_read(size)?)),
                            0xcafe_f0e4 => return caliptra_emu_bus::Register::read(&self.reg_action1, size),
                            0xcafe_f0f4..=CONST0 if (addr as usize) % <[u32; 5] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE == 0 => return caliptra_emu_bus::Register::read(&self.reg_array[(addr - 0xcafe_f0f4) as usize /  <[u32; 5] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE], size),
                            0xcafe_f114..=CONST1 if (addr as usize) % <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE == 0 => return std::result::Result::Ok(std::convert::Into::<caliptra_emu_types::RvAddr>::into(self.reg_array_action0_read(size, (addr - 0xcafe_f114) as usize /  <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE)?)),
                            0xcafe_f11c..=CONST2 if (addr as usize) % <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE == 0 => return caliptra_emu_bus::Register::read(&self.reg_array_action1[(addr - 0xcafe_f11c) as usize /  <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE], size),
                            0xcafe_f0e8 => return std::result::Result::Ok(std::convert::Into::<caliptra_emu_types::RvAddr>::into(self.reg_action2_read(size)?)),
                            0xcafe_f0ec => return std::result::Result::Ok(std::convert::Into::<caliptra_emu_types::RvAddr>::into(self.reg_action3_read(size)?)),
                            0xcafe_f134..=CONST3 if (addr as usize) % 4usize == 0 => return std::result::Result::Ok(std::convert::Into::<caliptra_emu_types::RvAddr>::into(self.reg_array_action2_read(size, (addr - 0xcafe_f134) as usize / 4usize)?)),
                            _ => {}
                        }
                        match addr & 0xf000_0000 {
                            0x0000_0000 => return caliptra_emu_bus::Bus::read(&mut self.rom, size, addr & 0x0fff_ffff),
                            0x1000_0000 => return caliptra_emu_bus::Bus::read(&mut self.sram, size, addr & 0x0fff_ffff),
                            0x2000_0000 => return caliptra_emu_bus::Bus::read(&mut self.dram, size, addr & 0x0fff_ffff),
                            0xa000_0000 => match addr & 0xffff_0000 {
                                0xaa00_0000 => return caliptra_emu_bus::Bus::read(&mut self.uart0, size, addr & 0x0000_ffff),
                                0xaa01_0000 => return caliptra_emu_bus::Bus::read(&mut self.uart1, size, addr & 0x0000_ffff),
                                0xaa02_0000 => match addr & 0xffff_ff00 {
                                    0xaa02_0000 => return caliptra_emu_bus::Bus::read(&mut self.i2c0, size, addr & 0x0000_00ff),
                                    0xaa02_0400 => return caliptra_emu_bus::Bus::read(&mut self.i2c1, size, addr & 0x0000_00ff),
                                    0xaa02_0800 => return caliptra_emu_bus::Bus::read(&mut self.i2c2, size, addr & 0x0000_00ff),
                                    _ => {}
                                },
                                _ => {}
                            },
                            0xb000_0000 => match addr & 0xffff_0000 {
                                0xbb42_0000 => return caliptra_emu_bus::Bus::read(&mut self.spi0, size, addr & 0x0000_ffff),
                                _ => {}
                            },
                            _ => {}
                        }
                        Err(caliptra_emu_bus::BusError::LoadAccessFault)
                    }
                    fn write(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr, val: caliptra_emu_types::RvData) -> Result<(), caliptra_emu_bus::BusError> {
                        const CONST0: u32 = (0xcafe_f0f4 + (<[u32; 5] as caliptra_emu_bus::RegisterArray>::LEN - 1) * <[u32; 5] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE) as u32;
                        const CONST1: u32 = (0xcafe_f114 + (<[u32; 2] as caliptra_emu_bus::RegisterArray>::LEN - 1) * <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE) as u32;
                        const CONST2: u32 = (0xcafe_f11c + (<[u32; 2] as caliptra_emu_bus::RegisterArray>::LEN - 1) * <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE) as u32;
                        const CONST3: u32 = (0xcafe_f134 + (5usize - 1) * 4usize) as u32;
                        match addr {
                            0xcafe_f0d0 => return caliptra_emu_bus::Register::write(&mut self.reg_u32, size, val),
                            0xcafe_f0d4 => return caliptra_emu_bus::Register::write(&mut self.reg_u16, size, val),
                            0xcafe_f0d8 => return caliptra_emu_bus::Register::write(&mut self.reg_u8, size, val),
                            0xcafe_f0e0 => return caliptra_emu_bus::Register::write(&mut self.reg_action0, size, val),
                            0xcafe_f0e4 => return self.reg_action1_write(size, std::convert::From::<caliptra_emu_types::RvAddr>::from(val)),
                            0xcafe_f0f4..=CONST0 if (addr as usize) % <[u32; 5] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE == 0 => return caliptra_emu_bus::Register::write(&mut self.reg_array[(addr - 0xcafe_f0f4) as usize /  <[u32; 5] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE], size, val),
                            0xcafe_f114..=CONST1 if (addr as usize) % <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE == 0 => return caliptra_emu_bus::Register::write(&mut self.reg_array_action0[(addr - 0xcafe_f114) as usize /  <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE], size, val),
                            0xcafe_f11c..=CONST2 if (addr as usize) % <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE == 0 => return self.reg_array_action1_write(size, (addr - 0xcafe_f11c) as usize /  <[u32; 2] as caliptra_emu_bus::RegisterArray>::ITEM_SIZE, std::convert::From::<caliptra_emu_types::RvAddr>::from(val)),
                            0xcafe_f0e8 => return self.reg_action2_write(size, std::convert::From::<caliptra_emu_types::RvAddr>::from(val)),
                            0xcafe_f0ec => return self.reg_action3_write(size, std::convert::From::<caliptra_emu_types::RvAddr>::from(val)),
                            0xcafe_f134..=CONST3 if (addr as usize) % 4usize == 0 => return self.reg_array_action2_write(size, (addr - 0xcafe_f134) as usize / 4usize, std::convert::From::<caliptra_emu_types::RvAddr>::from(val)),
                            _ => {}
                        }
                        match addr & 0xf000_0000 {
                            0x0000_0000 => return caliptra_emu_bus::Bus::write(&mut self.rom, size, addr & 0x0fff_ffff, val),
                            0x1000_0000 => return caliptra_emu_bus::Bus::write(&mut self.sram, size, addr & 0x0fff_ffff, val),
                            0x2000_0000 => return caliptra_emu_bus::Bus::write(&mut self.dram, size, addr & 0x0fff_ffff, val),
                            0xa000_0000 => match addr & 0xffff_0000 {
                                0xaa00_0000 => return caliptra_emu_bus::Bus::write(&mut self.uart0, size, addr & 0x0000_ffff, val),
                                0xaa01_0000 => return caliptra_emu_bus::Bus::write(&mut self.uart1, size, addr & 0x0000_ffff, val),
                                0xaa02_0000 => match addr & 0xffff_ff00 {
                                    0xaa02_0000 => return caliptra_emu_bus::Bus::write(&mut self.i2c0, size, addr & 0x0000_00ff, val),
                                    0xaa02_0400 => return caliptra_emu_bus::Bus::write(&mut self.i2c1, size, addr & 0x0000_00ff, val),
                                    0xaa02_0800 => return caliptra_emu_bus::Bus::write(&mut self.i2c2, size, addr & 0x0000_00ff, val),
                                    _ => {}
                                },
                                _ => {}
                            },
                            0xb000_0000 => match addr & 0xffff_0000 {
                                0xbb42_0000 => return caliptra_emu_bus::Bus::write(&mut self.spi0, size, addr & 0x0000_ffff, val),
                                _ => {}
                            },
                            _ => {}
                        }
                        Err(caliptra_emu_bus::BusError::StoreAccessFault)
                    }
                    fn poll(&mut self) {
                        self.rom.poll();
                        self.sram.poll();
                        self.dram.poll();
                        self.uart0.poll();
                        self.uart1.poll();
                        self.i2c0.poll();
                        self.i2c1.poll();
                        self.i2c2.poll();
                        self.spi0.poll();
                        Self::bus_poll(self);
                    }
                    fn warm_reset(&mut self) {
                        self.rom.warm_reset();
                        self.sram.warm_reset();
                        self.dram.warm_reset();
                        self.uart0.warm_reset();
                        self.uart1.warm_reset();
                        self.i2c0.warm_reset();
                        self.i2c1.warm_reset();
                        self.i2c2.warm_reset();
                        self.spi0.warm_reset();
                    }
                    fn update_reset(&mut self) {
                        self.rom.update_reset();
                        self.sram.update_reset();
                        self.dram.update_reset();
                        self.uart0.update_reset();
                        self.uart1.update_reset();
                        self.i2c0.update_reset();
                        self.i2c1.update_reset();
                        self.i2c2.update_reset();
                        self.spi0.update_reset();
                    }
                    fn handle_dma(&mut self) {
                        self.rom.handle_dma();
                        self.sram.handle_dma();
                        self.dram.handle_dma();
                        self.uart0.handle_dma();
                        self.uart1.handle_dma();
                        self.i2c0.handle_dma();
                        self.i2c1.handle_dma();
                        self.i2c2.handle_dma();
                        self.spi0.handle_dma();
                    }
                }
            }.to_string()
        );
    }

    #[test]
    fn test_derive_empty_bus() {
        let tokens = derive_bus(quote! {
            pub struct MyBus {}
        });

        assert_eq!(tokens.to_string(),
            quote! {
                impl caliptra_emu_bus::Bus for MyBus {
                    fn read(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr) -> Result<caliptra_emu_types::RvData, caliptra_emu_bus::BusError> {
                        Err(caliptra_emu_bus::BusError::LoadAccessFault)
                    }
                    fn write(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr, val: caliptra_emu_types::RvData) -> Result<(), caliptra_emu_bus::BusError> {
                        Err(caliptra_emu_bus::BusError::StoreAccessFault)
                    }
                    fn poll(&mut self) {
                    }
                    fn warm_reset(&mut self) {
                    }
                    fn update_reset(&mut self) {
                    }
                    fn handle_dma(&mut self) {
                    }
                }
            }.to_string()
        );
    }
}

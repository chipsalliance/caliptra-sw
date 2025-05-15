/*++

Licensed under the Apache-2.0 license.

File Name:

    bus.rs

Abstract:

    Implements #[derive(Bus)], used for dispatching Bus::read() Bus::write() to
    fields of a struct.

--*/
use crate::util::literal::{self, hex_literal_u32};
use crate::util::token_iter::{
    expect_ident, skip_to_field_with_attributes, skip_to_group, skip_to_struct_with_attributes,
    Attribute,
};
use proc_macro2::{Delimiter, Group, Ident, Span, TokenStream, TokenTree};
use quote::{format_ident, quote};

pub fn derive_bus(input: TokenStream) -> TokenStream {
    let mut iter = input.into_iter();
    let struct_attrs = skip_to_struct_with_attributes(&mut iter);
    let poll_fn = get_fn(&struct_attrs, "poll_fn");
    let warm_reset_fn = get_fn(&struct_attrs, "warm_reset_fn");
    let update_reset_fn = get_fn(&struct_attrs, "update_reset_fn");
    let incoming_event_fn = get_fn(&struct_attrs, "incoming_event_fn");
    let register_outgoing_events_fn = get_fn(&struct_attrs, "register_outgoing_events_fn");
    let struct_name = expect_ident(&mut iter);
    let struct_fields = skip_to_group(&mut iter, Delimiter::Brace);
    let peripheral_fields = parse_peripheral_fields(struct_fields.stream());
    let register_fields = parse_register_fields(struct_fields.stream());

    let offset_matches = build_match_tree_from_fields(&peripheral_fields);

    let read_bus_match_tokens = if let Some(offset_matches) = &offset_matches {
        gen_bus_match_tokens(offset_matches, AccessType::Read)
    } else {
        quote! {}
    };
    let write_bus_match_tokens = if let Some(offset_matches) = &offset_matches {
        gen_bus_match_tokens(offset_matches, AccessType::Write)
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

    let self_incoming_event_tokens = if let Some(incoming_event_fn) = &incoming_event_fn {
        let incoming_event_fn = Ident::new(incoming_event_fn, Span::call_site());
        quote! {
            Self::#incoming_event_fn(self, event);
        }
    } else {
        quote! {}
    };
    let self_register_outgoing_events_tokens =
        if let Some(register_outgoing_events_fn) = &register_outgoing_events_fn {
            let register_outgoing_events_fn =
                Ident::new(register_outgoing_events_fn, Span::call_site());
            quote! { Self::#register_outgoing_events_fn(self, sender); }
        } else {
            quote! {}
        };

    let field_idents: Vec<_> = peripheral_fields
        .iter()
        .filter(|f| !f.refcell)
        .map(|f| Ident::new(&f.name, Span::call_site()))
        .collect();

    let field_idents_refcell: Vec<_> = peripheral_fields
        .iter()
        .filter(|f| f.refcell)
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
                #(self.#field_idents_refcell.borrow_mut().poll();)*
                #self_poll_tokens
            }
            fn warm_reset(&mut self) {
                #(self.#field_idents.warm_reset();)*
                #(self.#field_idents_refcell.borrow_mut().warm_reset();)*
                #self_warm_reset_tokens
            }
            fn update_reset(&mut self) {
                #(self.#field_idents.update_reset();)*
                #(self.#field_idents_refcell.borrow_mut().update_reset();)*
                #self_update_reset_tokens
            }
            fn incoming_event(&mut self, event: std::rc::Rc<caliptra_emu_bus::Event>) {
                #(self.#field_idents.incoming_event(event.clone());)*
                #self_incoming_event_tokens
            }
            fn register_outgoing_events(&mut self, sender: std::sync::mpsc::Sender<caliptra_emu_bus::Event>) {
                #(self.#field_idents.register_outgoing_events(sender.clone());)*
                #self_register_outgoing_events_tokens
            }
        }
    }
}

fn get_fn(struct_attrs: &[Group], name: &str) -> Option<String> {
    for attr in struct_attrs {
        let mut iter = attr.stream().into_iter();
        if let Some(TokenTree::Ident(ident)) = iter.next() {
            if ident == name {
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
    len: u32,
    refcell: bool,
}

fn contains_refcell(stream: TokenStream) -> bool {
    stream.into_iter().any(|t| match t {
        TokenTree::Group(group) => contains_refcell(group.stream()),
        TokenTree::Ident(ident) => ident == "RefCell",
        _ => false,
    })
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
        if let (Some(offset), Some(len)) = (
            attr.args.get("offset").cloned(),
            attr.args.get("len").cloned(),
        ) {
            result.push(PeripheralField {
                name: field.field_name.unwrap().to_string(),
                offset: literal::parse_hex_u32(offset),
                len: literal::parse_hex_u32(len),
                refcell: contains_refcell(field.field_type),
            })
        } else {
            panic!("peripheral attribute must have offset and len parameters and be placed before a field offset={:?} len={:?}", attr.args.get("offset"), attr.args.get("len"));
        }
    }
    result
}

/// The arms of the match block.
type LengthMatchBlock = Vec<MatchArm>;

/// Represents a match arm of the form `offset` => `body`.
#[derive(Debug, Eq, PartialEq)]
struct MatchArm {
    /// The offset used in the pattern of a mask arm.
    offset: u32,

    /// The offset + len used in the pattern of a mask arm.
    len: u32,

    /// Whether the type is a RefCell.
    refcell: bool,

    /// The expression right of "=>" in the match arm.
    body: String,
}

/// Given a list of fields (with their peripheral arguments), generate a tree of
/// offset and len match blocks (to be converted to Rust tokens later).
fn build_match_tree_from_fields(fields: &[PeripheralField]) -> Option<LengthMatchBlock> {
    if fields.is_empty() {
        return None;
    }

    let mut fields_by_offset = fields.to_vec();
    fields_by_offset.sort_unstable_by_key(|field| field.offset);

    // NOTE: for now this implementation generates match blocks rather simplistically
    // This could be optimised further - if we split the address space into different
    // spans, like a tree, we can decrease the number of comparisons on average.
    let mut matches: LengthMatchBlock = Vec::new();
    for field in fields_by_offset.iter() {
        matches.push(MatchArm {
            offset: field.offset,
            len: field.len,
            body: field.name.clone(),
            refcell: field.refcell,
        });
    }
    Some(matches)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccessType {
    Read,
    Write,
}

/// Serialize `offset_matches` into a stream of Rust tokens. `access_type`
/// influences whether the generated code calls [`Bus::read()`] or [`Bus::write()`] on
/// the matching peripheral field.
fn gen_bus_match_tokens(offset_matches: &LengthMatchBlock, access_type: AccessType) -> TokenStream {
    let match_arms = offset_matches.iter().map(|m| {
        let offset = hex_literal_u32(m.offset);
        let offset_len = if m.len > 0 {
            hex_literal_u32(m.offset + (m.len - 1))
        } else {
            hex_literal_u32(m.offset)
        };
        match access_type {
            AccessType::Read => {
                let field_name = Ident::new(&m.body, Span::call_site());
                if m.refcell {
                    quote! {
                        #offset..=#offset_len => return self.#field_name.borrow_mut().read(size, addr - #offset),
                    }
                } else {
                    quote! {
                        #offset..=#offset_len => return caliptra_emu_bus::Bus::read(&mut self.#field_name, size, addr - #offset),
                    }
                }
            },
            AccessType::Write => {
                let field_name = Ident::new(&m.body, Span::call_site());
                if m.refcell {
                    quote! {
                        #offset..=#offset_len => return self.#field_name.borrow_mut().write(size, addr - #offset, val),
                    }
                } else {
                    quote! {
                        #offset..=#offset_len => return caliptra_emu_bus::Bus::write(&mut self.#field_name, size, addr - #offset, val),
                    }
                }
            },
        }
    });
    quote! {
        match addr {
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
    fn test_parse_peripheral_fields() {
        let tokens = parse_peripheral_fields(quote! {
            ignore_me: u32,

            #[peripheral(offset = 0x3000_0000, len = 0xffff)]
            #[ignore_me(foo = bar)]
            ram: Ram,

            #[peripheral(offset = 0x6000_0000, len = 0x34)]
            pub uart: Uart,
        });
        assert_eq!(
            tokens,
            vec![
                PeripheralField {
                    name: "ram".into(),
                    offset: 0x3000_0000,
                    len: 0xffff,
                    refcell: false,
                },
                PeripheralField {
                    name: "uart".into(),
                    offset: 0x6000_0000,
                    len: 0x34,
                    refcell: false,
                },
            ]
        );
    }

    #[test]
    #[should_panic(expected = "More than one #[peripheral] attribute attached to field")]
    fn test_parse_peripheral_fields_duplicate() {
        parse_peripheral_fields(quote! {

            #[peripheral(offset = 0x3000_0000, len = 0xffff)]
            #[peripheral(offset = 0x4000_0000, len = 0xffff)]
            ram: Ram,
        });
    }

    #[test]
    #[rustfmt::skip]
    fn test_organize_fields_by_mask() {
        let foo = build_match_tree_from_fields(&[
            PeripheralField { name: "rom".into(), offset: 0x0000_0000, len: 0xffff, refcell: false },
            PeripheralField { name: "sram".into(), offset: 0x1000_0000, len: 0xffff, refcell: false },
            PeripheralField { name: "dram".into(), offset: 0x2000_0000, len: 0xffff, refcell: false },
            PeripheralField { name: "uart0".into(), offset: 0xaa00_0000, len: 0x34, refcell: false },
            PeripheralField { name: "uart1".into(), offset: 0xaa01_0000, len: 0x34, refcell: false },
            PeripheralField { name: "i2c0".into(), offset: 0xaa02_0000, len: 0x80, refcell: false },
            PeripheralField { name: "i2c1".into(), offset: 0xaa02_0040, len: 0x80, refcell: false },
            PeripheralField { name: "i2c2".into(), offset: 0xaa02_0080, len: 0x80, refcell: false },
            PeripheralField { name: "spi0".into(), offset: 0xbb42_0000, len: 0x10000, refcell: false },
            ]);
        assert_eq!(foo, Some(vec![
            MatchArm { offset: 0x0000_0000, len: 0xffff, body: "rom".into(), refcell: false },
            MatchArm { offset: 0x1000_0000, len: 0xffff, body: "sram".into(), refcell: false },
            MatchArm { offset: 0x2000_0000, len: 0xffff, body: "dram".into(), refcell: false },
            MatchArm { offset: 0xaa00_0000, len: 0x34, body: "uart0".into(), refcell: false },
            MatchArm { offset: 0xaa01_0000, len: 0x34, body: "uart1".into(), refcell: false },
            MatchArm { offset: 0xaa02_0000, len: 0x80, body: "i2c0".into(), refcell: false },
            MatchArm { offset: 0xaa02_0040, len: 0x80, body: "i2c1".into(), refcell: false },
            MatchArm { offset: 0xaa02_0080, len: 0x80, body: "i2c2".into(), refcell: false },
            MatchArm { offset: 0xbb42_0000, len: 0x10000, body: "spi0".into(), refcell: false },
        ]));
    }

    /* TODO: fix this test for new system
    #[test]
    fn test_derive_bus() {
        let tokens = derive_bus(quote! {
            #[poll_fn(bus_poll)]
            struct MyBus {
                #[peripheral(offset = 0x0000_0000, len = 0x0100_0000)]
                pub rom: Rom,

                #[peripheral(offset = 0x1000_0000, len = 0x0100_0000)]
                pub sram: Ram,

                #[peripheral(offset = 0x2000_0000, len = 0x0100_0000)]
                pub dram: Ram,

                #[peripheral(offset = 0xaa00_0000, len = 0x34)]
                pub uart0: Uart,

                #[peripheral(offset = 0xaa01_0000, len = 0x34)]
                pub uart1: Uart,

                #[peripheral(offset = 0xaa02_0000, len = 0x80)]
                pub i2c0: I2c,

                #[peripheral(offset = 0xaa02_0400, len = 0x80)]
                pub i2c1: I2c,

                #[peripheral(offset = 0xaa02_0800, len = 0x80)]
                pub i2c2: I2c,

                #[peripheral(offset = 0xbb42_0000, len = 0x10000)]
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

        // TODO
        assert_eq!(tokens.to_string(),
            quote! {...})
    */

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
                    fn incoming_event(&mut self, event: std::rc::Rc<caliptra_emu_bus::Event>) {
                    }
                    fn register_outgoing_events(&mut self, sender: std::sync::mpsc::Sender<caliptra_emu_bus::Event>) {
                    }
                }
            }.to_string()
        );
    }
}

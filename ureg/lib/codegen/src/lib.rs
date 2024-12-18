/*++
Licensed under the Apache-2.0 license.
--*/

use std::{collections::HashMap, rc::Rc, str::FromStr};

use proc_macro2::{Ident, Literal, TokenStream};
use quote::{format_ident, quote};
use ureg_schema::{
    Enum, EnumVariant, FieldType, Register, RegisterBlock, RegisterSubBlock, RegisterType,
    RegisterWidth, ValidatedRegisterBlock,
};

fn tweak_keywords(s: &str) -> &str {
    match s {
        "as" => "as_",
        "break" => "break_",
        "const" => "const_",
        "continue" => "continue_",
        "crate" => "crate_",
        "else" => "else_",
        "fn" => "fn_",
        "for" => "for_",
        "if" => "if_",
        "impl" => "impl_",
        "in" => "in_",
        "let" => "let_",
        "loop" => "loop_",
        "match" => "match_",
        "mod" => "mod_",
        "move" => "move_",
        "mut" => "mut_",
        "pub" => "pub_",
        "ref" => "ref_",
        "return" => "return_",
        "self" => "self_",
        "Self" => "Self_",
        "static" => "static_",
        "struct" => "struct_",
        "super" => "super_",
        "trait" => "trait_",
        "true" => "true_",
        "type" => "type_",
        "unsafe" => "unsafe_",
        "use" => "use_",
        "where" => "where_",
        "while" => "while_",
        "async" => "async_",
        "await" => "await_",
        "dyn" => "dyn_",
        "abstract" => "abstract_",
        "become" => "become_",
        "box" => "box_",
        "do" => "do_",
        "final" => "final_",
        "macro" => "macro_",
        "override" => "override_",
        "priv" => "priv_",
        "typeof" => "typeof_",
        "unsized" => "unsized_",
        "virtual" => "virtual_",
        "yield" => "yield_",
        s => s,
    }
}

fn snake_ident(name: &str) -> Ident {
    let mut result = String::new();
    if let Some(c) = name.chars().next() {
        if c.is_ascii_digit() {
            result.push('_');
        }
    }
    let mut prev = None;
    for c in name.chars() {
        if c.is_ascii_whitespace() || c.is_ascii_punctuation() {
            if prev != Some('_') {
                result.push('_');
            }
            prev = Some('_');
            continue;
        }
        if let Some(prev) = prev {
            if (prev.is_ascii_lowercase() || prev.is_ascii_digit()) && c.is_ascii_uppercase() {
                result.push('_');
            }
        }
        prev = Some(c);
        result.push(c.to_ascii_lowercase());
    }

    result = result.replace("i3_c", "i3c_").replace("__", "_"); // hack for I3C
    format_ident!("{}", tweak_keywords(result.trim_end_matches('_')))
}
#[cfg(test)]
mod snake_ident_tests {
    use crate::*;

    #[test]
    fn test_snake_ident() {
        assert_eq!("_8_bits", snake_ident("8 bits").to_string());
        assert_eq!("_16_bits", snake_ident("16_Bits").to_string());
        assert_eq!("_16_bits", snake_ident("16Bits").to_string());
        assert_eq!("_16bits", snake_ident("16bits").to_string());
        assert_eq!("foo_bar_baz", snake_ident("fooBarBaz").to_string());
        assert_eq!("foo_bar_baz", snake_ident("FooBarBaz").to_string());
        assert_eq!("foo_bar_baz", snake_ident("foo bar baz").to_string());
        assert_eq!("foo_bar_baz", snake_ident("foo_bar_baz").to_string());
        assert_eq!("foo_bar_baz", snake_ident("FOO BAR BAZ").to_string());
        assert_eq!("foo_bar_baz", snake_ident("FOO_BAR_BAZ").to_string());
        assert_eq!("foo_bar_baz", snake_ident("FOO BAR BAZ.").to_string());
        assert_eq!("foo_bar_baz", snake_ident("FOO BAR.BAZ.").to_string());
        assert_eq!("foo_bar_baz", snake_ident("FOO BAR..BAZ.").to_string());

        assert_eq!("fn_", snake_ident("fn").to_string());
        assert_eq!("fn_", snake_ident("FN").to_string());
    }
}

fn camel_ident(name: &str) -> Ident {
    let mut result = String::new();
    if let Some(c) = name.chars().next() {
        if c.is_ascii_digit() {
            result.push('_');
        }
    }
    let mut upper_next = true;
    for c in name.chars() {
        if c.is_ascii_punctuation() || c.is_ascii_whitespace() {
            upper_next = true;
        } else {
            result.push(if upper_next {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            });
            upper_next = false;
        }
    }
    format_ident!("{}", tweak_keywords(&result))
}

#[cfg(test)]
mod camel_ident_tests {
    use crate::*;

    #[test]
    fn test_camel_ident() {
        assert_eq!("_8Bits", camel_ident("8 bits").to_string());
        assert_eq!("_16Bits", camel_ident("16_bits").to_string());
        assert_eq!("FooBarBaz", camel_ident("foo bar baz").to_string());
        assert_eq!("FooBarBaz", camel_ident("foo_bar_baz").to_string());
        assert_eq!("FooBarBaz", camel_ident("FOO BAR BAZ").to_string());
        assert_eq!("FooBarBaz", camel_ident("FOO_BAR_BAZ").to_string());
        assert_eq!("FooBarBaz", camel_ident("FOO BAR BAZ.").to_string());
        assert_eq!("FooBarBaz", camel_ident("FOO BAR.BAZ.").to_string());
        assert_eq!("Self_", camel_ident("self").to_string());
    }
}

fn generate_enum(e: &Enum) -> TokenStream {
    let mut variant_tokens = TokenStream::new();
    let mut accessor_tokens = TokenStream::new();
    let mut from_u32_tokens = TokenStream::new();
    let mut variant_map: HashMap<u32, &EnumVariant> = e
        .variants
        .iter()
        .map(|variant| (variant.value, variant))
        .collect();
    for i in 0..(1u32 << e.bit_width) {
        let variant = variant_map.remove(&i);

        let variant_ident = match variant {
            Some(variant) => camel_ident(&variant.name),
            None => format_ident!("Reserved{}", i),
        };
        let variant_value = Literal::u32_unsuffixed(i);
        variant_tokens.extend(quote! {
            #variant_ident = #variant_value,
        });
        from_u32_tokens.extend(quote! {
            #variant_value => Ok(Self::#variant_ident),
        });
        if let Some(variant) = variant {
            let accessor_ident = snake_ident(&variant.name);
            accessor_tokens.extend(quote! {
                #[inline(always)]
                pub fn #accessor_ident(&self) -> bool {
                    *self == Self::#variant_ident
                }
            });
        }
    }
    let total_count = hex_literal(1u64 << e.bit_width);

    // unwrap is safe because this came from a ValidatedRegisterBlock
    let enum_name = camel_ident(e.name.as_ref().unwrap());
    quote! {
        #[derive(Clone, Copy, Eq, PartialEq)]
        #[repr(u32)]
        pub enum #enum_name {
            #variant_tokens
        }
        impl #enum_name {
            #accessor_tokens
        }
        impl TryFrom<u32> for #enum_name {
            type Error = ();
            #[inline(always)]
            fn try_from(val: u32) -> Result<#enum_name, ()> {
                if val < #total_count {
                    // This transmute is safe because the check above ensures
                    // that the value has a corresponding enum variant, and the
                    // enum is using repr(u32).
                    Ok(unsafe { core::mem::transmute::<u32, #enum_name>(val) } )
                } else {
                    Err(())
                }
            }
        }
        impl From<#enum_name> for u32 {
            fn from(val: #enum_name) -> Self {
                val as u32
            }
        }
    }
}

fn generate_enum_selector(e: &Enum) -> TokenStream {
    let enum_name = camel_ident(e.name.as_ref().unwrap());
    let mut selector_tokens = TokenStream::new();
    for variant in e.variants.iter() {
        let selector_ident = snake_ident(&variant.name);
        let variant_ident = camel_ident(&variant.name);
        selector_tokens.extend(quote! {
            #[inline(always)]
            pub fn #selector_ident(&self) -> super::#enum_name {
                super::#enum_name::#variant_ident
            }
        });
    }

    let selector_name = format_ident!("{}Selector", enum_name);
    quote! {
        pub struct #selector_name();
        impl #selector_name {
            #selector_tokens
        }
    }
}

fn generate_enums<'a>(enums: impl Iterator<Item = &'a Enum>) -> TokenStream {
    let mut enum_tokens = TokenStream::new();
    let mut selector_tokens = TokenStream::new();
    let mut enums: Vec<_> = enums.collect();
    enums.sort_by_key(|e| &e.name);
    for e in enums {
        enum_tokens.extend(generate_enum(e));
        selector_tokens.extend(generate_enum_selector(e));
    }
    quote! {
        #enum_tokens
        pub mod selector {
            #selector_tokens
        }
    }
}

#[cfg(test)]
mod generate_enums_test {
    use ureg_schema::EnumVariant;

    use crate::*;

    #[test]
    fn test_generate_enums() {
        assert_eq!(
            generate_enums(
                [Enum {
                    name: Some("Pull DIR".into()),
                    bit_width: 2,
                    variants: vec![
                        EnumVariant {
                            name: "down".to_string(),
                            value: 0
                        },
                        EnumVariant {
                            name: "UP".to_string(),
                            value: 1
                        },
                        EnumVariant {
                            name: "Hi Z".to_string(),
                            value: 2
                        },
                    ]
                }]
                .iter()
            )
            .to_string(),
            quote! {
                #[derive (Clone , Copy , Eq , PartialEq)]
                #[repr(u32)]
                pub enum PullDir {
                    Down = 0,
                    Up = 1,
                    HiZ = 2,
                    Reserved3 = 3,
                }
                impl PullDir {
                    #[inline(always)]
                    pub fn down(&self) -> bool { *self == Self::Down }
                    #[inline(always)]
                    pub fn up(&self) -> bool { *self == Self::Up }
                    #[inline(always)]
                    pub fn hi_z(&self) -> bool { *self == Self::HiZ }
                }
                impl TryFrom<u32> for PullDir {
                    type Error = ();
                    #[inline (always)]
                    fn try_from(val : u32) -> Result<PullDir, ()> {
                        if val < 4 {
                            Ok(unsafe { core::mem::transmute(val) })
                        } else {
                            Err (())
                        }
                     }
                }
                impl From<PullDir> for u32 {
                    fn from(val : PullDir) -> Self {
                        val as u32
                    }
                }
                pub mod selector {
                    pub struct PullDirSelector();
                    impl PullDirSelector {
                        #[inline(always)]
                        pub fn down(&self) -> super::PullDir { super::PullDir::Down }
                        #[inline(always)]
                        pub fn up(&self) -> super::PullDir { super::PullDir::Up }
                        #[inline(always)]
                        pub fn hi_z(&self) -> super::PullDir { super::PullDir::HiZ }
                    }
                }
            }
            .to_string()
        );
    }
}

fn hex_literal(val: u64) -> Literal {
    if val > 9 {
        Literal::from_str(&format! {"0x{val:x}"}).unwrap()
    } else {
        Literal::u64_unsuffixed(val)
    }
}

fn read_val_ident(reg_type: &RegisterType) -> Ident {
    format_ident!("{}ReadVal", camel_ident(reg_type.name.as_ref().unwrap()))
}
fn write_val_ident(reg_type: &RegisterType) -> Ident {
    format_ident!("{}WriteVal", camel_ident(reg_type.name.as_ref().unwrap()))
}

fn generate_register(reg: &RegisterType) -> TokenStream {
    let read_val_ident = read_val_ident(reg);
    let write_val_ident = write_val_ident(reg);
    let raw_type = format_ident!("{}", reg.width.rust_primitive_name());

    let mut read_val_tokens = TokenStream::new();
    let mut write_val_tokens = TokenStream::new();

    for field in reg.fields.iter() {
        let field_ident = snake_ident(&field.name);
        let position = Literal::u64_unsuffixed(field.position.into());
        let mask = if field.width == 64 {
            hex_literal(u64::MAX)
        } else {
            hex_literal((1u64 << field.width) - 1)
        };
        let access_expr = quote! {
            (self.0 >> #position) & #mask
        };
        let comment = &field.comment.replace("<br>", "\n");
        if field.ty.can_read() {
            if !comment.is_empty() {
                read_val_tokens.extend(quote! {
                    #[doc = #comment]
                })
            }
            read_val_tokens.extend(quote! {
                #[inline(always)]
            });
            if let Some(ref enum_type) = field.enum_type {
                let enum_type_ident = camel_ident(enum_type.name.as_ref().unwrap());
                read_val_tokens.extend(quote! {
                    pub fn #field_ident(&self) -> super::enums::#enum_type_ident {
                        super::enums::#enum_type_ident::try_from(#access_expr).unwrap()
                    }
                });
            } else if field.width == 1 {
                read_val_tokens.extend(quote! {
                    pub fn #field_ident(&self) -> bool {
                        (#access_expr) != 0
                    }
                });
            } else {
                read_val_tokens.extend(quote! {
                    pub fn #field_ident(&self) -> #raw_type {
                        #access_expr
                    }
                });
            }
        }
        if field.ty.can_write() {
            if !comment.is_empty() {
                write_val_tokens.extend(quote! {
                    #[doc = #comment]
                })
            }
            write_val_tokens.extend(quote! {
                #[inline(always)]
            });
            if let Some(ref enum_type) = field.enum_type {
                let enum_type_ident = camel_ident(enum_type.name.as_ref().unwrap());
                let enum_selector_type = format_ident!("{}Selector", enum_type_ident);
                write_val_tokens.extend(quote! {
                    pub fn #field_ident(self, f: impl FnOnce(super::enums::selector::#enum_selector_type) -> super::enums::#enum_type_ident) -> Self {
                        Self((self.0 & !(#mask << #position)) | (#raw_type::from(f(super::enums::selector::#enum_selector_type())) << #position))
                    }
                });
            } else if field.width == 1 {
                write_val_tokens.extend(quote! {
                    pub fn #field_ident(self, val: bool) -> Self {
                        Self((self.0 & !(#mask << #position)) | (#raw_type::from(val) << #position))
                    }
                });
            } else {
                write_val_tokens.extend(quote! {
                    pub fn #field_ident(self, val: #raw_type) -> Self {
                        Self((self.0 & !(#mask << #position)) | ((val & #mask) << #position))
                    }
                });
            }
        }
        if field.ty == FieldType::W1C && field.width == 1 {
            let field_clear_ident = format_ident!("{}_clear", field_ident);
            write_val_tokens.extend(quote! {
                #[doc = #comment]
                #[inline(always)]
                pub fn #field_clear_ident(self) -> Self {
                    Self(self.0 | (1 << #position))
                }
            });
        }
        if field.ty == FieldType::W1S && field.width == 1 {
            let field_set_ident = format_ident!("{}_set", field_ident);
            write_val_tokens.extend(quote! {
                #[doc = #comment]
                #[inline(always)]
                pub fn #field_set_ident(self) -> Self {
                    Self(self.0 | (1 << #position))
                }
            });
        }
    }

    let mut result = TokenStream::new();
    if !read_val_tokens.is_empty() {
        let modify_fn_tokens = if !write_val_tokens.is_empty() {
            quote! {
                /// Construct a WriteVal that can be used to modify the contents of this register value.
                #[inline(always)]
                pub fn modify(self) -> #write_val_ident {
                    #write_val_ident(self.0)
                }
            }
        } else {
            quote! {}
        };
        result.extend(quote! {
            #[derive(Clone, Copy)]
            pub struct #read_val_ident(#raw_type);
            impl #read_val_ident{
                #read_val_tokens
                #modify_fn_tokens
            }
            impl From<#raw_type> for #read_val_ident {
                #[inline(always)]
                fn from(val: #raw_type) -> Self {
                    Self(val)
                }
            }
            impl From<#read_val_ident> for #raw_type {
                #[inline(always)]
                fn from(val: #read_val_ident) -> #raw_type {
                    val.0
                }
            }

        });
    }
    if !write_val_tokens.is_empty() {
        result.extend(quote! {
            #[derive(Clone, Copy)]
            pub struct #write_val_ident(#raw_type);
            impl #write_val_ident{
                #write_val_tokens
            }
            impl From<#raw_type> for #write_val_ident {
                #[inline(always)]
                fn from(val: #raw_type) -> Self {
                    Self(val)
                }
            }
            impl From<#write_val_ident> for #raw_type {
                #[inline(always)]
                fn from(val: #write_val_ident) -> #raw_type {
                    val.0
                }
            }
        });
    }
    result
}

fn generate_register_types<'a>(regs: impl Iterator<Item = &'a RegisterType>) -> TokenStream {
    let mut regs: Vec<_> = regs.collect();
    regs.sort_by_key(|e| &e.name);
    let mut tokens = TokenStream::new();
    for reg in regs {
        if !has_single_32_bit_field(reg) {
            tokens.extend(generate_register(reg));
        }
    }
    tokens
}

fn has_single_32_bit_field(t: &RegisterType) -> bool {
    t.fields.len() == 1
        && t.fields[0].enum_type.is_none()
        && t.fields[0].position == 0
        && t.fields[0].width == 32
}

fn read_write_types(t: &RegisterType, options: &OptionsInternal) -> (TokenStream, TokenStream) {
    // TODO: This should be using #reg_raw_type instead of u32
    if has_single_32_bit_field(t) {
        (quote! { u32 }, quote! { u32 })
    } else {
        if let Some(extern_type) = options.extern_types.get(t) {
            return (
                extern_type.read_val_type.clone(),
                extern_type.write_val_type.clone(),
            );
        }
        let read_type = read_val_ident(t);
        let write_type = write_val_ident(t);
        let module_path = &options.module_path;
        (
            quote! { #module_path::regs::#read_type },
            quote! { #module_path::regs::#write_type },
        )
    }
}

fn generate_array_type(
    mut remaining_dimensions: impl Iterator<Item = u64>,
    reg_type_tokens: TokenStream,
) -> TokenStream {
    match remaining_dimensions.next() {
        Some(array_dimension) => {
            let array_dimension = Literal::u64_unsuffixed(array_dimension);
            let inner = generate_array_type(remaining_dimensions, reg_type_tokens);
            quote! { ureg::Array<#array_dimension, #inner> }
        }
        None => reg_type_tokens,
    }
}

fn generate_block_registers(
    registers: &[Rc<Register>],
    raw_ptr_type: &Ident,
    meta_tokens: &mut TokenStream,
    block_tokens: &mut TokenStream,
    meta_prefix: &str,
    options: &OptionsInternal,
) {
    for reg in registers.iter() {
        let reg_raw_type = format_ident!("{}", reg.ty.width.rust_primitive_name());
        let reg_name = snake_ident(&reg.name);
        let mut reg_meta_name = format_ident!("{}{}", meta_prefix, camel_ident(&reg.name));
        if registers.len() == 1 && camel_ident(&reg.name) == meta_prefix {
            reg_meta_name = camel_ident(&reg.name);
        }
        let ty = reg.ty.as_ref();
        let default_val = hex_literal(reg.default_val);
        let (read_type, write_type) = read_write_types(ty, options);
        let ptr_offset = hex_literal(reg.offset);
        let can_read = ty.fields.iter().any(|f| f.ty.can_read());
        let can_write = ty.fields.iter().any(|f| f.ty.can_write());
        let can_clear = ty.fields.iter().any(|f| f.ty.can_clear());
        let can_set = ty.fields.iter().any(|f| f.ty.can_set());

        let needs_write = can_write || can_clear || can_set;

        if ty.width == RegisterWidth::_32 && can_read && !needs_write {
            meta_tokens.extend(quote! {
                pub type #reg_meta_name = ureg::ReadOnlyReg32<#read_type>;
            });
        } else if ty.width == RegisterWidth::_32 && !can_read && needs_write {
            meta_tokens.extend(quote! {
                pub type #reg_meta_name = ureg::WriteOnlyReg32<#default_val, #write_type>;
            });
        } else if ty.width == RegisterWidth::_32 && can_read && needs_write {
            meta_tokens.extend(quote! {
                pub type #reg_meta_name = ureg::ReadWriteReg32<#default_val, #read_type, #write_type>;
            });
        } else {
            meta_tokens.extend(quote! {
                #[derive(Clone, Copy)]
                pub struct #reg_meta_name();
                impl ureg::RegType for #reg_meta_name {
                    type Raw = #reg_raw_type;
                }
            });
            if can_read {
                meta_tokens.extend(quote! {
                    impl ureg::ReadableReg for #reg_meta_name {
                        type ReadVal = #read_type;
                    }
                });
            }
            if can_write || can_clear || can_set {
                meta_tokens.extend(quote! {
                    impl ureg::WritableReg for #reg_meta_name {
                        type WriteVal = #write_type;
                    }
                });
                meta_tokens.extend(quote! {
                    impl ureg::ResettableReg for #reg_meta_name {
                        const RESET_VAL: Self::Raw = #default_val;
                    }
                });
            }
        }
        let module_path = &options.module_path;
        let read_type_str = read_type
            .to_string()
            .replace(' ', "")
            .replace("crate::", "");
        let write_type_str = write_type
            .to_string()
            .replace(' ', "")
            .replace("crate::", "");
        let comment = format!(
            "{}\n\nRead value: [`{read_type_str}`]; Write value: [`{write_type_str}`]",
            reg.comment.replace("<br>", "\n")
        );

        let result_type = generate_array_type(
            reg.array_dimensions.iter().cloned(),
            quote! {
                ureg::RegRef<#module_path::meta::#reg_meta_name, &TMmio>
            },
        );
        let constructor = if reg.array_dimensions.is_empty() {
            quote! { ureg::RegRef::new_with_mmio }
        } else {
            quote! { ureg::Array::new_with_mmio }
        };

        block_tokens.extend(quote!{
            #[doc = #comment]
            #[inline(always)]
            pub fn #reg_name(&self) -> #result_type {
                unsafe { #constructor(self.ptr.wrapping_add(#ptr_offset / core::mem::size_of::<#raw_ptr_type>()),
                                      core::borrow::Borrow::borrow(&self.mmio)) }
            }
        });
    }
}

#[derive(Clone)]
pub struct ExternType {
    read_val_type: TokenStream,
    write_val_type: TokenStream,
}

pub struct OptionsInternal {
    module_path: TokenStream,
    is_root_module: bool,

    // TODO: This should probably be a const reference
    extern_types: HashMap<Rc<RegisterType>, ExternType>,
}

#[derive(Default)]
pub struct Options {
    /// If the generated code is not at the base of the crate, this should
    /// be set to the prefix.
    pub module: TokenStream,

    pub extern_types: HashMap<Rc<RegisterType>, ExternType>,
}
impl Options {
    fn compile(self) -> OptionsInternal {
        if self.module.is_empty() {
            OptionsInternal {
                module_path: quote! {crate},
                is_root_module: true,
                extern_types: self.extern_types,
            }
        } else {
            let module = self.module;
            OptionsInternal {
                module_path: quote! {crate::#module},
                is_root_module: false,
                extern_types: self.extern_types,
            }
        }
    }
}

pub fn build_extern_types(
    block: &ValidatedRegisterBlock,
    module: TokenStream,
    extern_types: &mut HashMap<Rc<RegisterType>, ExternType>,
) {
    for ty in block.block().declared_register_types.iter() {
        if ty.name.is_none() {
            continue;
        }
        let read_val_ident = read_val_ident(ty);
        let write_val_ident = write_val_ident(ty);
        extern_types.insert(
            ty.clone(),
            ExternType {
                read_val_type: quote! { #module::regs::#read_val_ident },
                write_val_type: quote! { #module::regs::#write_val_ident },
            },
        );
    }
}

fn block_is_empty(block: &ValidatedRegisterBlock) -> bool {
    block.block().registers.is_empty()
        && block.block().instances.is_empty()
        && block.block().sub_blocks.is_empty()
}

fn block_max_register_width(block: &RegisterBlock) -> RegisterWidth {
    let a = block.registers.iter().map(|r| r.ty.width).max();
    let b = block
        .sub_blocks
        .iter()
        .map(|sb| block_max_register_width(sb.block()))
        .max();
    match (a, b) {
        (Some(a), Some(b)) => a.max(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => RegisterWidth::default(),
    }
}

pub fn generate_code(block: &ValidatedRegisterBlock, options: Options) -> TokenStream {
    let options = options.compile();
    let enum_tokens = generate_enums(block.enum_types().values().map(AsRef::as_ref));
    let mut reg_tokens = generate_register_types(
        block
            .register_types()
            .values()
            .filter(|t| !options.extern_types.contains_key(*t))
            .map(AsRef::as_ref),
    );
    reg_tokens.extend(generate_register_types(
        block
            .block()
            .declared_register_types
            .iter()
            .map(AsRef::as_ref),
    ));

    let mut subblock_type_tokens = TokenStream::new();
    let mut block_inner_tokens = TokenStream::new();
    let mut meta_tokens = TokenStream::new();
    let mut block_tokens = TokenStream::new();

    let mut instance_type_tokens = TokenStream::new();
    let mut subblock_instance_type_tokens = TokenStream::new();

    if !block_is_empty(block) {
        let max_reg_width = block_max_register_width(block.block());
        let raw_ptr_type = format_ident!("{}", max_reg_width.rust_primitive_name());

        for instance in block.block().instances.iter() {
            let name_camel = camel_ident(&instance.name);
            let addr = hex_literal(instance.address.into());
            // TODO: Should this be unsafe?
            instance_type_tokens.extend(quote! {
                /// A zero-sized type that represents ownership of this
                /// peripheral, used to get access to a Register lock. Most
                /// programs create one of these in unsafe code near the top of
                /// main(), and pass it to the driver responsible for managing
                /// all access to the hardware.
                pub struct #name_camel {
                    // Ensure the only way to create this is via Self::new()
                    _priv: (),
                }
                impl #name_camel {
                    pub const PTR: *mut #raw_ptr_type = #addr as *mut #raw_ptr_type;

                    /// # Safety
                    ///
                    /// Caller must ensure that all concurrent use of this
                    /// peripheral in the firmware is done so in a compatible
                    /// way. The simplest way to enforce this is to only call
                    /// this function once.
                    #[inline(always)]
                    pub unsafe fn new() -> Self {
                        Self{
                            _priv: (),
                        }
                    }

                    /// Returns a register block that can be used to read
                    /// registers from this peripheral, but cannot write.
                    #[inline(always)]
                    pub fn regs(&self) -> RegisterBlock<ureg::RealMmio> {
                        RegisterBlock{
                            ptr: Self::PTR,
                            mmio: core::default::Default::default(),
                        }
                    }

                    /// Return a register block that can be used to read and
                    /// write this peripheral's registers.
                    #[inline(always)]
                    pub fn regs_mut(&mut self) -> RegisterBlock<ureg::RealMmioMut> {
                        RegisterBlock{
                            ptr: Self::PTR,
                            mmio: core::default::Default::default(),
                        }
                    }
                }
            });
        }
        generate_block_registers(
            &block.block().registers,
            &raw_ptr_type,
            &mut meta_tokens,
            &mut block_inner_tokens,
            "",
            &options,
        );

        for sb in block.block().sub_blocks.iter() {
            generate_subblock_code(
                sb,
                raw_ptr_type.clone(),
                &options,
                &mut block_inner_tokens,
                &mut subblock_type_tokens,
                &mut subblock_instance_type_tokens,
                &mut meta_tokens,
            );
        }
        block_tokens = quote! {
            #[allow(dead_code)]
            #[derive(Clone, Copy)]
            pub struct RegisterBlock<TMmio: ureg::Mmio + core::borrow::Borrow<TMmio>>{
                ptr: *mut #raw_ptr_type,
                mmio: TMmio,
            }
            impl<TMmio: ureg::Mmio + core::default::Default> RegisterBlock<TMmio> {
                /// # Safety
                ///
                /// The caller is responsible for ensuring that ptr is valid for
                /// volatile reads and writes at any of the offsets in this register
                /// block.
                #[inline(always)]
                pub unsafe fn new(ptr: *mut #raw_ptr_type) -> Self {
                    Self{
                        ptr,
                        mmio: core::default::Default::default(),
                    }
                }
            }
            impl<TMmio: ureg::Mmio> RegisterBlock<TMmio> {
                /// # Safety
                ///
                /// The caller is responsible for ensuring that ptr is valid for
                /// volatile reads and writes at any of the offsets in this register
                /// block.
                #[inline(always)]
                pub unsafe fn new_with_mmio(ptr: *mut #raw_ptr_type, mmio: TMmio) -> Self {
                    Self{
                        ptr,
                        mmio,
                    }
                }
                #block_inner_tokens
            }
        }
    }
    let no_std_header = if options.is_root_module {
        quote! { #![no_std] }
    } else {
        // You can't set no_std in a module
        quote! {}
    };

    quote! {
        #no_std_header

        #![allow(clippy::erasing_op)]
        #![allow(clippy::identity_op)]

        #instance_type_tokens

        #block_tokens

        #subblock_type_tokens

        #subblock_instance_type_tokens

        pub mod regs {
            //! Types that represent the values held by registers.
            #reg_tokens
        }

        pub mod enums {
            //! Enumerations used by some register fields.
            #enum_tokens
        }

        pub mod meta {
            //! Additional metadata needed by ureg.
            #meta_tokens
        }

    }
}

#[allow(clippy::too_many_arguments)]
fn generate_subblock_code(
    sb: &RegisterSubBlock,
    raw_ptr_type: Ident,
    options: &OptionsInternal,
    block_inner_tokens: &mut TokenStream,
    subblock_type_tokens: &mut TokenStream,
    subblock_instance_type_tokens: &mut TokenStream,
    meta_tokens: &mut TokenStream,
) {
    let mut subblock_tokens = TokenStream::new();
    let subblock_name = format_ident!("{}Block", camel_ident(&sb.block().name));
    let subblock_fn_name = snake_ident(&sb.block().name);
    let meta_prefix = camel_ident(&sb.block().name).to_string();

    for instance in sb.block().instances.iter() {
        let name_camel = camel_ident(&instance.name);
        let addr = hex_literal(instance.address.into());
        // TODO: Should this be unsafe?
        subblock_instance_type_tokens.extend(quote! {
            /// A zero-sized type that represents ownership of this
            /// peripheral, used to get access to a Register lock. Most
            /// programs create one of these in unsafe code near the top of
            /// main(), and pass it to the driver responsible for managing
            /// all access to the hardware.
            pub struct #name_camel {
                // Ensure the only way to create this is via Self::new()
                _priv: (),
            }
            impl #name_camel {
                pub const PTR: *mut #raw_ptr_type = #addr as *mut #raw_ptr_type;

                /// # Safety
                ///
                /// Caller must ensure that all concurrent use of this
                /// peripheral in the firmware is done so in a compatible
                /// way. The simplest way to enforce this is to only call
                /// this function once.
                #[inline(always)]
                pub unsafe fn new() -> Self {
                    Self{
                        _priv: (),
                    }
                }

                /// Returns a register block that can be used to read
                /// registers from this peripheral, but cannot write.
                #[inline(always)]
                pub fn regs(&self) -> RegisterBlock<ureg::RealMmio> {
                    RegisterBlock{
                        ptr: Self::PTR,
                        mmio: core::default::Default::default(),
                    }
                }

                /// Return a register block that can be used to read and
                /// write this peripheral's registers.
                #[inline(always)]
                pub fn regs_mut(&mut self) -> RegisterBlock<ureg::RealMmioMut> {
                    RegisterBlock{
                        ptr: Self::PTR,
                        mmio: core::default::Default::default(),
                    }
                }

            }

        });
    }

    generate_block_registers(
        &sb.block().registers,
        &raw_ptr_type,
        meta_tokens,
        &mut subblock_tokens,
        &meta_prefix,
        options,
    );

    subblock_type_tokens.extend(quote! {
        #[derive(Clone, Copy)]
        pub struct #subblock_name<TMmio: ureg::Mmio + core::borrow::Borrow<TMmio>>{
            ptr: *mut #raw_ptr_type,
            mmio: TMmio,
        }
        impl<TMmio: ureg::Mmio> #subblock_name<TMmio> {
            #subblock_tokens
        }
    });
    let start_offset = hex_literal(sb.start_offset());
    match sb {
        RegisterSubBlock::Array { stride, len, .. } => {
            let stride = hex_literal(*stride);
            block_inner_tokens.extend(quote! {
                #[inline(always)]
                pub fn #subblock_fn_name(&self, index: usize) -> #subblock_name<&TMmio> {
                    assert!(index < #len);
                    #subblock_name{
                        ptr: unsafe { self.ptr.add((#start_offset + index * #stride) / core::mem::size_of::<#raw_ptr_type>()) }
                        mmio: core::borrow::Borrow::borrow(&self.mmio),
                    }
                }
            });
        }
        RegisterSubBlock::Single { .. } => {
            block_inner_tokens.extend(quote! {
                #[inline(always)]
                pub fn #subblock_fn_name(&self) -> #subblock_name<&TMmio> {
                    #subblock_name{
                        ptr: unsafe { self.ptr.add(#start_offset / core::mem::size_of::<#raw_ptr_type>()) },
                        mmio: core::borrow::Borrow::borrow(&self.mmio),
                    }
                }
            });
        }
    }

    for sb2 in sb.block().sub_blocks.iter() {
        generate_subblock_code(
            sb2,
            raw_ptr_type.clone(),
            options,
            block_inner_tokens,
            subblock_type_tokens,
            subblock_instance_type_tokens,
            meta_tokens,
        );
    }
}

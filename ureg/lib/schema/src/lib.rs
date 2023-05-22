/*++
Licensed under the Apache-2.0 license.
--*/

use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

mod validate;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct RegisterField {
    pub name: String,
    pub ty: FieldType,
    pub default_val: u64,
    pub comment: String,

    /// Describes any enumeration variants this field might have.
    pub enum_type: Option<Rc<Enum>>,

    /// The position of the field in the register, starting from the least
    /// significant bit.
    pub position: u8,

    /// The width of the field in bits
    pub width: u8,
}
impl RegisterField {
    /// A mask of the bits of this field.
    pub fn mask(&self) -> u64 {
        ((1u64 << self.width) - 1) << self.position
    }
}
#[cfg(test)]
mod registerfield_tests {
    use super::*;

    #[test]
    fn test_mask() {
        assert_eq!(
            RegisterField {
                position: 0,
                width: 1,
                ..Default::default()
            }
            .mask(),
            0x00000001
        );

        assert_eq!(
            RegisterField {
                position: 0,
                width: 2,
                ..Default::default()
            }
            .mask(),
            0x00000003
        );

        assert_eq!(
            RegisterField {
                position: 0,
                width: 3,
                ..Default::default()
            }
            .mask(),
            0x00000007
        );

        assert_eq!(
            RegisterField {
                position: 1,
                width: 3,
                ..Default::default()
            }
            .mask(),
            0x0000000e
        );

        assert_eq!(
            RegisterField {
                position: 8,
                width: 3,
                ..Default::default()
            }
            .mask(),
            0x00000700
        );

        assert_eq!(
            RegisterField {
                position: 28,
                width: 4,
                ..Default::default()
            }
            .mask(),
            0xf0000000
        );

        assert_eq!(
            RegisterField {
                position: 31,
                width: 1,
                ..Default::default()
            }
            .mask(),
            0x80000000
        );
    }
}

/// Represents an memory-mapped I/O register.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Register {
    pub name: String,
    pub default_val: u64,
    pub comment: String,

    /// The offset of the register from the start of the register block.
    pub offset: u64,

    pub array_dimensions: Vec<u64>,

    pub ty: Rc<RegisterType>,
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct RegisterType {
    /// The optional name of the register type
    pub name: Option<String>,

    pub width: RegisterWidth,

    /// The bit fields of the register.
    pub fields: Vec<RegisterField>,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum FieldType {
    #[default]
    /// Read/Write
    RW,

    /// Read-only
    RO,

    /// Write-only
    WO,

    /// Write to clear all bits
    WC,

    /// ?
    WRC,

    /// Write 1 to clear a bit, write 0 for no effect.
    W1C,

    /// Write 1 to set a bit, write 0 for no effect,
    W1S,
}
impl FieldType {
    pub fn can_read(&self) -> bool {
        match *self {
            FieldType::RO => true,
            FieldType::RW => true,
            FieldType::WO => false,
            FieldType::WC => false,
            FieldType::WRC => false,
            FieldType::W1C => true,
            FieldType::W1S => true,
        }
    }
    pub fn can_write(&self) -> bool {
        match *self {
            FieldType::RO => false,
            FieldType::RW => true,
            FieldType::WO => true,
            FieldType::WC => false,
            FieldType::WRC => false,
            FieldType::W1C => false,
            FieldType::W1S => false,
        }
    }
    pub fn can_clear(&self) -> bool {
        match *self {
            FieldType::RO => false,
            FieldType::RW => false,
            FieldType::WO => false,
            FieldType::WC => false,
            FieldType::WRC => false,
            FieldType::W1C => true,
            FieldType::W1S => false,
        }
    }
    pub fn can_set(&self) -> bool {
        match *self {
            FieldType::RO => false,
            FieldType::RW => false,
            FieldType::WO => false,
            FieldType::WC => false,
            FieldType::WRC => false,
            FieldType::W1C => false,
            FieldType::W1S => true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterSubBlock {
    Single {
        block: RegisterBlock,
        start_offset: u64,
    },
    Array {
        block: RegisterBlock,
        start_offset: u64,
        stride: u64,
        len: usize,
    },
}
impl RegisterSubBlock {
    pub fn block(&self) -> &RegisterBlock {
        match self {
            Self::Single { block, .. } => block,
            Self::Array { block, .. } => block,
        }
    }
    pub fn block_mut(&mut self) -> &mut RegisterBlock {
        match self {
            Self::Single { block, .. } => block,
            Self::Array { block, .. } => block,
        }
    }
    pub fn start_offset(&self) -> u64 {
        match self {
            Self::Single { start_offset, .. } => *start_offset,
            Self::Array { start_offset, .. } => *start_offset,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegisterBlock {
    pub name: String,
    pub registers: Vec<Rc<Register>>,
    pub instances: Vec<RegisterBlockInstance>,
    pub sub_blocks: Vec<RegisterSubBlock>,

    // Register types that are "owned" by this block (but might be used by other register blocks)
    pub declared_register_types: Vec<Rc<RegisterType>>,
}
impl RegisterBlock {
    pub fn remove_enums(&mut self, register_fields: &[(&str, &str)]) {
        let mut selector: HashMap<&str, HashSet<&str>> = HashMap::new();
        for (register_name, field_name) in register_fields.iter() {
            selector
                .entry(register_name)
                .or_default()
                .insert(field_name);
        }
        for reg in self.registers.iter_mut() {
            if let Some(selected_fields) = selector.get(reg.name.as_str()) {
                let reg = Rc::make_mut(reg);
                let reg_ty = Rc::make_mut(&mut reg.ty);
                for field in reg_ty.fields.iter_mut() {
                    if selected_fields.contains(field.name.as_str()) {
                        field.enum_type = None;
                    }
                }
            }
        }
    }
    pub fn rename_enum_variants(&mut self, renames: &[(&str, &str)]) {
        let rename_map: HashMap<&str, &str> = renames.iter().cloned().collect();
        for reg in self.registers.iter_mut() {
            let reg = Rc::make_mut(reg);
            let reg_ty = Rc::make_mut(&mut reg.ty);
            for field in reg_ty.fields.iter_mut() {
                if let Some(ref mut e) = field.enum_type {
                    let e = Rc::make_mut(e);
                    for variant in e.variants.iter_mut() {
                        if let Some(new_name) = rename_map.get(variant.name.as_str()) {
                            variant.name = new_name.to_string();
                        }
                    }
                }
            }
        }
    }
    pub fn rename_fields(&mut self, renames: &[(&str, &str, &str)]) {
        let mut selector: HashMap<&str, HashMap<&str, &str>> = HashMap::new();
        for (register_name, old_field_name, new_field_name) in renames.iter() {
            selector
                .entry(register_name)
                .or_default()
                .insert(old_field_name, new_field_name);
        }
        for reg in self.registers.iter_mut() {
            if let Some(selected_fields) = selector.get(reg.name.as_str()) {
                let reg = Rc::make_mut(reg);
                let reg_ty = Rc::make_mut(&mut reg.ty);
                for field in reg_ty.fields.iter_mut() {
                    if let Some(new_field_name) = selected_fields.get(field.name.as_str()) {
                        field.name = new_field_name.to_string();
                    }
                }
            }
        }
    }
    pub fn replace_field_comments(&mut self, replacements: &[(&str, &str)]) {
        let map: HashMap<&str, &str> = replacements.iter().cloned().collect();
        for reg in self.registers.iter_mut() {
            let reg = Rc::make_mut(reg);
            let reg_ty = Rc::make_mut(&mut reg.ty);
            for field in reg_ty.fields.iter_mut() {
                if let Some(new_comment) = map.get(field.comment.as_str()) {
                    field.comment = new_comment.to_string();
                }
            }
        }
    }
}

pub use validate::ValidatedRegisterBlock;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegisterBlockInstance {
    pub name: String,
    pub address: u32,
}

#[derive(Clone, Copy, Debug, Default, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegisterWidth {
    _8 = 8,
    _16 = 16,

    #[default]
    _32 = 32,

    _64 = 64,
}
impl RegisterWidth {
    pub fn in_bytes(self) -> u64 {
        match self {
            RegisterWidth::_8 => 1,
            RegisterWidth::_16 => 2,
            RegisterWidth::_32 => 4,
            RegisterWidth::_64 => 8,
        }
    }

    pub fn rust_primitive_name(self) -> &'static str {
        match self {
            RegisterWidth::_8 => "u8",
            RegisterWidth::_16 => "u16",
            RegisterWidth::_32 => "u32",
            RegisterWidth::_64 => "u64",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct EnumVariant {
    pub name: String,
    pub value: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Enum {
    pub name: Option<String>,
    pub variants: Vec<EnumVariant>,
    pub bit_width: u8,
}

fn collect_used_reg_types(block: &RegisterBlock, used_types: &mut HashSet<Rc<RegisterType>>) {
    for reg in block.registers.iter() {
        used_types.insert(reg.ty.clone());
    }
    for sb in block.sub_blocks.iter() {
        for reg in sb.block().registers.iter() {
            used_types.insert(reg.ty.clone());
        }
    }
}

pub fn filter_unused_types(blocks: &mut [&mut ValidatedRegisterBlock]) {
    let mut used_types = HashSet::new();

    for block in blocks.iter() {
        collect_used_reg_types(block.block(), &mut used_types);
    }
    for block in blocks.iter_mut() {
        block.filter_register_types(|ty| used_types.contains(ty));
    }
}

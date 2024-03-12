/*++
Licensed under the Apache-2.0 license.
--*/

use crate::Enum;
use crate::EnumVariant;
use crate::Register;
use crate::RegisterBlock;
use crate::RegisterField;
use crate::RegisterSubBlock;
use crate::RegisterType;

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fmt::Display;
use std::hash::Hash;
use std::hash::Hasher;
use std::rc::Rc;

#[derive(Debug)]
pub enum ValidationError {
    RegisterOffsetCollision {
        block_name: String,
        reg_name: String,
        offset: u64,
    },
    BadArrayDimension {
        block_name: String,
        reg_name: String,
    },
    DuplicateRegisterName {
        block_name: String,
        reg_name: String,
    },
    DuplicateRegisterTypeName {
        block_name: String,
        reg_type_name: String,
    },
    DuplicateEnumName {
        block_name: String,
        enum_name: String,
    },
    DuplicateEnumVariantName {
        block_name: String,
        enum_name: String,
        variant_name: String,
    },
    DuplicateEnumVariantValue {
        block_name: String,
        enum_name: String,
        variant_value: u32,
        variant_name0: String,
        variant_name1: String,
    },
}
impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::RegisterOffsetCollision {
                block_name,
                reg_name,
                offset,
            } => {
                write!(
                    f,
                    "Register offset collision at {block_name}::{reg_name} offset 0x{offset:x}"
                )
            }
            ValidationError::BadArrayDimension {
                block_name,
                reg_name,
            } => {
                write!(
                    f,
                    "Bad array dimension at {block_name}::{reg_name}; can't be 0"
                )
            }
            ValidationError::DuplicateRegisterName {
                block_name,
                reg_name,
            } => {
                write!(f, "Duplicate register {block_name}::{reg_name}")
            }
            ValidationError::DuplicateRegisterTypeName {
                block_name,
                reg_type_name,
            } => {
                write!(f, "Duplicate register type {block_name}::{reg_type_name}")
            }
            ValidationError::DuplicateEnumName {
                block_name,
                enum_name,
            } => {
                write!(f, "Duplicate enum name {block_name}::{enum_name}")
            }
            ValidationError::DuplicateEnumVariantName {
                block_name,
                enum_name,
                variant_name,
            } => {
                write!(
                    f,
                    "Duplicate enum variants with name {block_name}::{enum_name}::{variant_name}"
                )
            }
            ValidationError::DuplicateEnumVariantValue {
                block_name,
                enum_name,
                variant_value,
                variant_name0,
                variant_name1,
            } => {
                write!(f, "Duplicate enum variants with value {variant_value}: {block_name}::{enum_name}::{{{variant_name0},{variant_name1}}}")
            }
        }
    }
}
impl Error for ValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug)]
pub struct ValidatedRegisterBlock {
    block: RegisterBlock,
    register_types: HashMap<String, Rc<RegisterType>>,
    enum_types: HashMap<String, Rc<Enum>>,
}
impl ValidatedRegisterBlock {
    pub fn block(&self) -> &RegisterBlock {
        &self.block
    }
    pub fn register_types(&self) -> &HashMap<String, Rc<RegisterType>> {
        &self.register_types
    }
    pub fn enum_types(&self) -> &HashMap<String, Rc<Enum>> {
        &self.enum_types
    }

    pub fn transform(&mut self, t: impl FnOnce(&mut ValidatedRegisterBlockTransformer)) {
        t(&mut ValidatedRegisterBlockTransformer(self));
        self.update_enum_references();
        self.update_reg_type_references();
        self.update_enum_name_keys();
    }

    fn update_enum_references(&mut self) {
        for reg_type in self.register_types.values_mut() {
            let reg_type = Rc::make_mut(reg_type);
            for field in reg_type.fields.iter_mut() {
                if let Some(ref enum_type) = field.enum_type {
                    if let Some(ref name) = enum_type.name {
                        field.enum_type = self.enum_types.get(name.as_str()).cloned();
                    }
                }
            }
        }
    }
    fn update_reg_type_references(&mut self) {
        for reg in self.block.registers.iter_mut() {
            let reg = Rc::make_mut(reg);
            if let Some(ref name) = reg.ty.name {
                reg.ty = self.register_types.get(name).unwrap().clone();
            }
        }
    }

    fn update_enum_name_keys(&mut self) {
        // Clippy is wrong here; collect is required to keep the
        // the borrow checker happy (the loop cannot erase elements from
        // self.enum_types while self.enum_types is borrowed)
        #[allow(clippy::needless_collect)]
        let all_enums: Vec<(String, Rc<Enum>)> = self
            .enum_types
            .iter()
            .map(|(key, val)| (key.clone(), val.clone()))
            .collect();

        for (key, val) in all_enums.into_iter() {
            if val.name.as_ref() != Some(&key) {
                self.enum_types.remove(&key);
                if let Some(new_name) = &val.name {
                    if let Some(old_enum) = self.enum_types.insert(new_name.clone(), val.clone()) {
                        panic!(
                            "Enum collision with name {:?} {:?} vs {:?}",
                            old_enum.name, old_enum, val
                        );
                    }
                }
            }
        }
    }

    pub fn filter_register_types(&mut self, mut pred: impl FnMut(&Rc<RegisterType>) -> bool) {
        self.block.declared_register_types = self
            .block
            .declared_register_types
            .drain(..)
            .filter(&mut pred)
            .collect();
        self.register_types = self
            .register_types
            .drain()
            .filter(|(_, ty)| pred(ty))
            .collect();
    }

    pub fn extract_subblock_array(
        &mut self,
        block_name: &str,
        register_prefixes: &[&str],
        type_index: usize,
    ) {
        struct MyRegInstance {
            index: usize,
            reg: Rc<Register>,
        }
        let register_prefixes: HashSet<String> = register_prefixes
            .iter()
            .cloned()
            .map(str::to_ascii_lowercase)
            .collect();
        let mut instances_by_name: HashMap<String, Vec<MyRegInstance>> = HashMap::new();
        self.block.registers.retain_mut(|reg| {
            let reg_name = reg
                .name
                .trim_end_matches(|c: char| c.is_ascii_digit())
                .to_ascii_lowercase();
            if !register_prefixes.contains(&reg_name) {
                // Keep this register in self.registers
                return true;
            }
            let Ok(index) = reg.name[reg_name.len()..].parse::<usize>() else {
                return true;
            };

            let reg_name = reg_name.trim_start_matches(block_name);
            instances_by_name
                .entry(reg_name.to_string())
                .or_default()
                .push(MyRegInstance {
                    index,
                    reg: reg.clone(),
                });
            // Remove this register from self.registers, as it will be part
            // of the new subblock array
            false
        });
        struct MyRegisterSpec {
            name: String,
            default_val: u64,
            min_offset: u64,
            stride: u64,
            count: usize,
            array_dimensions: Vec<u64>,
            ty: Rc<RegisterType>,
            comment: String,
        }
        let mut reg_specs: Vec<MyRegisterSpec> = instances_by_name
            .into_iter()
            .map(|(name, mut instances)| {
                instances.sort_by_key(|reg_inst| reg_inst.index);
                let stride = instances[1].reg.offset - instances[0].reg.offset;
                for (prev_inst, next_inst) in instances.iter().zip(instances[1..].iter()) {
                    if next_inst.reg.offset - prev_inst.reg.offset != stride {
                        panic!("Stride not consistent for register {:?}", name);
                    }
                    if next_inst.reg.default_val != prev_inst.reg.default_val {
                        panic!("default_val not consistent for register {:?}", name);
                    }
                    if next_inst.reg.array_dimensions != prev_inst.reg.array_dimensions {
                        panic!("array_dimensions not consistent for register {:?}", name);
                    }
                }
                MyRegisterSpec {
                    name,
                    default_val: instances[0].reg.default_val,
                    min_offset: instances
                        .iter()
                        .map(|reg_inst| reg_inst.reg.offset)
                        .min()
                        .unwrap(),
                    stride,
                    count: instances.len(),
                    array_dimensions: instances[0].reg.array_dimensions.clone(),
                    ty: instances[type_index].reg.ty.clone(),
                    comment: instances[type_index].reg.comment.clone(),
                }
            })
            .collect();
        reg_specs.sort_by_key(|reg| reg.min_offset);
        let start_offset = reg_specs[0].min_offset;
        let block_array = RegisterSubBlock::Array {
            start_offset,
            stride: reg_specs[0].stride,
            len: reg_specs[0].count,
            block: RegisterBlock {
                name: block_name.to_string(),
                registers: reg_specs
                    .into_iter()
                    .map(|reg_spec| {
                        Rc::new(Register {
                            name: reg_spec.name.to_string(),
                            default_val: reg_spec.default_val,
                            comment: reg_spec.comment,
                            array_dimensions: reg_spec.array_dimensions,
                            offset: reg_spec.min_offset - start_offset,
                            ty: reg_spec.ty,
                        })
                    })
                    .collect(),
                ..Default::default()
            },
        };

        self.block.sub_blocks.push(block_array);
    }
}

pub struct ValidatedRegisterBlockTransformer<'a>(&'a mut ValidatedRegisterBlock);
impl ValidatedRegisterBlockTransformer<'_> {
    pub fn add_enum_type(&mut self, e: Rc<Enum>) {
        if let Some(ref name) = e.name {
            if !self.0.enum_types.contains_key(name) {
                self.0.enum_types.insert(name.clone(), e);
            }
        }
    }
    // Replaces enums with the same name as the supplied enum.
    pub fn replace_enum_types(&mut self, enums: Vec<Rc<Enum>>) {
        for e in enums.into_iter() {
            if let Some(ref name) = e.name {
                self.0.enum_types.insert(name.clone(), e);
            }
        }
    }
    /// Finds enums with the exact same variants as the supplied enum, and
    /// renames them all to be the same as the supplied enum.
    pub fn rename_enums(&mut self, enums: Vec<Rc<Enum>>) {
        let mut hash = HashMap::<Enum, Rc<Enum>>::new();
        for e in enums.into_iter() {
            let nameless_enum = Enum {
                name: None,
                ..(*e).clone()
            };
            hash.insert(nameless_enum, e.clone());
        }

        // Clippy is wrong here; collect is required to keep the
        // the borrow checker happy (the loop cannot modify
        // self.enum_types while self.enum_types is borrowed)
        #[allow(clippy::needless_collect)]
        let all_enums: Vec<Rc<Enum>> = self.0.enum_types.values().cloned().collect();
        for e in all_enums.into_iter() {
            let nameless_enum = Enum {
                name: None,
                ..(*e).clone()
            };
            if let Some(renamed_enum) = hash.get(&nameless_enum) {
                // Unwrap is safe because all enum names in a validate register block must be Some.
                self.0
                    .enum_types
                    .insert(e.name.clone().unwrap(), renamed_enum.clone());
                // We have to go through the hash-map at the end and replace all the names
            }
        }
    }

    pub fn remove_enum_types(&mut self, names: &[&str]) {
        for name in names.iter().cloned() {
            self.0.enum_types.remove(name);
        }
    }
    pub fn set_register_enum(&mut self, register_type: &str, field_name: &str, e: Rc<Enum>) {
        let enum_name = e.name.clone().unwrap();
        self.0.enum_types.insert(enum_name, e.clone());
        let reg_ty = self
            .0
            .register_types
            .get_mut(register_type)
            .unwrap_or_else(|| panic!("Unknown register type {}", register_type));
        let reg_ty = Rc::make_mut(reg_ty);
        for field in reg_ty.fields.iter_mut() {
            if field.name == field_name {
                field.enum_type = Some(e);
                return;
            }
        }
        panic!("Could not find field {field_name} in register type {register_type}");
    }
}

fn common_with_placeholders(reg_names: &[&str]) -> (String, i64) {
    let shortest_len = match reg_names.iter().map(|s| s.len()).min() {
        Some(l) => l,
        None => return ("".into(), 0),
    };
    let mut common_chars: Vec<Option<char>> =
        reg_names[0][0..shortest_len].chars().map(Some).collect();
    for reg_name in reg_names[1..].iter() {
        for (a, b) in reg_name[0..shortest_len]
            .chars()
            .zip(common_chars.iter_mut())
        {
            if Some(a) != *b {
                *b = None;
            }
        }
    }
    while common_chars.last() == Some(&None) {
        common_chars.pop();
    }
    let x_char = if common_chars.iter().any(|c| {
        if let Some(c) = c {
            c.is_ascii_uppercase()
        } else {
            false
        }
    }) {
        'X'
    } else {
        'x'
    };
    let score = common_chars
        .iter()
        .map(|c| i64::from(c.is_some()))
        .sum::<i64>()
        - 1;
    (
        common_chars.iter().map(|c| c.unwrap_or(x_char)).collect(),
        score,
    )
}

fn shortest_prefix<'a>(reg_names: &[&'a str]) -> &'a str {
    let mut iter = reg_names.iter().cloned();
    if let Some(mut first) = iter.next() {
        for reg_name in iter {
            let common_len = reg_name
                .as_bytes()
                .iter()
                .zip(first.as_bytes())
                .take_while(|t| t.0 == t.1)
                .count();
            first = &first[0..common_len];
        }
        first
    } else {
        ""
    }
}
fn shortest_suffix<'a>(reg_names: &[&'a str]) -> &'a str {
    let mut iter = reg_names.iter().cloned();
    if let Some(mut first) = iter.next() {
        for reg_name in iter {
            let common_len = reg_name
                .as_bytes()
                .iter()
                .rev()
                .zip(first.as_bytes().iter().rev())
                .take_while(|t| t.0 == t.1)
                .count();
            first = &first[first.len() - common_len..];
        }
        first
    } else {
        ""
    }
}

fn compute_common_name<'a>(reg_names: &'a [&'a str]) -> Option<String> {
    let shortest_prefix = shortest_prefix(reg_names);
    let shortest_suffix = shortest_suffix(reg_names);
    let mut options = vec![
        (shortest_prefix.to_string(), shortest_prefix.len() as i64),
        (shortest_suffix.to_string(), shortest_suffix.len() as i64),
        common_with_placeholders(reg_names),
    ];
    options.sort_by_key(|(_, score)| *score);
    options
        .pop()
        .map(|(name, _)| name)
        .and_then(|s| if s.is_empty() { None } else { Some(s) })
}

fn hash_u64(v: &impl Hash) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

fn validate_enum(block_name: &str, e: &Enum) -> Result<(), ValidationError> {
    let mut variants_by_val: HashMap<u32, &EnumVariant> = HashMap::new();
    let mut variants_by_name: HashMap<&str, &EnumVariant> = HashMap::new();
    for variant in e.variants.iter() {
        if let Some(existing) = variants_by_val.insert(variant.value, variant) {
            return Err(ValidationError::DuplicateEnumVariantValue {
                block_name: block_name.into(),
                enum_name: e.name.clone().unwrap_or_else(|| "?".into()),
                variant_value: variant.value,
                variant_name0: existing.name.clone(),
                variant_name1: variant.name.clone(),
            });
        }
        if let Some(existing) = variants_by_name.insert(&variant.name, variant) {
            return Err(ValidationError::DuplicateEnumVariantName {
                block_name: block_name.into(),
                enum_name: e.name.clone().unwrap_or_else(|| "?".into()),
                variant_name: existing.name.clone(),
            });
        }
    }
    Ok(())
}

fn is_meaningless_field_name(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "val" | "value")
}

fn determine_enum_name(reg: &Register, field: &RegisterField) -> String {
    if reg.ty.fields.len() == 1 && is_meaningless_field_name(&field.name) {
        reg.name.clone()
    } else {
        field.name.clone()
    }
}
fn determine_enum_name_from_reg_ty(reg_ty: &RegisterType, field: &RegisterField) -> String {
    if reg_ty.fields.len() == 1 && is_meaningless_field_name(&field.name) {
        if let Some(ref reg_ty_name) = reg_ty.name {
            return reg_ty_name.into();
        }
    }
    field.name.clone()
}

fn all_regs<'a>(
    regs: &'a [Rc<Register>],
    sub_blocks: &'a [RegisterSubBlock],
) -> impl Iterator<Item = &'a Rc<Register>> {
    // TODO: Do this recursively
    regs.iter()
        .chain(sub_blocks.iter().flat_map(|a| a.block().registers.iter()))
}

fn all_regs_mut<'a>(
    regs: &'a mut [Rc<Register>],
    sub_blocks: &'a mut [RegisterSubBlock],
) -> impl Iterator<Item = &'a mut Rc<Register>> {
    // TODO: Do this recursively
    regs.iter_mut().chain(
        sub_blocks
            .iter_mut()
            .flat_map(|a| a.block_mut().registers.iter_mut()),
    )
}

impl RegisterBlock {
    pub fn validate_and_dedup(mut self) -> Result<ValidatedRegisterBlock, ValidationError> {
        self.registers.sort_by_key(|reg| reg.offset);
        self.sub_blocks
            .sort_by_key(|sub_array| sub_array.start_offset());

        for sb in self.sub_blocks.iter_mut() {
            // TODO: Do this recursively
            sb.block_mut().registers.sort_by_key(|reg| reg.offset);
        }

        let mut enum_types: HashMap<String, Rc<Enum>> = HashMap::new();
        {
            let mut enum_names = HashMap::<Rc<Enum>, HashSet<String>>::new();
            for reg in all_regs(&self.registers, &self.sub_blocks) {
                for field in reg.ty.fields.iter() {
                    if let Some(ref e) = field.enum_type {
                        enum_names
                            .entry(e.clone())
                            .or_default()
                            .insert(determine_enum_name(reg, field));
                    }
                }
            }

            let mut new_enums: HashMap<Rc<Enum>, Rc<Enum>> = HashMap::new();
            for (e, names) in enum_names.into_iter() {
                let names: Vec<&str> = names.iter().map(|n| n.as_str()).collect();

                let name = e.name.clone().unwrap_or(match compute_common_name(&names) {
                    Some(name) => name,
                    None => {
                        format!("Enum{:016x}", hash_u64(&e))
                    }
                });
                new_enums.insert(
                    e.clone(),
                    Rc::new(Enum {
                        name: Some(name),
                        ..(*e).clone()
                    }),
                );
            }
            for reg_ty in self.declared_register_types.iter() {
                for field in reg_ty.fields.iter() {
                    if let Some(ref e) = field.enum_type {
                        let name = determine_enum_name_from_reg_ty(reg_ty, field);
                        if e.name.is_some() {
                            new_enums.insert(e.clone(), e.clone());
                        } else {
                            new_enums.insert(
                                e.clone(),
                                Rc::new(Enum {
                                    name: Some(name),
                                    ..(**e).clone()
                                }),
                            );
                        }
                    }
                }
            }

            for reg in all_regs_mut(&mut self.registers, &mut self.sub_blocks) {
                let reg = Rc::make_mut(reg);
                let ty = Rc::make_mut(&mut reg.ty);
                reg.array_dimensions.retain(|d| *d != 1);
                if reg.array_dimensions.contains(&0) {
                    return Err(ValidationError::BadArrayDimension {
                        block_name: self.name,
                        reg_name: reg.name.clone(),
                    });
                }
                for field in ty.fields.iter_mut() {
                    if let Some(ref mut e) = field.enum_type {
                        if let Some(new_e) = new_enums.get(e) {
                            *e = new_e.clone();
                        }
                    }
                }
            }
            for e in new_enums.into_values() {
                let enum_name = e.name.clone().unwrap();
                if enum_types.contains_key(&enum_name) {
                    return Err(ValidationError::DuplicateEnumName {
                        block_name: self.name,
                        enum_name,
                    });
                }
                validate_enum(&self.name, &e)?;
                enum_types.insert(enum_name, e);
            }
        };

        let mut regs_by_type = HashMap::<Rc<RegisterType>, Vec<Rc<Register>>>::new();

        let mut used_names = HashSet::new();
        let mut next_free_offset = 0;
        for reg in self.registers.iter() {
            if reg.offset < next_free_offset {
                return Err(ValidationError::RegisterOffsetCollision {
                    block_name: self.name,
                    reg_name: reg.name.clone(),
                    offset: reg.offset,
                });
            }
            next_free_offset = reg.offset + reg.ty.width.in_bytes();
            if !used_names.insert(reg.name.clone()) {
                return Err(ValidationError::DuplicateRegisterName {
                    block_name: self.name,
                    reg_name: reg.name.clone(),
                });
            }
        }
        for reg in all_regs(&self.registers, &self.sub_blocks) {
            regs_by_type
                .entry(reg.ty.clone())
                .or_default()
                .push(reg.clone());
        }
        let mut new_types = HashMap::<Rc<RegisterType>, Rc<RegisterType>>::new();

        for (reg_type, regs) in regs_by_type.into_iter() {
            if reg_type.fields.is_empty() {
                continue;
            }
            let mut new_type = (*reg_type).clone();
            let reg_names: Vec<&str> = regs.iter().map(|r| r.name.as_str()).collect();
            if new_type.name.is_none() {
                new_type.name = compute_common_name(&reg_names).map(Into::into);
            }
            if new_type.name.is_none() {
                new_type.name = Some(format!("Field{:016x}", hash_u64(&new_type)));
            }
            new_types.insert(reg_type, Rc::new(new_type));
        }
        // Replace the old duplicate register types with the new shared types
        for reg in all_regs_mut(&mut self.registers, &mut self.sub_blocks) {
            if let Some(new_type) = new_types.get(&reg.ty) {
                Rc::make_mut(reg).ty = new_type.clone();
            }
        }
        for reg_type in self.declared_register_types.iter_mut() {
            if let Some(new_type) = new_types.get(reg_type) {
                *reg_type = new_type.clone();
            }
        }
        let mut register_types = HashMap::new();
        for reg_type in new_types.into_values() {
            let reg_type_name = reg_type.name.clone().unwrap();
            if let Some(existing_reg_type) = register_types.get(&reg_type_name) {
                println!("Duplicate: {:#?} vs {:#?}", existing_reg_type, reg_type);
                return Err(ValidationError::DuplicateRegisterTypeName {
                    block_name: self.name,
                    reg_type_name,
                });
            }
            register_types.insert(reg_type_name, reg_type);
        }

        Ok(ValidatedRegisterBlock {
            block: self,
            register_types,
            enum_types,
        })
    }
}

#[cfg(test)]
mod compute_reg_type_name_tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            compute_common_name(&["UART0", "UART1", "UART10"]),
            Some("UART".into())
        );
        assert_eq!(compute_common_name(&["UART0"]), Some("UART0".into()));
        assert_eq!(
            compute_common_name(&["DIEPTCTL", "DOEPTCTL"]),
            Some("DXEPTCTL".into())
        );
        assert_eq!(
            compute_common_name(&["dieptctl", "doeptctl"]),
            Some("dxeptctl".into())
        );
        assert_eq!(
            compute_common_name(&["DIEPTCTL0", "DIEPTCTL1", "DOEPTCTL0", "DOEPTCTL1"]),
            Some("DXEPTCTL".into())
        );
        assert_eq!(
            compute_common_name(&["PROG_LB0_POST_OVRD", "LB0_POST_OVRD"]),
            Some("LB0_POST_OVRD".into())
        );
    }
}

/*++
Licensed under the Apache-2.0 license.
--*/
mod error;

pub use error::Error;
use ureg::RegisterType;

use std::rc::Rc;

use caliptra_systemrdl as systemrdl;
use caliptra_systemrdl::{ComponentType, ScopeType};
use systemrdl::{AccessType, ParentScope, RdlError};
use ureg_schema as ureg;
use ureg_schema::{RegisterBlock, RegisterBlockInstance};

fn unpad_description(desc: &str) -> String {
    let ltrim = desc
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.find(|c| c != ' '))
        .min()
        .flatten()
        .unwrap_or(0);
    let mut lines = vec![];
    for l in desc.lines() {
        let trim_start = usize::min(ltrim, l.find(|c| c != ' ').unwrap_or(0));
        lines.push(&l[trim_start..]);
    }
    while let Some(line) = lines.last() {
        if !line.trim().is_empty() {
            break;
        }
        lines.pop();
    }
    lines.join("\n")
}

fn get_property_opt<T: TryFrom<systemrdl::Value, Error = RdlError<'static>>>(
    scope: &systemrdl::Scope,
    name: &'static str,
) -> Result<Option<T>, Error> {
    scope.property_val_opt::<T>(name).map_err(Error::RdlError)
}

fn expect_instance_type(scope: systemrdl::ParentScope, ty: ScopeType) -> Result<(), Error> {
    if scope.scope.ty != ty {
        Err(Error::UnexpectedScopeType {
            expected: ty,
            actual: scope.scope.ty,
        })
    } else {
        Ok(())
    }
}

fn translate_access_type(ty: systemrdl::AccessType) -> Result<ureg::FieldType, Error> {
    match ty {
        systemrdl::AccessType::Rw => Ok(ureg::FieldType::RW),
        systemrdl::AccessType::R => Ok(ureg::FieldType::RO),
        systemrdl::AccessType::W => Ok(ureg::FieldType::WO),
        systemrdl::AccessType::Rw1 => Ok(ureg::FieldType::RW),
        systemrdl::AccessType::W1 => Ok(ureg::FieldType::WO),
        systemrdl::AccessType::Na => Err(Error::AccessTypeNaUnsupported),
    }
}

fn field_width(field: &systemrdl::Instance) -> Result<u64, Error> {
    if field.dimension_sizes.is_empty() {
        return Ok(field
            .scope
            .property_val_opt("fieldwidth")
            .ok()
            .flatten()
            .unwrap_or(1u64));
    }
    if field.dimension_sizes.len() > 1 {
        return Err(Error::FieldsCannotHaveMultipleDimensions);
    }
    Ok(field.dimension_sizes[0])
}

fn translate_enum(name: &str, enm: systemrdl::ParentScope) -> Result<ureg::Enum, Error> {
    let wrap_err = |err: Error| Error::EnumError {
        enum_name: name.into(),
        err: Box::new(err),
    };
    expect_instance_type(enm, ComponentType::Enum.into()).map_err(wrap_err)?;
    let mut variants = vec![];
    let mut width = 0;
    for variant in enm.scope.instances.iter() {
        let wrap_err = |err: Error| {
            wrap_err(Error::EnumVariantError {
                variant_name: variant.name.clone(),
                err: Box::new(err),
            })
        };
        if variant.scope.ty != ComponentType::EnumVariant.into() {
            continue;
        }
        let Some(reset) = variant.reset else {
            return Err(wrap_err(Error::ValueNotDefined));
        };
        width = u64::max(width, reset.w());
        variants.push(ureg::EnumVariant {
            name: variant.name.clone(),
            value: reset.val() as u32,
        })
    }
    Ok(ureg::Enum {
        name: Some(name.to_string()),
        variants,
        bit_width: width as u8,
    })
}

fn translate_field(iref: systemrdl::InstanceRef) -> Result<ureg::RegisterField, Error> {
    let wrap_err = |err: Error| Error::FieldError {
        field_name: iref.instance.name.clone(),
        err: Box::new(err),
    };
    expect_instance_type(iref.scope, ComponentType::Field.into()).map_err(wrap_err)?;
    let inst = iref.instance;

    let access_ty: AccessType = get_property_opt(&inst.scope, "sw")?.unwrap_or_default();

    let enum_type =
        if let Ok(Some(systemrdl::EnumReference(eref))) = inst.scope.property_val_opt("encode") {
            if let Some(enm) = iref.scope.lookup_typedef(&eref) {
                Some(Rc::new(translate_enum(&eref, enm).map_err(wrap_err)?))
            } else {
                None
            }
        } else {
            None
        };

    let description: String = inst
        .scope
        .property_val_opt("desc")
        .unwrap()
        .unwrap_or_default();
    let result = ureg::RegisterField {
        name: inst.name.clone(),
        ty: translate_access_type(access_ty).map_err(wrap_err)?,
        default_val: inst.reset.map(|b| b.val()).unwrap_or_default(),
        comment: unpad_description(&description),
        enum_type,
        position: inst
            .offset
            .ok_or(Error::OffsetNotDefined)
            .map_err(wrap_err)? as u8,
        width: field_width(inst).map_err(wrap_err)? as u8,
    };

    Ok(result)
}

fn translate_register(iref: systemrdl::InstanceRef) -> Result<ureg::Register, Error> {
    let wrap_err = |err: Error| Error::RegisterError {
        register_name: iref.instance.name.clone(),
        err: Box::new(err),
    };

    expect_instance_type(iref.scope, ComponentType::Reg.into()).map_err(wrap_err)?;
    let inst = iref.instance;

    let description: String = inst
        .scope
        .property_val_opt("desc")
        .unwrap()
        .unwrap_or_default();

    if inst.reset.is_some() {
        return Err(wrap_err(Error::ResetValueOnRegisterUnsupported));
    }

    let ty = translate_register_ty(inst.type_name.clone(), iref.scope)?;

    let result = ureg_schema::Register {
        name: inst.name.clone(),
        offset: inst
            .offset
            .ok_or(Error::OffsetNotDefined)
            .map_err(wrap_err)?,
        default_val: ty.fields.iter().fold(0, |reset, field| {
            let width_mask = (1 << field.width) - 1;
            reset | ((field.default_val & width_mask) << field.position)
        }),
        comment: unpad_description(&description),
        array_dimensions: inst.dimension_sizes.clone(),
        ty,
    };

    Ok(result)
}
fn translate_register_ty(
    type_name: Option<String>,
    scope: ParentScope,
) -> Result<Rc<ureg_schema::RegisterType>, Error> {
    let wrap_err = |err: Error| {
        if let Some(ref type_name) = type_name {
            Error::RegisterTypeError {
                register_type_name: type_name.clone(),
                err: Box::new(err),
            }
        } else {
            err
        }
    };

    let regwidth = match get_property_opt(scope.scope, "regwidth").map_err(wrap_err)? {
        Some(8) => ureg_schema::RegisterWidth::_8,
        Some(16) => ureg_schema::RegisterWidth::_16,
        Some(32) => ureg_schema::RegisterWidth::_32,
        Some(64) => ureg_schema::RegisterWidth::_64,
        Some(other) => return Err(wrap_err(Error::UnsupportedRegWidth(other))),
        None => ureg_schema::RegisterWidth::_32,
    };

    let mut fields = vec![];
    for field in scope.instance_iter() {
        match translate_field(field).map_err(wrap_err) {
            Ok(field) => fields.push(field),
            Err(err) => {
                if matches!(err.root_cause(), Error::AccessTypeNaUnsupported) {
                    continue;
                } else {
                    return Err(err);
                }
            }
        }
    }
    Ok(Rc::new(ureg_schema::RegisterType {
        name: type_name,
        fields,
        width: regwidth,
    }))
}

pub fn translate_types(scope: systemrdl::ParentScope) -> Result<Vec<Rc<RegisterType>>, Error> {
    let mut result = vec![];
    for (name, subscope) in scope.type_iter() {
        if subscope.scope.ty == ComponentType::Reg.into() {
            result.push(translate_register_ty(Some(name.into()), subscope)?);
        }
    }
    Ok(result)
}

pub fn translate_addrmap(addrmap: systemrdl::ParentScope) -> Result<Vec<RegisterBlock>, Error> {
    expect_instance_type(addrmap, ComponentType::AddrMap.into())?;
    let mut blocks = vec![];
    for iref in addrmap.instance_iter() {
        let wrap_err = |err: Error| Error::RegisterError {
            register_name: iref.instance.name.clone(),
            err: Box::new(err),
        };
        let inst = iref.instance;
        let mut block = RegisterBlock {
            name: inst.name.clone(),
            ..Default::default()
        };
        if let Some(addr) = inst.offset {
            block.instances.push(RegisterBlockInstance {
                name: inst.name.clone(),
                address: u32::try_from(addr).map_err(|_| wrap_err(Error::AddressTooLarge(addr)))?,
            });
        }
        for (name, ty) in iref.scope.type_iter() {
            if ty.scope.ty == ComponentType::Reg.into() {
                block
                    .declared_register_types
                    .push(translate_register_ty(Some(name.into()), ty).map_err(wrap_err)?);
            }
        }
        for reg in iref.scope.instance_iter() {
            if reg.instance.scope.ty == ComponentType::Reg.into() {
                block
                    .registers
                    .push(Rc::new(translate_register(reg).map_err(wrap_err)?));
            }
        }
        blocks.push(block);
    }
    Ok(blocks)
}

/*++
Licensed under the Apache-2.0 license.
--*/

use crate::value::{ComponentType, PropertyType, ScopeType};
use crate::{RdlError, Result};

#[derive(Debug)]
pub struct PropertyMeta {
    pub name: &'static str,
    pub ty: PropertyType,
    pub is_dynamic: bool,
}

pub struct ComponentMeta {
    ty: ComponentType,
    pub can_instantiate: bool,
    deep_subelement_types: &'static [&'static ComponentMeta],
    properties: &'static [PropertyMeta],
}

#[rustfmt::skip]
static SIGNAL: ComponentMeta = ComponentMeta {
    ty: ComponentType::Signal,
    can_instantiate: true,
    deep_subelement_types: &[],
    properties: &[
        PropertyMeta{name: "signalwidth", ty: PropertyType::U64, is_dynamic: false },
        PropertyMeta{name: "sync", ty: PropertyType::Boolean, is_dynamic: true },
        PropertyMeta{name: "async", ty: PropertyType::Boolean, is_dynamic: true },
        PropertyMeta{name: "cpuif_reset", ty: PropertyType::Boolean, is_dynamic: true },
        PropertyMeta{name: "field_reset", ty: PropertyType::Boolean, is_dynamic: true },
        PropertyMeta{name: "activelow", ty: PropertyType::Boolean, is_dynamic: true },
        PropertyMeta{name: "activehigh", ty: PropertyType::Boolean, is_dynamic: true },
    ],
};

#[rustfmt::skip]
static FIELD: ComponentMeta = ComponentMeta {
    ty: ComponentType::Field,
    can_instantiate: true,
    deep_subelement_types: &[],
    properties: &[
        // Structural properties
        PropertyMeta{name: "donttest", ty: PropertyType::Bits, is_dynamic: true},
        PropertyMeta{name: "dontcompare", ty: PropertyType::Bits, is_dynamic: true},

        // Field access properties
        PropertyMeta{name: "hw", ty: PropertyType::AccessType, is_dynamic: false},
        PropertyMeta{name: "sw", ty: PropertyType::AccessType, is_dynamic: true},

        // Hardware signal properties
        PropertyMeta{name: "next", ty: PropertyType::Reference, is_dynamic: true},
        PropertyMeta{name: "reset", ty: PropertyType::BitOrReference, is_dynamic: true},
        PropertyMeta{name: "resetsignal", ty: PropertyType::Reference, is_dynamic: true},

        // Software access properties
        PropertyMeta{name: "rclr", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "rset", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "onread", ty: PropertyType::OnReadType, is_dynamic: true},
        PropertyMeta{name: "woset", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "woclr", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "onwrite", ty: PropertyType::OnWriteType, is_dynamic: true},
        PropertyMeta{name: "swwe", ty: PropertyType::BooleanOrReference, is_dynamic: true},
        PropertyMeta{name: "swwel", ty: PropertyType::BooleanOrReference, is_dynamic: true},
        PropertyMeta{name: "swmod", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "swacc", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "singlepulse", ty: PropertyType::Boolean, is_dynamic: true},

        // Hardware access properties
        PropertyMeta{name: "we", ty: PropertyType::BooleanOrReference, is_dynamic: true},
        PropertyMeta{name: "wel", ty: PropertyType::BooleanOrReference, is_dynamic: true},
        PropertyMeta{name: "anded", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "ored", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "xored", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "fieldwidth", ty: PropertyType::U64, is_dynamic: true},
        PropertyMeta{name: "hwclr", ty: PropertyType::BooleanOrReference, is_dynamic: true},
        PropertyMeta{name: "hwset", ty: PropertyType::BooleanOrReference, is_dynamic: true},
        PropertyMeta{name: "hwenable", ty: PropertyType::Reference, is_dynamic: true},
        PropertyMeta{name: "hwmask", ty: PropertyType::Reference, is_dynamic: true},

        // Counter field properties
        PropertyMeta{name: "counter", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "threshold", ty: PropertyType::BitOrReference, is_dynamic: true}, // alias incrthreshold
        PropertyMeta{name: "saturate", ty: PropertyType::BitOrReference, is_dynamic: true}, // alias incrsaturate
        PropertyMeta{name: "incrthreshold", ty: PropertyType::BitOrReference, is_dynamic: true},
        PropertyMeta{name: "incrsaturate", ty: PropertyType::BitOrReference, is_dynamic: true},
        PropertyMeta{name: "overflow", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "underflow", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "incrvalue", ty: PropertyType::BitOrReference, is_dynamic: true},
        PropertyMeta{name: "incr", ty: PropertyType::Reference, is_dynamic: true},
        PropertyMeta{name: "incrwidth", ty: PropertyType::U64, is_dynamic: true},
        PropertyMeta{name: "decrvalue", ty: PropertyType::BitOrReference, is_dynamic: true},
        PropertyMeta{name: "decr", ty: PropertyType::Reference, is_dynamic: true},
        PropertyMeta{name: "decrwidth", ty: PropertyType::U64, is_dynamic: true},
        PropertyMeta{name: "decrsaturate", ty: PropertyType::BitOrReference, is_dynamic: true},
        PropertyMeta{name: "decrthreshold", ty: PropertyType::BitOrReference, is_dynamic: true},

        // Field access interrupt properties
        PropertyMeta{name: "intr" , ty: PropertyType::FieldInterrupt, is_dynamic: true}, // also
        PropertyMeta{name: "enable", ty: PropertyType::Reference, is_dynamic: true},
        PropertyMeta{name: "mask", ty: PropertyType::Reference, is_dynamic: true},
        PropertyMeta{name: "haltenable", ty: PropertyType::Reference, is_dynamic: true},
        PropertyMeta{name: "haltmask", ty: PropertyType::Reference, is_dynamic: true},
        PropertyMeta{name: "sticky", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "stickybit", ty: PropertyType::Boolean, is_dynamic: true},

        // Miscellaneous field properties
        PropertyMeta{name: "encode", ty: PropertyType::EnumReference, is_dynamic: true},
        PropertyMeta{name: "precedence", ty: PropertyType::PrecedenceType, is_dynamic: true},
        PropertyMeta{name: "paritycheck", ty: PropertyType::Boolean, is_dynamic: true},
    ],
};

#[rustfmt::skip]
static REG: ComponentMeta = ComponentMeta {
    ty: ComponentType::Reg,
    can_instantiate: true,
    deep_subelement_types: &[&FIELD],
    properties: &[
        PropertyMeta{name: "regwidth", ty: PropertyType::U64, is_dynamic: true},
        PropertyMeta{name: "accesswidth", ty: PropertyType::U64, is_dynamic: true},
        PropertyMeta{name: "errextbus", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "shared", ty: PropertyType::Boolean, is_dynamic: true},
    ],
};

#[rustfmt::skip]
static MEM: ComponentMeta = ComponentMeta {
    ty: ComponentType::Mem,
    can_instantiate: true,
    deep_subelement_types: &[],
    properties: &[
        PropertyMeta{name: "mementries", ty: PropertyType::U64, is_dynamic: true},
        PropertyMeta{name: "memwidth", ty: PropertyType::U64, is_dynamic: true},
        PropertyMeta{name: "sw", ty: PropertyType::AccessType, is_dynamic: true},
    ],
};

#[rustfmt::skip]
static REGFILE: ComponentMeta = ComponentMeta {
    ty: ComponentType::RegFile,
    can_instantiate: true,
    deep_subelement_types: &[&REG, &REGFILE, &FIELD, &SIGNAL],
    properties: &[
        PropertyMeta{name: "alignment", ty: PropertyType::U64, is_dynamic: true},
        PropertyMeta{name: "sharedextbus", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "errextbus", ty: PropertyType::Boolean, is_dynamic: true},
    ],
};

#[rustfmt::skip]
static ADDRMAP: ComponentMeta = ComponentMeta {
    ty: ComponentType::AddrMap,
    can_instantiate: true,
    deep_subelement_types: &[&REG, &REGFILE, &FIELD, &SIGNAL],
    properties: &[
        PropertyMeta{name: "alignment", ty: PropertyType::U64, is_dynamic: false},
        PropertyMeta{name: "sharedextbus", ty: PropertyType::Boolean, is_dynamic: false},
        PropertyMeta{name: "errextbus", ty: PropertyType::Boolean, is_dynamic: false},
        PropertyMeta{name: "bigendian", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "littleendian", ty: PropertyType::Boolean, is_dynamic: true},
        PropertyMeta{name: "addressing", ty: PropertyType::AddressingType, is_dynamic: false},
        PropertyMeta{name: "rsvdset", ty: PropertyType::Boolean, is_dynamic: false},
        PropertyMeta{name: "rsvdsetX", ty: PropertyType::Boolean, is_dynamic: false},
        PropertyMeta{name: "msb0", ty: PropertyType::Boolean, is_dynamic: false},
        PropertyMeta{name: "lsb0", ty: PropertyType::Boolean, is_dynamic: false},
    ],
};

static CONSTRAINT: ComponentMeta = ComponentMeta {
    ty: ComponentType::Constraint,
    can_instantiate: true,
    deep_subelement_types: &[],
    properties: &[],
};

static ENUM: ComponentMeta = ComponentMeta {
    ty: ComponentType::Enum,
    can_instantiate: false,
    deep_subelement_types: &[],
    properties: &[],
};

static ENUM_VARIANT: ComponentMeta = ComponentMeta {
    ty: ComponentType::EnumVariant,
    can_instantiate: false,
    deep_subelement_types: &[],
    properties: &[],
};

pub fn get_component_meta(component_type: ComponentType) -> &'static ComponentMeta {
    let result = match component_type {
        ComponentType::Field => &FIELD,
        ComponentType::Reg => &REG,
        ComponentType::RegFile => &REGFILE,
        ComponentType::AddrMap => &ADDRMAP,
        ComponentType::Signal => &SIGNAL,
        ComponentType::Mem => &MEM,
        ComponentType::Constraint => &CONSTRAINT,
        ComponentType::Enum => &ENUM,
        ComponentType::EnumVariant => &ENUM_VARIANT,
    };
    assert!(result.ty == component_type);
    result
}

static ALL_COMPONENTS: [&ComponentMeta; 8] = [
    &FIELD,
    &REG,
    &REGFILE,
    &ADDRMAP,
    &SIGNAL,
    &MEM,
    &ENUM,
    &CONSTRAINT,
];

static GENERAL_PROPERTIES: [PropertyMeta; 2] = [
    PropertyMeta {
        name: "name",
        ty: PropertyType::String,
        is_dynamic: true,
    },
    PropertyMeta {
        name: "desc",
        ty: PropertyType::String,
        is_dynamic: true,
    },
];

pub(crate) fn property(
    component_type: ComponentType,
    name: &str,
) -> Result<'_, &'static PropertyMeta> {
    if let Some(p) = GENERAL_PROPERTIES.iter().find(|m| m.name == name) {
        return Ok(p);
    }
    if let Some(p) = get_component_meta(component_type)
        .properties
        .iter()
        .find(|m| m.name == name)
    {
        return Ok(p);
    }
    Err(RdlError::UnknownPropertyName(name))
}

pub(crate) fn default_property(
    scope_type: ScopeType,
    name: &str,
) -> Result<'_, &'static PropertyMeta> {
    if let Some(p) = GENERAL_PROPERTIES.iter().find(|m| m.name == name) {
        return Ok(p);
    }
    let ScopeType::Component(component_type) = scope_type else {
        for subcomponent_meta in ALL_COMPONENTS.iter() {
            if let Some(p) = subcomponent_meta.properties.iter().find(|m| m.name == name) {
                return Ok(p);
            }
        }
        return Err(RdlError::UnknownPropertyName(name));
    };
    for subcomponent_meta in get_component_meta(component_type)
        .deep_subelement_types
        .iter()
    {
        if let Some(p) = subcomponent_meta.properties.iter().find(|m| m.name == name) {
            return Ok(p);
        }
    }
    Err(RdlError::UnknownPropertyName(name))
}

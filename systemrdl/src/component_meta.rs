/*++
Licensed under the Apache-2.0 license.
--*/

use crate::value::{ComponentType, PropertyType, ScopeType};
use crate::{RdlError, Result};

#[derive(Debug)]
pub struct PropertyMeta {
    pub name: &'static str,
    pub ty: PropertyType,
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
        PropertyMeta{name: "signalwidth", ty: PropertyType::U64},
        PropertyMeta{name: "sync", ty: PropertyType::Boolean},
        PropertyMeta{name: "async", ty: PropertyType::Boolean},
        PropertyMeta{name: "cpuif_reset", ty: PropertyType::Boolean},
        PropertyMeta{name: "field_reset", ty: PropertyType::Boolean},
        PropertyMeta{name: "activelow", ty: PropertyType::Boolean},
        PropertyMeta{name: "activehigh", ty: PropertyType::Boolean},
    ],
};

#[rustfmt::skip]
static FIELD: ComponentMeta = ComponentMeta {
    ty: ComponentType::Field,
    can_instantiate: true,
    deep_subelement_types: &[],
    properties: &[
        // Structural properties
        PropertyMeta{name: "donttest", ty: PropertyType::Bits},
        PropertyMeta{name: "dontcompare", ty: PropertyType::Bits},

        // Field access properties
        PropertyMeta{name: "hw", ty: PropertyType::AccessType},
        PropertyMeta{name: "sw", ty: PropertyType::AccessType},

        // Hardware signal properties
        PropertyMeta{name: "next", ty: PropertyType::Reference},
        PropertyMeta{name: "reset", ty: PropertyType::BitOrReference},
        PropertyMeta{name: "resetsignal", ty: PropertyType::Reference},

        // Software access properties
        PropertyMeta{name: "rclr", ty: PropertyType::Boolean},
        PropertyMeta{name: "rset", ty: PropertyType::Boolean},
        PropertyMeta{name: "onread", ty: PropertyType::OnReadType},
        PropertyMeta{name: "woset", ty: PropertyType::Boolean},
        PropertyMeta{name: "woclr", ty: PropertyType::Boolean},
        PropertyMeta{name: "onwrite", ty: PropertyType::OnWriteType},
        PropertyMeta{name: "swwe", ty: PropertyType::BooleanOrReference},
        PropertyMeta{name: "swwel", ty: PropertyType::BooleanOrReference},
        PropertyMeta{name: "swmod", ty: PropertyType::Boolean},
        PropertyMeta{name: "swacc", ty: PropertyType::Boolean},
        PropertyMeta{name: "singlepulse", ty: PropertyType::Boolean},

        // Hardware access properties
        PropertyMeta{name: "we", ty: PropertyType::BooleanOrReference},
        PropertyMeta{name: "wel", ty: PropertyType::BooleanOrReference},
        PropertyMeta{name: "anded", ty: PropertyType::Boolean},
        PropertyMeta{name: "ored", ty: PropertyType::Boolean},
        PropertyMeta{name: "xored", ty: PropertyType::Boolean},
        PropertyMeta{name: "fieldwidth", ty: PropertyType::U64},
        PropertyMeta{name: "hwclr", ty: PropertyType::BooleanOrReference},
        PropertyMeta{name: "hwset", ty: PropertyType::BooleanOrReference},
        PropertyMeta{name: "hwenable", ty: PropertyType::Reference},
        PropertyMeta{name: "hwmask", ty: PropertyType::Reference},

        // Counter field properties
        PropertyMeta{name: "counter", ty: PropertyType::Boolean},
        PropertyMeta{name: "threshold", ty: PropertyType::BitOrReference}, // alias incrthreshold
        PropertyMeta{name: "saturate", ty: PropertyType::BitOrReference}, // alias incrsaturate
        PropertyMeta{name: "incrthreshold", ty: PropertyType::BitOrReference},
        PropertyMeta{name: "incrsaturate", ty: PropertyType::BitOrReference},
        PropertyMeta{name: "overflow", ty: PropertyType::Boolean},
        PropertyMeta{name: "underflow", ty: PropertyType::Boolean},
        PropertyMeta{name: "incrvalue", ty: PropertyType::BitOrReference},
        PropertyMeta{name: "incr", ty: PropertyType::Reference},
        PropertyMeta{name: "incrwidth", ty: PropertyType::U64},
        PropertyMeta{name: "decrvalue", ty: PropertyType::BitOrReference},
        PropertyMeta{name: "decr", ty: PropertyType::Reference},
        PropertyMeta{name: "decrwidth", ty: PropertyType::U64},
        PropertyMeta{name: "decrsaturate", ty: PropertyType::BitOrReference},
        PropertyMeta{name: "decrthreshold", ty: PropertyType::BitOrReference},

        // Field access interrupt properties
        PropertyMeta{name: "intr" , ty: PropertyType::FieldInterrupt}, // also
        PropertyMeta{name: "enable", ty: PropertyType::Reference},
        PropertyMeta{name: "mask", ty: PropertyType::Reference},
        PropertyMeta{name: "haltenable", ty: PropertyType::Reference},
        PropertyMeta{name: "haltmask", ty: PropertyType::Reference},
        PropertyMeta{name: "sticky", ty: PropertyType::Boolean},
        PropertyMeta{name: "stickybit", ty: PropertyType::Boolean},

        // Miscellaneous field properties
        PropertyMeta{name: "encode", ty: PropertyType::EnumReference},
        PropertyMeta{name: "precedence", ty: PropertyType::PrecedenceType},
        PropertyMeta{name: "paritycheck", ty: PropertyType::Boolean},
    ],
};

#[rustfmt::skip]
static REG: ComponentMeta = ComponentMeta {
    ty: ComponentType::Reg,
    can_instantiate: true,
    deep_subelement_types: &[&FIELD],
    properties: &[
        PropertyMeta{name: "regwidth", ty: PropertyType::U64},
        PropertyMeta{name: "accesswidth", ty: PropertyType::U64},
        PropertyMeta{name: "errextbus", ty: PropertyType::Boolean},
        PropertyMeta{name: "shared", ty: PropertyType::Boolean},
    ],
};

#[rustfmt::skip]
static MEM: ComponentMeta = ComponentMeta {
    ty: ComponentType::Mem,
    can_instantiate: true,
    deep_subelement_types: &[],
    properties: &[
        PropertyMeta{name: "mementries", ty: PropertyType::U64},
        PropertyMeta{name: "memwidth", ty: PropertyType::U64},
        PropertyMeta{name: "sw", ty: PropertyType::AccessType},
    ],
};

#[rustfmt::skip]
static REGFILE: ComponentMeta = ComponentMeta {
    ty: ComponentType::RegFile,
    can_instantiate: true,
    deep_subelement_types: &[&REG, &REGFILE, &FIELD, &SIGNAL],
    properties: &[
        PropertyMeta{name: "alignment", ty: PropertyType::U64},
        PropertyMeta{name: "sharedextbus", ty: PropertyType::Boolean},
        PropertyMeta{name: "errextbus", ty: PropertyType::Boolean},
    ],
};

#[rustfmt::skip]
static ADDRMAP: ComponentMeta = ComponentMeta {
    ty: ComponentType::AddrMap,
    can_instantiate: true,
    deep_subelement_types: &[&REG, &REGFILE, &FIELD, &SIGNAL],
    properties: &[
        PropertyMeta{name: "alignment", ty: PropertyType::U64},
        PropertyMeta{name: "sharedextbus", ty: PropertyType::Boolean},
        PropertyMeta{name: "errextbus", ty: PropertyType::Boolean},
        PropertyMeta{name: "bigendian", ty: PropertyType::Boolean},
        PropertyMeta{name: "littleendian", ty: PropertyType::Boolean},
        PropertyMeta{name: "addressing", ty: PropertyType::AddressingType},
        PropertyMeta{name: "rsvdset", ty: PropertyType::Boolean},
        PropertyMeta{name: "rsvdsetX", ty: PropertyType::Boolean},
        PropertyMeta{name: "msb0", ty: PropertyType::Boolean},
        PropertyMeta{name: "lsb0", ty: PropertyType::Boolean},
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
    },
    PropertyMeta {
        name: "desc",
        ty: PropertyType::String,
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

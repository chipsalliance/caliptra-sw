/*++
Licensed under the Apache-2.0 license.
--*/

use std::error::Error;
use std::fmt::Write;

use caliptra_systemrdl::{ComponentType, EnumReference, InputFile, InstanceRef, ScopeType};

fn dimension_suffix(dimensions: &[u64]) -> String {
    let mut result = String::new();
    for dimension in dimensions {
        write!(&mut result, "[{}]", dimension).unwrap();
    }
    result
}

fn print_instance(iref: InstanceRef, padding: &str) {
    let inst = iref.instance;
    match inst.scope.ty {
        ScopeType::Component(ComponentType::Field) => {
            println!(
                "{}{}: field {}{}",
                padding,
                inst.offset.unwrap(),
                inst.name,
                dimension_suffix(&inst.dimension_sizes)
            );
            if let Ok(Some(EnumReference(eref))) = inst.scope.property_val_opt("encode") {
                if let Some(enm) = iref.scope.lookup_typedef(&eref) {
                    println!("{}  enum {}", padding, eref);
                    for variant in enm.instance_iter() {
                        print_instance(variant, &format!("{padding}    "));
                    }
                }
            }
        }
        ScopeType::Component(ComponentType::Reg) => {
            println!(
                "{}{:#x?}: reg {}{}",
                padding,
                inst.offset.unwrap(),
                inst.name,
                dimension_suffix(&inst.dimension_sizes)
            );
        }
        ScopeType::Component(ComponentType::RegFile) => {
            println!(
                "{}{:x?}: regfile {}{}",
                padding,
                inst.offset,
                inst.name,
                dimension_suffix(&inst.dimension_sizes)
            );
        }
        ScopeType::Component(ComponentType::AddrMap) => {
            println!(
                "{}{:#x?}: addrmap {}{}",
                padding,
                inst.offset.unwrap(),
                inst.name,
                dimension_suffix(&inst.dimension_sizes)
            );
        }
        ScopeType::Component(ComponentType::EnumVariant) => {
            println!(
                "{}{}: variant {}",
                padding,
                inst.reset.as_ref().unwrap().val(),
                inst.name
            );
        }
        _ => {}
    }
    for sub_inst in iref.scope.instance_iter() {
        print_instance(sub_inst, &format!("{padding}  "));
    }
}

fn real_main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        Err("Usage: parse <file.rdl>...")?;
    }
    let files =
        args[1..]
            .iter()
            .try_fold(vec![], |mut acc, name| -> std::io::Result<Vec<InputFile>> {
                acc.push(InputFile::read(name.as_ref())?);
                Ok(acc)
            })?;

    let scope = caliptra_systemrdl::Scope::parse_root(&files).map_err(|s| s.to_string())?;
    let scope = scope.as_parent();

    let addrmap = scope.lookup_typedef("clp").unwrap();

    for inst in addrmap.instance_iter() {
        print_instance(inst, "");
    }

    Ok(())
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

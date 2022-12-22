/*++
Licensed under the Apache-2.0 license.
--*/

//! General-purpose parser for systemrdl files.
//!
//! Not yet implemented:
//! - dynamic assignment
//! - instance parameters
//!
//! Examples
//!
//! ```no_run
//! use caliptra_systemrdl::{ComponentType, EnumReference, InputFile, InstanceRef, Scope, ScopeType};
//!
//! let file = InputFile::read(std::path::Path::new("/tmp/foo.rdl")).unwrap();
//! let scope = Scope::parse_root(&[file]).unwrap();
//! let parent = scope.as_parent();
//!
//! let clp = parent.lookup_typedef("clp").unwrap();
//! for iref in clp.instance_iter() {
//!   print_instance(iref, "");
//! }
//!
//! fn print_instance(iref: InstanceRef, padding: &str) {
//!     let inst = iref.instance;
//!     match inst.scope.ty {
//!         ScopeType::Component(ComponentType::Field) => {
//!             println!("{}{}: field {}", padding, inst.offset.unwrap(), inst.name);
//!             if let Ok(Some(EnumReference(eref))) = inst.scope.property_val_opt("encode") {
//!                 if let Some(enm) = iref.scope.lookup_typedef(&eref) {
//!                     println!("{}  enum {}", padding, eref);
//!                     for variant in enm.instance_iter() {
//!                         print_instance(variant, &format!("{padding}    "));
//!                     }
//!                 }
//!             }
//!         }
//!         ScopeType::Component(ComponentType::Reg) => {
//!             println!("{}{:#x?}: reg {}", padding, inst.offset.unwrap(), inst.name);
//!         }
//!         ScopeType::Component(ComponentType::RegFile) => {
//!             println!("{}{:x?}: regfile {}", padding, inst.offset.unwrap(), inst.name);
//!         }
//!         ScopeType::Component(ComponentType::AddrMap) => {
//!             println!("{}{:#x?}: addrmap {}", padding, inst.offset.unwrap(), inst.name);
//!         }
//!         ScopeType::Component(ComponentType::EnumVariant) => {
//!             println!("{}{}: variant {}", padding, inst.reset.as_ref().unwrap().val(), inst.name);
//!         }
//!         _ => {}
//!     }
//!     for sub_inst in iref.scope.instance_iter() {
//!         print_instance(sub_inst, &format!("{padding}  "));
//!     }
//! }
//!  
//! ```
//!

mod bits;
mod component_meta;
mod error;
mod lexer;
mod scope;
mod token;
mod token_iter;
mod value;

use lexer::Span;
pub use scope::Scope;
pub use value::Value;

pub use error::RdlError;
pub use scope::{Instance, InstanceRef, ParentScope};
pub use value::AccessType;
pub use value::AddressingType;
pub use value::ComponentType;
pub use value::EnumReference;
pub use value::ScopeType;

pub use crate::bits::Bits;

use std::fmt::{Debug, Display};
use std::path::Path;

pub type Result<'a, T> = std::result::Result<T, RdlError<'a>>;

pub struct InputFile {
    // The filename
    pub name: String,

    // The full contents of the file
    pub text: String,
}
impl InputFile {
    pub fn read(filename: &Path) -> std::io::Result<InputFile> {
        Ok(InputFile {
            name: filename.to_string_lossy().into(),
            text: std::fs::read_to_string(filename)?,
        })
    }
    pub fn fake(text: &str) -> InputFile {
        InputFile {
            name: "".into(),
            text: text.into(),
        }
    }
}

#[derive(Debug)]
pub struct FileLocation<'a> {
    line: usize,
    column: usize,
    line_val: &'a str,
}

pub struct FileParseError<'a> {
    file_id: &'a str,
    file_text: &'a str,
    span: Span,
    pub error: RdlError<'a>,
}
impl<'a> FileParseError<'a> {
    fn new(file_id: &'a str, file_text: &'a str, mut span: Span, error: RdlError<'a>) -> Self {
        span.start = Ord::min(file_text.len(), span.start);
        span.end = Ord::min(file_text.len(), span.end);
        Self {
            file_id,
            file_text,
            span,
            error,
        }
    }
    pub fn location(&self) -> FileLocation {
        let mut line = 1;
        let mut column = 1;
        let mut line_start: &str = self.file_text;
        for (offset, ch) in self.file_text.as_bytes()[0..self.span.start]
            .iter()
            .enumerate()
        {
            if *ch == b'\n' {
                line += 1;
                column = 1;
                line_start = &self.file_text[offset + 1..];
            } else {
                column += 1;
            }
        }
        FileLocation {
            line,
            column,
            line_val: line_start.lines().next().unwrap(),
        }
    }
}
impl Debug for FileParseError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileParseError")
            .field("span", &self.span)
            .field("error", &self.error)
            .field("location", &self.location())
            .finish()
    }
}
impl Display for FileParseError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let location = self.location();
        writeln!(
            f,
            "At {} line {} column {}, {}:",
            self.file_id, location.line, location.column, self.error
        )?;
        writeln!(f, "    {}", location.line_val)?;
        write!(f, "    {}^", " ".repeat(location.column - 1))
    }
}

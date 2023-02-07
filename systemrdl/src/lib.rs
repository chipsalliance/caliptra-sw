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
//! use caliptra_systemrdl::{ComponentType, EnumReference, FileSource, FsFileSource, InstanceRef, Scope, ScopeType};
//!
//! let fs = FsFileSource::new();
//! let scope = Scope::parse_root(&fs, &["/tmp/foo.rdl".into()]).unwrap();
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
mod file_source;
mod lexer;
mod scope;
mod string_arena;
mod token;
mod token_iter;
mod value;

use lexer::Span;
pub use scope::Scope;
pub use value::Value;

pub use error::RdlError;
pub use file_source::{FileSource, FsFileSource};
pub use scope::{Instance, InstanceRef, ParentScope};
pub use value::AccessType;
pub use value::AddressingType;
pub use value::ComponentType;
pub use value::EnumReference;
pub use value::ScopeType;

pub use crate::bits::Bits;

use std::fmt::{Debug, Display};
use std::path::Path;
use std::path::PathBuf;

pub type Result<'a, T> = std::result::Result<T, RdlError<'a>>;

#[derive(Debug)]
pub struct FileLocation<'a> {
    line: usize,
    column: usize,
    line_val: &'a str,
}

#[derive(Debug)]
pub enum FileParseError<'a> {
    Parse(ParseError<'a>),
    Io(std::io::Error),
    CouldNotCalculateOffsets,
}

pub struct ParseError<'a> {
    file_id: PathBuf,
    file_text: &'a str,
    span: Span,
    pub error: RdlError<'a>,
}
impl<'a> ParseError<'a> {
    fn new(file_id: &Path, file_text: &'a str, mut span: Span, error: RdlError<'a>) -> Self {
        span.start = Ord::min(file_text.len(), span.start);
        span.end = Ord::min(file_text.len(), span.end);
        Self {
            file_id: file_id.into(),
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
impl Debug for ParseError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileParseError")
            .field("span", &self.span)
            .field("error", &self.error)
            .field("location", &self.location())
            .finish()
    }
}
impl Display for ParseError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let location = self.location();
        writeln!(
            f,
            "At {:?} line {} column {}, {}:",
            self.file_id, location.line, location.column, self.error
        )?;
        writeln!(f, "    {}", location.line_val)?;
        write!(f, "    {}^", " ".repeat(location.column - 1))
    }
}

impl Display for FileParseError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileParseError::Parse(e) => Display::fmt(e, f),
            FileParseError::Io(e) => Display::fmt(e, f),
            FileParseError::CouldNotCalculateOffsets => write!(f, "Could not calculate offsets"),
        }
    }
}

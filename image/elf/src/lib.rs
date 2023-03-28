/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains ELF Executable loading and parsing related functionality.

--*/

use anyhow::{bail, Context};
use caliptra_image_gen::ImageGenratorExecutable;
use caliptra_image_types::ImageRevision;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use std::path::PathBuf;

/// ELF Executable
#[derive(Default)]
pub struct ElfExecutable {
    svn: u32,
    min_svn: u32,
    rev: ImageRevision,
    load_addr: u32,
    entry_point: u32,
    content: Vec<u8>,
}

impl ElfExecutable {
    /// Create new instance of `ElfExecutable`.
    pub fn new(path: &PathBuf, svn: u32, min_svn: u32, rev: ImageRevision) -> anyhow::Result<Self> {
        let mut content = vec![];

        let file_data = std::fs::read(path).with_context(|| "Failed to read file")?;

        let elf_file = ElfBytes::<AnyEndian>::minimal_parse(&file_data)
            .with_context(|| "Failed to parse elf file")?;

        let (load_addr, text) = Self::read_section(&elf_file, ".text", true)?;
        content.extend_from_slice(text);

        let (_, rodata) = Self::read_section(&elf_file, ".rodata", false)?;
        content.extend_from_slice(rodata);

        let (_, data) = Self::read_section(&elf_file, ".data", false)?;
        content.extend_from_slice(data);

        let entry_point = elf_file.ehdr.e_entry as u32;

        Ok(Self {
            svn,
            min_svn,
            rev,
            load_addr,
            entry_point,
            content,
        })
    }

    /// Read a section from ELF file
    fn read_section<'a>(
        elf_file: &'a ElfBytes<AnyEndian>,
        name: &str,
        required: bool,
    ) -> anyhow::Result<(u32, &'a [u8])> {
        let load_addr: u32;
        let section = elf_file
            .section_header_by_name(name)
            .with_context(|| format!("Failed to find {name} section"))?;
        if let Some(section) = section {
            let data = elf_file
                .section_data(&section)
                .with_context(|| format!("Failed to read {name} section"))?
                .0;
            load_addr = section.sh_addr as u32;
            Ok((load_addr, data))
        } else {
            if required {
                bail!("{} section not found", name)
            }
            Ok((0, &[]))
        }
    }
}

impl ImageGenratorExecutable for ElfExecutable {
    /// Executable Security Version Number
    fn svn(&self) -> u32 {
        self.svn
    }

    /// Executable Minimum Security Version Number
    fn min_svn(&self) -> u32 {
        self.min_svn
    }

    /// Executable Revision
    fn rev(&self) -> &ImageRevision {
        &self.rev
    }

    /// Executable load address
    fn load_addr(&self) -> u32 {
        self.load_addr
    }

    /// Executable entry point
    fn entry_point(&self) -> u32 {
        self.entry_point
    }

    /// Executable content
    fn content(&self) -> &Vec<u8> {
        &self.content
    }

    /// Executable size
    fn size(&self) -> u32 {
        self.content.len() as u32
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains ELF Executable loading and parsing related functionality.

--*/

use anyhow::{bail, Context};
use caliptra_image_gen::ImageGeneratorExecutable;
use caliptra_image_types::ImageRevision;
use elf::abi::PT_LOAD;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use std::path::PathBuf;

/// ELF Executable
#[derive(Default)]
pub struct ElfExecutable {
    version: u32,
    svn: u32,
    rev: ImageRevision,
    load_addr: u32,
    entry_point: u32,
    content: Vec<u8>,
}

fn load_into_image(
    image: &mut Vec<u8>,
    image_base_addr: u32,
    section_addr: u32,
    section_data: &[u8],
) -> anyhow::Result<()> {
    if section_addr < image_base_addr {
        bail!("Section address 0x{section_addr:08x} is below image base address 0x{image_base_addr:08x}");
    }
    let section_offset = usize::try_from(section_addr - image_base_addr).unwrap();
    image.resize(
        usize::max(image.len(), section_offset + section_data.len()),
        u8::default(),
    );
    image[section_offset..][..section_data.len()].copy_from_slice(section_data);
    Ok(())
}

impl ElfExecutable {
    pub fn open(
        path: &PathBuf,
        version: u32,
        svn: u32,
        rev: ImageRevision,
    ) -> anyhow::Result<Self> {
        let file_data = std::fs::read(path).with_context(|| "Failed to read file")?;
        ElfExecutable::new(&file_data, version, svn, rev)
    }
    /// Create new instance of `ElfExecutable`.
    pub fn new(
        elf_bytes: &[u8],
        version: u32,
        svn: u32,
        rev: ImageRevision,
    ) -> anyhow::Result<Self> {
        let mut content = vec![];

        let elf_file = ElfBytes::<AnyEndian>::minimal_parse(elf_bytes)
            .with_context(|| "Failed to parse elf file")?;

        let Some(segments) = elf_file.segments() else {
            bail!("ELF file has no segments");
        };

        let Some(load_addr) = segments.iter().filter(|s| s.p_type == PT_LOAD).map(|s| s.p_paddr as u32).min() else {
            bail!("ELF file has no LOAD segments");
        };

        for segment in segments {
            if segment.p_type != PT_LOAD {
                continue;
            }
            let segment_data = elf_file.segment_data(&segment)?;
            if segment_data.is_empty() {
                continue;
            }
            load_into_image(
                &mut content,
                load_addr,
                segment.p_paddr as u32,
                segment_data,
            )?;
        }

        let entry_point = elf_file.ehdr.e_entry as u32;

        Ok(Self {
            version,
            svn,
            rev,
            load_addr,
            entry_point,
            content,
        })
    }
}

impl ImageGeneratorExecutable for ElfExecutable {
    /// Executable Version Number
    fn version(&self) -> u32 {
        self.version
    }

    /// Executable Security Version Number
    fn svn(&self) -> u32 {
        self.svn
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

#[cfg(test)]
mod test {
    use crate::load_into_image;

    #[test]
    fn test_load_into_image() {
        let mut image = Vec::new();
        load_into_image(&mut image, 0x4000_0000, 0x4000_0006, b"hello world").unwrap();
        load_into_image(&mut image, 0x4000_0000, 0x4000_0000, b"abcdef").unwrap();
        load_into_image(&mut image, 0x4000_0000, 0x4000_0011, b"hi").unwrap();
        assert_eq!(&image, b"abcdefhello worldhi");
    }

    #[test]
    fn test_load_into_image_bad_address() {
        let mut image = Vec::new();
        assert_eq!(
            load_into_image(&mut image, 0x4000_0000, 0x3fff_ffff, b"h")
                .unwrap_err()
                .to_string(),
            "Section address 0x3fffffff is below image base address 0x40000000"
        );
    }
}

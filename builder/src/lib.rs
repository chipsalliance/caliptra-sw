// Licensed under the Apache-2.0 license

use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::process::Command;

use elf::endian::LittleEndian;

fn other_err(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(ErrorKind::Other, e)
}

fn run_cmd(cmd: &mut Command) -> io::Result<()> {
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::Other,
            format!(
                "Process {:?} {:?} exited with status code {:?}",
                cmd.get_program(),
                cmd.get_args(),
                status.code()
            ),
        ))
    }
}

pub fn build_firmware_elf(fw_crate_name: &str, bin_name: &str) -> io::Result<Vec<u8>> {
    const WORKSPACE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    const TARGET: &str = "riscv32imc-unknown-none-elf";
    const PROFILE: &str = "firmware";

    run_cmd(
        Command::new(env!("CARGO"))
            .current_dir(WORKSPACE_DIR)
            .arg("build")
            .arg("--quiet")
            .arg("--locked")
            .arg("--target")
            .arg(TARGET)
            .arg("--features=emu,riscv")
            .arg("--profile")
            .arg(PROFILE)
            .arg("-p")
            .arg(fw_crate_name)
            .arg("--bin")
            .arg(bin_name),
    )?;
    fs::read(
        Path::new(WORKSPACE_DIR)
            .join("target")
            .join(TARGET)
            .join(PROFILE)
            .join(bin_name),
    )
}

pub fn build_firmware_rom(fw_crate_name: &str, bin_name: &str) -> io::Result<Vec<u8>> {
    let elf_bytes = build_firmware_elf(fw_crate_name, bin_name)?;
    elf2rom(&elf_bytes)
}

pub fn elf2rom(elf_bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = vec![0u8; 0x8000];
    let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).map_err(other_err)?;

    let Some(segments) = elf.segments() else {
        return Err(other_err("ELF file has no segments"))
    };
    for segment in segments {
        if segment.p_type != elf::abi::PT_LOAD {
            continue;
        }
        let file_offset = segment.p_offset as usize;
        let mem_offset = segment.p_paddr as usize;
        let len = segment.p_filesz as usize;
        let Some(src_bytes) = elf_bytes.get(file_offset..file_offset + len) else {
            return Err(other_err(format!("segment at 0x{:x} out of file bounds", segment.p_offset)));
        };
        let Some(dest_bytes) = result.get_mut(mem_offset..mem_offset + len) else {
            continue;
        };
        dest_bytes.copy_from_slice(src_bytes);
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_build_firmware() {
        // Ensure that we can build the ELF and elf2rom can parse it
        build_firmware_rom("caliptra-drivers-test-bin", "test_success").unwrap();
    }

    #[test]
    fn test_elf2rom_golden() {
        let rom_bytes = elf2rom(include_bytes!("testdata/example.elf")).unwrap();
        assert_eq!(&rom_bytes, include_bytes!("testdata/example.rom.golden"));
    }
}

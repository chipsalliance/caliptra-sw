/*++

Licensed under the Apache-2.0 license.

File Name:

    test_builder.rs

Abstract:

    Code for compiling risc-v compliance tests from https://github.com/riscv-non-isa/riscv-arch-test.

--*/
use crate::exec::exec;
use crate::fs::{self, TempDir, TempFile};
use crate::{into_io_error, TestInfo};
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone)]

pub struct TestBuilderConfig {
    pub test_root_path: PathBuf,
    pub compiler_path: PathBuf,
    pub objcopy_path: PathBuf,
    pub linker_script_contents: &'static [u8],
    pub model_test_contents: &'static [u8],
}
pub struct TestBuilder {
    config: TestBuilderConfig,
    include_dir: TempDir,
    linker_script: TempFile,
}
impl TestBuilder {
    pub fn new(config: TestBuilderConfig) -> std::io::Result<Self> {
        let include_dir = TempDir::new()?;
        std::fs::write(
            include_dir.path().join("model_test.h"),
            config.model_test_contents,
        )?;

        let linker_script = TempFile::with_extension("ld")?;
        std::fs::write(&linker_script, config.linker_script_contents)?;

        Ok(Self {
            config,
            include_dir,
            linker_script,
        })
    }
    pub fn build_test_binary(&self, test: &TestInfo) -> std::io::Result<Vec<u8>> {
        let elf_file = TempFile::with_extension(".o")?;
        let bin_file = TempFile::with_extension(".bin")?;
        exec(
            Command::new(&self.config.compiler_path)
                .arg("-march=rv32i")
                .arg("-mabi=ilp32")
                .arg("-DXLEN=32")
                .arg("-static")
                .arg("-mcmodel=medany")
                .arg(if test.extension == "C" {
                    "-march=rv32imc"
                } else {
                    "-march=rv32im"
                })
                .arg("-mabi=ilp32")
                .arg("-fvisibility=hidden")
                .arg("-nostdlib")
                .arg("-nostartfiles")
                .arg("-I")
                .arg(self.config.test_root_path.join("riscv-test-suite/env/"))
                .arg("-I")
                .arg(self.include_dir.path())
                .arg("-T")
                .arg(self.linker_script.path())
                .arg(
                    self.config
                        .test_root_path
                        .join("riscv-test-suite/rv32i_m")
                        .join(test.extension)
                        .join("src")
                        .join(format!("{}.S", test.name)),
                )
                .arg("-o")
                .arg(elf_file.path()),
        )?;

        exec(
            Command::new(&self.config.objcopy_path)
                .arg("-O")
                .arg("binary")
                .arg(elf_file.path())
                .arg(bin_file.path()),
        )?;
        fs::read(&bin_file)
    }
    pub fn get_reference_data(&self, test: &TestInfo) -> std::io::Result<String> {
        String::from_utf8(fs::read(
            self.config
                .test_root_path
                .join("riscv-test-suite/rv32i_m")
                .join(test.extension)
                .join("references")
                .join(format!("{}.reference_output", test.name)),
        )?)
        .map_err(into_io_error)
    }
}

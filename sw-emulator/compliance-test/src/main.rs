/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    Test-runner for risc-v compliance tests from https://github.com/riscv-non-isa/riscv-arch-test.

--*/

use crate::test_builder::{TestBuilder, TestBuilderConfig};
use caliptra_emu_bus::{Bus, Clock, Ram};
use caliptra_emu_cpu::{Cpu, StepAction};
use caliptra_emu_types::RvSize;
use clap::{arg, value_parser};
use std::error::Error;
use std::io::ErrorKind;
use std::path::PathBuf;

mod exec;
mod fs;
mod test_builder;

pub struct TestInfo {
    extension: &'static str,
    name: &'static str,
}
#[rustfmt::skip]
static TESTS_TO_RUN: &[TestInfo] = &[
    TestInfo {extension: "I", name: "add-01"},
    TestInfo {extension: "I", name: "addi-01"},
    TestInfo {extension: "I", name: "and-01"},
    TestInfo {extension: "I", name: "andi-01"},
    TestInfo {extension: "I", name: "auipc-01"},
    TestInfo {extension: "I", name: "beq-01"},
    TestInfo {extension: "I", name: "bge-01"},
    TestInfo {extension: "I", name: "bgeu-01"},
    TestInfo {extension: "I", name: "blt-01"},
    TestInfo {extension: "I", name: "bltu-01"},
    TestInfo {extension: "I", name: "bne-01"},
    TestInfo {extension: "I", name: "fence-01"},
    TestInfo {extension: "I", name: "jal-01"},
    TestInfo {extension: "I", name: "jalr-01"},
    TestInfo {extension: "I", name: "lb-align-01"},
    TestInfo {extension: "I", name: "lbu-align-01"},
    TestInfo {extension: "I", name: "lh-align-01"},
    TestInfo {extension: "I", name: "lhu-align-01"},
    TestInfo {extension: "I", name: "lui-01"},
    TestInfo {extension: "I", name: "lw-align-01"},
    TestInfo {extension: "I", name: "or-01"},
    TestInfo {extension: "I", name: "ori-01"},
    TestInfo {extension: "I", name: "sb-align-01"},
    TestInfo {extension: "I", name: "sh-align-01"},
    TestInfo {extension: "I", name: "sll-01"},
    TestInfo {extension: "I", name: "slli-01"},
    TestInfo {extension: "I", name: "slt-01"},
    TestInfo {extension: "I", name: "slti-01"},
    TestInfo {extension: "I", name: "sltiu-01"},
    TestInfo {extension: "I", name: "sltu-01"},
    TestInfo {extension: "I", name: "sra-01"},
    TestInfo {extension: "I", name: "srai-01"},
    TestInfo {extension: "I", name: "srl-01"},
    TestInfo {extension: "I", name: "srli-01"},
    TestInfo {extension: "I", name: "sub-01"},
    TestInfo {extension: "I", name: "sw-align-01"},
    TestInfo {extension: "I", name: "xor-01"},
    TestInfo {extension: "I", name: "xori-01"},
    TestInfo {extension: "M", name: "div-01"},
    TestInfo {extension: "M", name: "divu-01"},
    TestInfo {extension: "M", name: "mul-01"},
    TestInfo {extension: "M", name: "mulh-01"},
    TestInfo {extension: "M", name: "mulhsu-01"},
    TestInfo {extension: "M", name: "mulhu-01"},
    TestInfo {extension: "M", name: "rem-01"},
    TestInfo {extension: "M", name: "remu-01"},
    TestInfo {extension: "C", name: "cadd-01"},
    TestInfo {extension: "C", name: "caddi-01"},
    TestInfo {extension: "C", name: "caddi16sp-01"},
    TestInfo {extension: "C", name: "caddi4spn-01"},
    TestInfo {extension: "C", name: "cand-01"},
    TestInfo {extension: "C", name: "candi-01"},
    TestInfo {extension: "C", name: "cbeqz-01"},
    TestInfo {extension: "C", name: "cbnez-01"},
    //TestInfo {extension: "C", name: "cebreak-01"},
    TestInfo {extension: "C", name: "cj-01"},
    TestInfo {extension: "C", name: "cjal-01"},
    TestInfo {extension: "C", name: "cjalr-01"},
    TestInfo {extension: "C", name: "cjr-01"},
    TestInfo {extension: "C", name: "cli-01"},
    TestInfo {extension: "C", name: "clui-01"},
    TestInfo {extension: "C", name: "clw-01"},
    TestInfo {extension: "C", name: "clwsp-01"},
    TestInfo {extension: "C", name: "cmv-01"},
    TestInfo {extension: "C", name: "cnop-01"},
    TestInfo {extension: "C", name: "cor-01"},
    TestInfo {extension: "C", name: "cslli-01"},
    TestInfo {extension: "C", name: "csrai-01"},
    TestInfo {extension: "C", name: "csrli-01"},
    TestInfo {extension: "C", name: "csub-01"},
    TestInfo {extension: "C", name: "csw-01"},
    TestInfo {extension: "C", name: "cswsp-01"},
    TestInfo {extension: "C", name: "cxor-01"},
];

fn into_io_error(err: impl Into<Box<dyn Error + Send + Sync>>) -> std::io::Error {
    std::io::Error::new(ErrorKind::Other, err)
}

fn check_reference_data(expected_txt: &str, bus: &mut impl Bus) -> std::io::Result<()> {
    let mut addr = 0x1000;
    for line in expected_txt.lines() {
        let expected_word = u32::from_str_radix(line, 16).map_err(into_io_error)?;
        let actual_word = match bus.read(RvSize::Word, addr) {
            Ok(val) => val,
            Err(err) => {
                return Err(into_io_error(format!(
                    "Error accessing memory for comparison with reference data: {:?}",
                    err
                )))
            }
        };
        if expected_word != actual_word {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                format!(
                    "At addr {:#x}, expected {:#010x} but was {:#010x}",
                    addr, expected_word, actual_word
                ),
            ));
        }
        addr += 4;
    }
    Ok(())
}

fn is_test_complete(bus: &mut impl Bus) -> bool {
    bus.read(RvSize::Word, 0x0).unwrap() != 0
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = clap::Command::new("compliance-test")
        .about("RISC-V compliance suite runner")
        .arg(arg!(--test_root_path <DIR> "Path to directory containing https://github.com/riscv-non-isa/riscv-arch-test").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--compiler <FILE> "Path to risc-v build of gcc").required(false).default_value("riscv64-unknown-elf-gcc").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--objcopy <FILE> "Path to risc-v build of objcopy").required(false).default_value("riscv64-unknown-elf-objcopy").value_parser(value_parser!(PathBuf)))
        .get_matches();

    let builder = TestBuilder::new(TestBuilderConfig {
        test_root_path: args.get_one::<PathBuf>("test_root_path").unwrap().clone(),
        compiler_path: args.get_one::<PathBuf>("compiler").unwrap().clone(),
        objcopy_path: args.get_one::<PathBuf>("objcopy").unwrap().clone(),
        linker_script_contents: include_bytes!("../target-files/link.ld"),
        model_test_contents: include_bytes!("../target-files/model_test.h"),
    })?;

    for test in TESTS_TO_RUN.iter() {
        println!("Running test {}/{}", test.extension, test.name);
        let binary: Vec<u8> = builder.build_test_binary(test)?;
        let reference_txt = builder.get_reference_data(test)?;

        let mut cpu = Cpu::new(Ram::new(binary), Clock::new());
        cpu.write_pc(0x3000);
        while !is_test_complete(&mut cpu.bus) {
            match cpu.step(None) {
                StepAction::Continue => continue,
                _ => break,
            }
        }
        if !is_test_complete(&mut cpu.bus) {
            return Err(std::io::Error::new(ErrorKind::Other, "test did not complete").into());
        }
        check_reference_data(&reference_txt, &mut cpu.bus)?;
        println!("PASSED");
        drop(cpu);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_reference_data() {
        let mut ram_bytes = vec![0u8; 4096];
        ram_bytes.extend(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let mut cpu = Cpu::new(Ram::new(ram_bytes), Clock::new());

        check_reference_data("03020100\n07060504\n", &mut cpu.bus).unwrap();
        assert_eq!(
            check_reference_data("03050100\n07060503\n", &mut cpu.bus)
                .err()
                .unwrap()
                .to_string(),
            "At addr 0x1000, expected 0x03050100 but was 0x03020100"
        );
        assert_eq!(
            check_reference_data("03020100\n07060502", &mut cpu.bus)
                .err()
                .unwrap()
                .to_string(),
            "At addr 0x1004, expected 0x07060502 but was 0x07060504"
        );
    }
}

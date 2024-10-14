// Licensed under the Apache-2.0 license

// These tests are here so that they are excluded in FPGA tests.

// These tests don't directly import the CFI code. If they fail,
// this likely indicates that the CFI laundering code may not
// be doing what we want, and we need to investigate.

#[cfg(test)]
mod test {

    const START: &str = "
#![no_std]

pub fn add(mut a: u32, mut b: u32) -> u32 {
    launder(a) + launder(a) + launder(b) + launder(b)
}
";

    const LAUNDER: &str = "
#[inline(always)]
fn launder(mut val: u32) -> u32 {
    // Safety: this is a no-op, since we don't modify the input.
    unsafe {
        core::arch::asm!(
            \"/* {t} */\",
            t = inout(reg) val,
        );
    }
    val
}";

    const NO_LAUNDER: &str = "
#[inline(always)]
fn launder(mut val: u32) -> u32 {
    val
}
";

    fn compile_to_riscv32_asm(src: String) -> String {
        let dir = std::env::temp_dir();
        let src_path = dir.join("asm.rs");
        let dst_path = dir.join("asm.s");

        std::fs::write(src_path.clone(), src).expect("could not write asm file");

        let p = std::process::Command::new("rustc")
            .args([
                "--crate-type=lib",
                "--target",
                "riscv32imc-unknown-none-elf",
                "-C",
                "opt-level=s",
                "--emit",
                "asm",
                src_path.to_str().expect("could not convert path"),
                "-o",
                dst_path.to_str().expect("could not convert path"),
            ])
            .output()
            .expect("failed to compile");
        assert!(p.status.success());
        std::fs::read_to_string(dst_path).expect("could not read asm file")
    }

    #[test]
    fn test_launder() {
        // With no laundering, LLVM can simplify the double add to a shift left.
        let src = format!("{}{}", START, NO_LAUNDER);
        let asm = compile_to_riscv32_asm(src);
        assert!(asm.contains("sll"));

        // With laundering, LLVM cannot simplify the double add and has to use the register twice.
        let src = format!("{}{}", START, LAUNDER);
        let asm = compile_to_riscv32_asm(src);
        assert!(!asm.contains("sll"));
    }
}

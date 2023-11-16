// Licensed under the Apache-2.0 license
use std::process::Command;

use caliptra_builder::run_cmd_stdout;

const OBJDUMP: &str = "riscv64-unknown-elf-objdump";

pub fn invoke_objdump(binary_path: &str) -> std::io::Result<String> {
    let mut cmd = Command::new(OBJDUMP);

    cmd.arg("-C").arg("-d").arg(binary_path);

    run_cmd_stdout(&mut cmd, None)
}

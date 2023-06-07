// Licensed under the Apache-2.0 license

use std::{
    io,
    process::{Command, Stdio},
};

pub fn run_cmd(cmd: &mut Command) -> io::Result<()> {
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Process {:?} {:?} exited with status code {:?}",
                cmd.get_program(),
                cmd.get_args(),
                status.code()
            ),
        ))
    }
}

pub fn run_cmd_stdout(cmd: &mut Command, input: Option<&[u8]>) -> io::Result<Vec<u8>> {
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());

    let mut child = cmd.spawn()?;
    if let (Some(mut stdin), Some(input)) = (child.stdin.take(), input) {
        std::io::Write::write_all(&mut stdin, input)?;
    }
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Process {:?} {:?} exited with status code {:?} stdout {} stderr {}",
                cmd.get_program(),
                cmd.get_args(),
                out.status.code(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        ))
    }
}

// Licensed under the Apache-2.0 license
//
// Derived from OpenTitan's opentitanlib with original copyright:
//
// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::openocd::printer;

/// Errors related to the OpenOCD server.
#[derive(Error, Debug, Deserialize, Serialize)]
pub enum OpenOcdError {
    #[error("OpenOCD initialization failed: {0}")]
    InitializeFailure(String),
    #[error("OpenOCD server exited prematurely")]
    PrematureExit,
    #[error("Generic error {0}")]
    Generic(String),
}

/// Represents an OpenOCD server that we can interact with.
pub struct OpenOcdServer {
    /// OpenOCD child process.
    server_process: Child,
    /// Receiving side of the stream to the telnet interface of OpenOCD.
    reader: BufReader<TcpStream>,
    /// Sending side of the stream to the telnet interface of OpenOCD.
    writer: TcpStream,
}

impl Drop for OpenOcdServer {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl OpenOcdServer {
    /// Duration to wait for OpenOCD to be ready to accept a Tcl connection.
    const OPENOCD_TCL_READY_TMO: Duration = Duration::from_secs(5);

    /// Wait until we see a particular message over STDERR.
    fn wait_until_regex_match<'a>(
        stderr: &mut impl BufRead,
        regex: &Regex,
        timeout: Duration,
        s: &'a mut String,
    ) -> Result<regex::Captures<'a>> {
        let start = Instant::now();
        loop {
            // NOTE this read could block indefinitely, but this behavior is desired for test simplicity.
            let n = stderr.read_line(s)?;
            if n == 0 {
                bail!("OpenOCD stopped before being ready?");
            }
            print!("OpenOCD::stderr: {}", s);
            if regex.is_match(s) {
                // This is not a `if let Some(capture) = regex.captures(s) {}` to to Rust
                // borrow checker limitations. Can be modified if Polonius lands.
                return Ok(regex.captures(s).unwrap());
            }
            s.clear();
            if start.elapsed() >= timeout {
                bail!("OpenOCD did not become ready to accept a Tcl connection");
            }
        }
    }

    /// Spawn an OpenOCD Tcl server with the given OpenOCD binary path.
    pub fn spawn(path: &Path, log_stdio: bool) -> Result<Self> {
        // Let OpenOCD choose which port to bind to, in order to never unnecesarily run into
        // issues due to a particular port already being in use.
        // We don't use the telnet and GDB ports so disable them.
        // The configuration will happen through the Tcl interface, so use `noinit` to prevent
        // OpenOCD from transition to execution mode.
        let mut cmd = Command::new(path);
        cmd.arg("-c")
            .arg("tcl_port 0; telnet_port disabled; gdb_port disabled; noinit;");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // SAFETY: prctl is a syscall which is atomic and thus async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                // Since we use OpenOCD as a library, make sure it's killed when
                // the parent process dies. This setting is preserved across execve.
                rustix::process::set_parent_process_death_signal(Some(
                    rustix::process::Signal::HUP,
                ))?;
                Ok(())
            });
        }

        if log_stdio {
            println!("Spawning OpenOCD with: {cmd:?}");
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn openocd: {cmd:?}",))?;
        let stdout = child.stdout.take().unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());

        // Wait until we see 'Info : Listening on port XYZ for Tcl connections' before knowing
        // which port to connect to.
        if log_stdio {
            println!("Waiting for OpenOCD to be ready to accept a Tcl connection ...");
        }
        static READY_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new("Info : Listening on port ([0-9]+) for tcl connections").unwrap()
        });
        let mut buf = String::new();
        let regex_captures = Self::wait_until_regex_match(
            &mut stderr,
            &READY_REGEX,
            Self::OPENOCD_TCL_READY_TMO,
            &mut buf,
        )
        .context("OpenOCD was not ready in time to accept a connection")?;
        let openocd_port: u16 = regex_captures.get(1).unwrap().as_str().parse()?;

        // Print stdout and stderr with log
        if log_stdio {
            std::thread::spawn(move || {
                printer::accumulate(stdout, "OpenOCD::stdout", Default::default())
            });
            std::thread::spawn(move || {
                printer::accumulate(stderr, "OpenOCD::stderr", Default::default())
            });
        }

        let kill_guard = scopeguard::guard(child, |mut child| {
            let _ = child.kill();
        });

        if log_stdio {
            println!("Connecting to OpenOCD Tcl interface ...");
        }
        let stream = TcpStream::connect(("localhost", openocd_port))
            .context("failed to connect to OpenOCD socket")?;
        let connection = Self {
            server_process: scopeguard::ScopeGuard::into_inner(kill_guard),
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
        };

        Ok(connection)
    }

    /// Send a string to the OpenOCD Tcl server.
    fn send(&mut self, cmd: &str) -> Result<()> {
        // The protocol is to send the command followed by a `0x1a` byte,
        // see https://openocd.org/doc/html/Tcl-Scripting-API.html#Tcl-RPC-server

        // Sanity check to ensure that the command string is not malformed.
        if cmd.contains('\x1A') {
            bail!("Tcl command string should be contained inside the string to send.");
        }
        self.writer
            .write_all(cmd.as_bytes())
            .context("failed to send a command to the OpenOCD server")?;
        self.writer
            .write_all(&[0x1a])
            .context("failed to send the command terminator to OpenOCD server")?;
        self.writer.flush().context("failed to flush stream")?;
        Ok(())
    }

    /// Receive a string from the OpenOCD Tcl server.
    fn recv(&mut self) -> Result<String> {
        let mut buf = Vec::new();
        self.reader.read_until(0x1A, &mut buf)?;
        if !buf.ends_with(b"\x1A") {
            bail!(OpenOcdError::PrematureExit);
        }
        buf.pop();
        String::from_utf8(buf).context("failed to parse OpenOCD response as UTF-8")
    }

    /// Execute a Tcl command via the OpenOCD and wait for its response.
    pub fn execute(&mut self, cmd: &str) -> Result<String> {
        self.send(cmd)?;
        self.recv()
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.execute("shutdown")?;
        self.server_process
            .wait()
            .context("failed to wait for OpenOCD server to exit")?;
        Ok(())
    }
}

#[cfg(feature = "fpga_subsystem")]
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_openocd_server() {
        let Ok(mut openocd) = OpenOcdServer::spawn(Path::new("openocd"), /*log_stdio=*/ true)
        else {
            panic!("Failed to spawn an openocd subprocess.");
        };
        let Ok(version) = openocd.execute("version") else {
            panic!("Failed to execute an openocd command.");
        };
        println!("OpenOCD version: {version}");
        assert!(openocd.shutdown().is_ok());
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    exec.rs

Abstract:

    Offers exec (subprocess) functionality similar to std::process but with better error
    messages that include paths, args, and stderr.

--*/

use crate::fs::annotate_error;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, ErrorKind, Write};

/// Executes a command (subprocess).
///
/// If it fails, the error has a very descriptive error message that includes
/// stderr from the command along with all the arguments to command.
pub fn exec(cmd: &mut std::process::Command) -> io::Result<()> {
    let output = cmd
        .stdout(std::process::Stdio::inherit())
        .output()
        .map_err(|err| {
            annotate_error(
                err,
                &format!("while running command {:?}", collect_args(cmd)),
            )
        })?;
    if output.status.success() {
        io::stderr().write_all(&output.stderr)?;
        Ok(())
    } else {
        Err(ExecError {
            code: output.status.code(),
            args: collect_args(cmd),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into_io_error())
    }
}

pub struct ExecError {
    /// The exit code of the subprocess. If the subprocess could not be started,
    /// this will be [`None`].
    code: Option<i32>,
    /// The arguments passed to the subprocess. `args[0]` will be the executable.
    args: Vec<OsString>,
    /// The captured stderr from the process, lossily converted to UTF-8.
    stderr: String,
}
impl ExecError {
    fn into_io_error(self) -> io::Error {
        io::Error::new(ErrorKind::Other, self)
    }
}
impl std::error::Error for ExecError {}
impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Subprocess exited with error {:?}: {:?}\n{}",
            self.code, self.args, self.stderr
        )
    }
}
impl fmt::Debug for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn collect_args(cmd: &std::process::Command) -> Vec<OsString> {
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(OsString::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::TempFile;

    #[cfg(target_family = "unix")]
    #[test]
    fn test_exec_success() {
        let temp_file = TempFile::new().unwrap();
        assert!(!temp_file.path().exists());
        exec(std::process::Command::new("touch").arg(temp_file.path())).unwrap();
        assert!(temp_file.path().exists());
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_exec_process_not_found() {
        let result = exec(&mut std::process::Command::new(
            "/tmp/pvoruxpa5dbnjv5sj5t15omn",
        ));
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(err
            .to_string()
            .contains("while running command [\"/tmp/pvoruxpa5dbnjv5sj5t15omn\"]"));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_exec_process_returned_nonzero() {
        let result = exec(std::process::Command::new("cat").arg("/tmp/pvoruxpa5dbnjv5sj5t15omn"));
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::Other);
        let err = err.into_inner().unwrap().downcast::<ExecError>().unwrap();
        assert_eq!(err.code, Some(1));
        assert_eq!(
            &err.stderr,
            "cat: /tmp/pvoruxpa5dbnjv5sj5t15omn: No such file or directory\n"
        );
        assert_eq!(
            err.args,
            vec![
                OsString::from("cat"),
                OsString::from("/tmp/pvoruxpa5dbnjv5sj5t15omn")
            ]
        );
        assert_eq!(
            format!("{}", err),
            "Subprocess exited with error Some(1): [\"cat\", \"/tmp/pvoruxpa5dbnjv5sj5t15omn\"]\n\
                   cat: /tmp/pvoruxpa5dbnjv5sj5t15omn: No such file or directory\n"
        );
    }
}

// Licensed under the Apache-2.0 license

use std::io;

pub fn expect_line(expected_val: &str, line: Option<&str>) -> io::Result<()> {
    if let Some(line) = line {
        if line == expected_val {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("Expected line with contents {expected_val:?}; was {line:?}"),
    ))
}

pub fn expect_line_with_prefix<'a>(prefix: &str, line: Option<&'a str>) -> io::Result<&'a str> {
    if let Some(line) = line {
        if let Some(stripped) = line.strip_prefix(prefix) {
            return Ok(stripped);
        }
    };
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("Expected line with prefix {prefix:?}; was {line:?}"),
    ))
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut result = String::new();
    for b in bytes {
        write!(&mut result, "{:02x}", b).unwrap();
    }
    result
}

pub fn bytes_to_string(vec: Vec<u8>) -> io::Result<String> {
    String::from_utf8(vec).map_err(other_err)
}

pub fn other_err(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

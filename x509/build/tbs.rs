/*++

Licensed under the Apache-2.0 license.

File Name:

    tbs.rs

Abstract:

    File contains definition of types used as templates and parameters.

--*/

use hex::ToHex;

/// Template parameter
#[derive(Debug, Copy, Clone)]
pub struct TbsParam {
    pub name: &'static str,
    pub offset: usize,
    pub len: usize,
}

impl TbsParam {
    /// Create an instance `TbsParam`
    pub fn new(name: &'static str, offset: usize, len: usize) -> Self {
        Self { name, offset, len }
    }
}

/// Template
pub struct TbsTemplate {
    buf: Vec<u8>,
    params: Vec<TbsParam>,
}

impl TbsTemplate {
    /// Create an instance of `TbsTemplate`
    pub fn new(template: Vec<u8>, params: Vec<TbsParam>) -> Self {
        Self {
            buf: template,
            params,
        }
    }

    /// Retrieve template blob
    pub fn tbs(&self) -> &[u8] {
        &self.buf
    }

    /// Retrieve template parameters
    pub fn params(&self) -> &[TbsParam] {
        &self.params
    }
}

/// Initialize template parameter with its offset
pub fn init_param(needle: &[u8], haystack: &[u8], param: TbsParam) -> TbsParam {
    assert_eq!(needle.len(), param.len);
    eprintln!("{}", param.name);
    // Throw an error if there are multiple instances of our "needle"
    // This could lead to incorrect offsets in the cert template
    if haystack.windows(param.len).filter(|w| *w == needle).count() > 1 {
        panic!(
            "Multiple instances of needle '{}' with value\n\n{}\n\nin haystack\n\n{}",
            param.name,
            needle.encode_hex::<String>(),
            haystack.encode_hex::<String>()
        );
    }
    let pos = haystack.windows(param.len).position(|w| w == needle);

    match pos {
        Some(offset) => TbsParam { offset, ..param },
        None => panic!(
            "Could not find needle '{}' with value\n\n{}\n\nin haystack\n\n{}",
            param.name,
            needle.encode_hex::<String>(),
            haystack.encode_hex::<String>()
        ),
    }
}

/// Sanitize the TBS buffer for the specified parameter
pub fn sanitize(param: TbsParam, buf: &mut [u8]) -> TbsParam {
    for byte in buf.iter_mut().skip(param.offset).take(param.len) {
        *byte = 0x5F;
    }
    param
}

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

    /// Find the PUBLIC_KEY param and return (offset, len)
    pub fn public_key_info(&self) -> Option<(usize, usize)> {
        self.params
            .iter()
            .find(|p| p.name == "PUBLIC_KEY")
            .map(|p| (p.offset, p.len))
    }

    /// Get the TBS bytes before the public key
    pub fn tbs_before_key(&self) -> Option<&[u8]> {
        self.public_key_info()
            .map(|(offset, _)| &self.buf[..offset])
    }

    /// Get the TBS bytes after the public key
    pub fn tbs_after_key(&self) -> Option<&[u8]> {
        self.public_key_info()
            .map(|(offset, len)| &self.buf[offset + len..])
    }
}

/// Initialize template parameter with its offset
pub fn init_param(needle: &[u8], haystack: &[u8], param: TbsParam) -> TbsParam {
    assert_eq!(needle.len(), param.len);
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

/// Retrieve the TBS from DER encoded vector
///
/// Note: Rust OpenSSL binding is missing the extensions to retrieve TBS portion of the X509
/// artifact
pub fn get_tbs(der: Vec<u8>) -> Vec<u8> {
    if der[0] != 0x30 {
        panic!("Invalid DER start tag");
    }

    let der_len_offset = 1;

    let tbs_offset = match der[der_len_offset] {
        0..=0x7F => der_len_offset + 1,
        0x81 => der_len_offset + 2,
        0x82 => der_len_offset + 3,
        _ => panic!("Unsupported DER Length"),
    };

    if der[tbs_offset] != 0x30 {
        panic!("Invalid TBS start tag");
    }

    let tbs_len_offset = tbs_offset + 1;
    let tbs_len = match der[tbs_len_offset] {
        0..=0x7F => der[tbs_len_offset] as usize + 2,
        0x81 => (der[tbs_len_offset + 1]) as usize + 3,
        0x82 => {
            usize::from(u16::from_be_bytes([
                der[tbs_len_offset + 1],
                der[tbs_len_offset + 2],
            ])) + 4
        }
        _ => panic!("Invalid DER Length"),
    };

    der[tbs_offset..tbs_offset + tbs_len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::get_tbs;

    #[test]
    fn test_get_tbs_two_byte_len_low_byte_carry() {
        // TBS content length 0x01FE (510 bytes) + 4-byte header = 514 bytes.
        // Without parenthesizing the low-byte addition, `(0x01 << 8) | (0xFE + 4)`
        // yielded `0x0102` (258) instead of `0x0202` (514).
        let tbs_content_len = 0x01FEusize;
        let mut tbs = vec![0x30, 0x82, 0x01, 0xFE];
        tbs.extend(vec![0xAA; tbs_content_len]);

        let sig_trailing = vec![0x03, 0x02, 0x00, 0xFF];
        let outer_content_len = tbs.len() + sig_trailing.len();
        let mut der = vec![
            0x30,
            0x82,
            (outer_content_len >> 8) as u8,
            (outer_content_len & 0xFF) as u8,
        ];
        der.extend_from_slice(&tbs);
        der.extend_from_slice(&sig_trailing);

        assert_eq!(get_tbs(der), tbs);
    }
}

// Licensed under the Apache-2.0 license

//! COSE (CBOR Object Signing and Encryption) functionality
//!
//! This module provides structures and encoding functions for COSE Sign1
//! as defined in RFC 8152.

use crate::cbor::{CborEncodable, CborEncoder};
use crate::error::EatError;

/// COSE header label constants (RFC 8152)
pub mod header_params {
    pub const ALG: i32 = 1;
    pub const CONTENT_TYPE: i32 = 3;
    pub const KID: i32 = 4;
    pub const X5CHAIN: i32 = 33; // X.509 Certificate Chain
}

/// COSE algorithm identifiers (IANA COSE Algorithms Registry)
pub mod cose_alg {
    pub const ESP384: i32 = -51; // ECDSA using P-384 curve and SHA-384
    pub const MLDSA87: i32 = -50; // CBOR Object Signing Algorithm for ML-DSA-87
}

/// Raw COSE signature sizes.
pub mod signature_size {
    pub const ESP384: usize = 96;
    pub const MLDSA87: usize = 4627;
}

/// Concrete COSE signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlgorithm {
    Esp384,
    Mldsa87,
}

impl CoseAlgorithm {
    pub const fn id(self) -> i32 {
        match self {
            Self::Esp384 => cose_alg::ESP384,
            Self::Mldsa87 => cose_alg::MLDSA87,
        }
    }

    pub const fn signature_size(self) -> usize {
        match self {
            Self::Esp384 => signature_size::ESP384,
            Self::Mldsa87 => signature_size::MLDSA87,
        }
    }

    pub fn protected_header(self) -> ProtectedHeader<'static> {
        match self {
            Self::Esp384 => ProtectedHeader::new_es384(),
            Self::Mldsa87 => ProtectedHeader::new_mldsa87(),
        }
    }
}

/// COSE content type constants
pub mod content_type {
    pub const APPLICATION_EAT_CWT: u16 = 263; // "application/eat+cwt"
    pub const APPLICATION_CE_CBOR: u16 = 10571; // "application/ce+cbor"
}

/// COSE header parameter as a key-value pair
#[derive(Debug, Clone, Copy)]
pub struct CoseHeaderPair<'a> {
    pub key: i32,
    pub value: &'a [u8],
}

/// COSE protected header structure
#[derive(Debug, Clone, Copy)]
pub struct ProtectedHeader<'a> {
    pub alg: i32,              // Algorithm identifier
    pub content_type: u16,     // Content type
    pub kid: Option<&'a [u8]>, // Key identifier
}

impl ProtectedHeader<'_> {
    /// Create a new protected header for ES384 (ECDSA with P-384 and SHA-384)
    /// with default content type APPLICATION_EAT_CWT and no key ID.
    pub fn new_es384() -> Self {
        Self {
            alg: cose_alg::ESP384,
            content_type: content_type::APPLICATION_EAT_CWT,
            kid: None,
        }
    }

    /// Create a new protected header for MLDSA87
    /// with default content type APPLICATION_EAT_CWT and no key ID.
    pub fn new_mldsa87() -> Self {
        Self {
            alg: cose_alg::MLDSA87,
            content_type: content_type::APPLICATION_EAT_CWT,
            kid: None,
        }
    }

    /// Estimate the size required for encoding this protected header
    pub fn estimate_size(&self) -> usize {
        let mut size = 0;

        // Map header (1-9 bytes, typically 1 byte for small maps)
        let mut entries = 2u64; // alg and content_type are mandatory
        if self.kid.is_some() {
            entries += 1;
        }
        size += CborEncoder::estimate_uint_size(entries);

        // Key 1 (alg): key + algorithm value size
        size += CborEncoder::estimate_int_size(header_params::ALG as i64); // Key label
        size += CborEncoder::estimate_int_size(self.alg as i64);

        // Key 3 (content_type): key + value size
        size += CborEncoder::estimate_int_size(header_params::CONTENT_TYPE as i64); // Key label
        size += CborEncoder::estimate_uint_size(self.content_type as u64);

        // Key 4 (kid): key + byte string (header + data)
        if let Some(kid) = self.kid {
            size += CborEncoder::estimate_int_size(header_params::KID as i64); // Key label
            size += CborEncoder::estimate_bytes_string_size(kid.len());
        }

        size
    }

    /// Encode the protected header into the provided buffer
    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EatError> {
        let mut encoder = CborEncoder::new(buffer);
        CborEncodable::encode(self, &mut encoder)?;
        Ok(encoder.len())
    }
}

impl CborEncodable for ProtectedHeader<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        // Calculate number of entries
        let mut entries = 2u64; // alg and content_type are mandatory
        if self.kid.is_some() {
            entries += 1;
        }

        encoder.encode_map_header(entries)?;

        // alg (label 1): algorithm identifier
        encoder.encode_int(header_params::ALG as i64)?;
        encoder.encode_int(self.alg as i64)?;

        // content_type (label 3): content type
        encoder.encode_int(header_params::CONTENT_TYPE as i64)?;
        encoder.encode_uint(self.content_type as u64)?;

        // kid (label 4): key identifier (optional)
        if let Some(kid) = self.kid {
            encoder.encode_int(header_params::KID as i64)?;
            encoder.encode_bytes(kid)?;
        }

        Ok(())
    }
}

/// COSE Sign1 encoder with builder pattern
pub struct CoseSign1<'a> {
    buffer: &'a mut [u8],
    protected_header: Option<&'a ProtectedHeader<'a>>,
    unprotected_headers: Option<&'a [CoseHeaderPair<'a>]>,
}

impl<'a> CoseSign1<'a> {
    const SIG_STRUCTURE_ARRAY_LEN: u64 = 4;
    const COSE_SIGN1_ARRAY_LEN: u64 = 4;
    const SIG_STRUCTURE_CONTEXT: &'static str = "Signature1";

    /// Create a new COSE Sign1 encoder with the given buffer
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            protected_header: None,
            unprotected_headers: None,
        }
    }

    fn encode_unprotected_header(
        encoder: &mut CborEncoder,
        headers: &[CoseHeaderPair],
    ) -> Result<(), EatError> {
        encoder.encode_map_header(headers.len() as u64)?;

        for header in headers {
            encoder.encode_int(header.key as i64)?;
            encoder.encode_bytes(header.value)?;
        }

        Ok(())
    }

    fn estimate_unprotected_header_size(headers: &[CoseHeaderPair]) -> usize {
        let mut size = CborEncoder::estimate_uint_size(headers.len() as u64);
        for header in headers {
            size += CborEncoder::estimate_int_size(header.key as i64);
            size += CborEncoder::estimate_bytes_string_size(header.value.len());
        }
        size
    }

    /// Set the protected header
    pub fn protected_header(mut self, header: &'a ProtectedHeader) -> Self {
        self.protected_header = Some(header);
        self
    }

    /// Set the unprotected headers
    pub fn unprotected_headers(mut self, headers: &'a [CoseHeaderPair<'a>]) -> Self {
        self.unprotected_headers = Some(headers);
        self
    }

    /// Encode the COSE_Sign1 structure with optional outer tags
    /// Always encodes tag 18 (COSE_Sign1). Additional outer tags can be provided.
    /// If additional_tags is Some, they are encoded before tag 18.
    pub fn encode<P, S, Sig>(
        self,
        additional_tags: Option<&[u64]>,
        encode_payload: P,
        sign: S,
    ) -> Result<usize, EatError>
    where
        P: FnOnce(&mut CborEncoder) -> Result<(), EatError>,
        S: FnOnce(&[u8]) -> Result<Sig, EatError>,
        Sig: AsRef<[u8]>,
    {
        let protected = self
            .protected_header
            .ok_or(EatError::MissingMandatoryClaim)?;
        let unprotected = self.unprotected_headers.unwrap_or(&[]);

        // Encode Sig_structure ["Signature1", bstr(protected), bstr(""), bstr(payload)]
        let (protected_src, protected_bstr_len, payload_src, sig_ctx_end) = {
            let mut encoder = CborEncoder::new(self.buffer);
            encoder.encode_array_header(Self::SIG_STRUCTURE_ARRAY_LEN)?;
            encoder.encode_text(Self::SIG_STRUCTURE_CONTEXT)?;
            let protected_src = encoder.len();
            encoder.encode_bytes_deferred(|enc| CborEncodable::encode(protected, enc))?;
            let protected_end = encoder.len();
            let protected_bstr_len = protected_end - protected_src;
            encoder.encode_bytes(&[])?;
            let payload_src = encoder.len();
            encoder.encode_bytes_deferred(encode_payload)?;
            let sig_ctx_end = encoder.len();
            (protected_src, protected_bstr_len, payload_src, sig_ctx_end)
        };
        let payload_bstr_len = sig_ctx_end - payload_src;

        // Sign the encoded Sig_structure
        let sig = sign(&self.buffer[..sig_ctx_end])?;

        // Calculate COSE_Sign1 layout offsets and shift bstr(protected) and bstr(payload) into place
        let mut cose_prefix_len = CborEncoder::estimate_uint_size(crate::cbor::tag::COSE_SIGN1)
            + CborEncoder::estimate_uint_size(Self::COSE_SIGN1_ARRAY_LEN);
        if let Some(tags) = additional_tags {
            for tag in tags {
                cose_prefix_len = cose_prefix_len
                    .checked_add(CborEncoder::estimate_uint_size(*tag))
                    .ok_or(EatError::BufferTooSmall)?;
            }
        }
        let unprotected_len = Self::estimate_unprotected_header_size(unprotected);
        let protected_dst = cose_prefix_len;
        let unprotected_dst = protected_dst
            .checked_add(protected_bstr_len)
            .ok_or(EatError::BufferTooSmall)?;
        let payload_dst = unprotected_dst
            .checked_add(unprotected_len)
            .ok_or(EatError::BufferTooSmall)?;
        let payload_dst_end = payload_dst
            .checked_add(payload_bstr_len)
            .ok_or(EatError::BufferTooSmall)?;
        if payload_dst_end > self.buffer.len() {
            return Err(EatError::BufferTooSmall);
        }

        if payload_dst >= payload_src {
            self.buffer
                .copy_within(payload_src..sig_ctx_end, payload_dst);
            self.buffer.copy_within(
                protected_src..protected_src + protected_bstr_len,
                protected_dst,
            );
        } else {
            self.buffer.copy_within(
                protected_src..protected_src + protected_bstr_len,
                protected_dst,
            );
            self.buffer
                .copy_within(payload_src..sig_ctx_end, payload_dst);
        }

        // Write COSE_Sign1 tags/array header, unprotected headers, and signature bstr
        {
            let mut prefix_enc = CborEncoder::new(&mut self.buffer[..cose_prefix_len]);
            if let Some(tags) = additional_tags {
                for tag in tags {
                    prefix_enc.encode_tag(*tag)?;
                }
            }
            prefix_enc.encode_cose_sign1_tag()?;
            prefix_enc.encode_array_header(Self::COSE_SIGN1_ARRAY_LEN)?;
        }
        {
            let mut unprot_enc = CborEncoder::new(&mut self.buffer[unprotected_dst..payload_dst]);
            Self::encode_unprotected_header(&mut unprot_enc, unprotected)?;
            if unprot_enc.len() != unprotected_len {
                return Err(EatError::EncodingError);
            }
        }
        let sig_bstr_len = {
            let mut sig_enc = CborEncoder::new(&mut self.buffer[payload_dst_end..]);
            sig_enc.encode_bytes(sig.as_ref())?;
            sig_enc.len()
        };

        Ok(payload_dst_end + sig_bstr_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_int_size_common_cose_algorithms() {
        // ESP384 (-51) should fit in 2 bytes
        assert_eq!(CborEncoder::estimate_int_size(cose_alg::ESP384 as i64), 2);
        // ES256 (-7) should fit in 1 byte
        assert_eq!(CborEncoder::estimate_int_size(-7), 1);
        // ES512 (-36) should fit in 2 bytes
        assert_eq!(CborEncoder::estimate_int_size(-36), 2);
    }

    #[test]
    fn test_protected_header_new_es384() {
        let algorithm = CoseAlgorithm::Esp384;
        let header = algorithm.protected_header();
        assert_eq!(header.alg, cose_alg::ESP384);
        assert_eq!(algorithm.id(), cose_alg::ESP384);
        assert_eq!(algorithm.signature_size(), 96);
        assert_eq!(header.content_type, content_type::APPLICATION_EAT_CWT);
        assert!(header.kid.is_none());
    }

    #[test]
    fn test_protected_header_new_mldsa87() {
        let algorithm = CoseAlgorithm::Mldsa87;
        let header = algorithm.protected_header();
        assert_eq!(header.alg, cose_alg::MLDSA87);
        assert_eq!(algorithm.id(), cose_alg::MLDSA87);
        assert_eq!(algorithm.signature_size(), 4627);
        assert_eq!(header.content_type, content_type::APPLICATION_EAT_CWT);
        assert!(header.kid.is_none());
    }

    #[test]
    fn test_protected_header_estimate_size_minimal() {
        let header = ProtectedHeader::new_es384();
        let estimated = header.estimate_size();

        // Map(2): 1 + Key(1): 1 + alg(-51): 2 + Key(3): 1 + content_type(263): 3 = 8 bytes
        assert_eq!(estimated, 8);
    }

    #[test]
    fn test_protected_header_estimate_size_with_custom_content_type() {
        let header = ProtectedHeader {
            alg: cose_alg::ESP384,
            content_type: 100,
            kid: None,
        };
        let estimated = header.estimate_size();

        // Map(2 entries): 1 + Key(1): 1 + alg(-51): 2 + Key(3): 1 + content_type(100): 2 = 7 bytes
        assert_eq!(estimated, 7);
    }

    #[test]
    fn test_protected_header_estimate_size_with_kid() {
        const KID: &[u8] = b"test-key-id";
        let header = ProtectedHeader {
            alg: cose_alg::ESP384,
            content_type: content_type::APPLICATION_EAT_CWT,
            kid: Some(KID),
        };
        let estimated = header.estimate_size();

        // Map(3 entries): 1 + Key(1): 1 + alg(-51): 2 + Key(3): 1 + content_type(263): 3 + Key(4): 1 + bstr header: 1 + kid data: 11 = 21 bytes
        assert_eq!(estimated, 21);
    }

    #[test]
    fn test_protected_header_encode_minimal() {
        let header = ProtectedHeader::new_es384();
        let mut buffer = [0u8; 64];

        let encoded_len = header.encode(&mut buffer).expect("Encoding failed");
        // Map(2 entries): 1 + Key(1): 1 + alg(-51): 2 + Key(3): 1 + content_type(263): 3 = 8 bytes
        assert_eq!(encoded_len, 8);
        assert_eq!(encoded_len, header.estimate_size());

        // Verify CBOR structure: map with 2 entries
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 2)
        );
    }

    #[test]
    fn test_protected_header_encode_with_all_fields() {
        const KID: &[u8] = b"key123";
        let header = ProtectedHeader {
            alg: cose_alg::ESP384,
            content_type: 500,
            kid: Some(KID),
        };
        let mut buffer = [0u8; 128];

        let encoded_len = header.encode(&mut buffer).expect("Encoding failed");
        // Map(3): 1 + Key(1): 1 + alg(-51): 2 + Key(3): 1 + content_type(500): 3 + Key(4): 1 + bstr header: 1 + kid: 6 = 16 bytes
        assert_eq!(encoded_len, 16);
        assert_eq!(encoded_len, header.estimate_size());

        // Verify CBOR structure: map with 3 entries
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 3)
        );
    }

    #[test]
    fn test_protected_header_encode_buffer_too_small() {
        let header = ProtectedHeader::new_es384();
        let mut buffer = [0u8; 2]; // Deliberately too small

        let result = header.encode(&mut buffer);
        assert_eq!(result, Err(EatError::BufferTooSmall));
    }

    #[test]
    fn test_cose_sign1_signature_context() {
        let protected = ProtectedHeader::new_es384();
        let signature = [0xAA; 96];

        let mut buffer = [0u8; 512];
        CoseSign1::new(&mut buffer)
            .protected_header(&protected)
            .encode(
                None,
                |enc| enc.encode_text("test payload"),
                |sig_ctx| {
                    // Array(4): 1 + "Signature1"(10 chars): 11 + protected(8 bytes): 9 + empty AAD: 1 + payload(1 + 13 bytes): 14 = 36 bytes
                    assert_eq!(sig_ctx.len(), 36);
                    assert_eq!(
                        sig_ctx[0],
                        crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Array, 4)
                    );
                    Ok(signature)
                },
            )
            .expect("Encoding failed");
    }

    #[test]
    fn test_cose_sign1_encode_complete() {
        let protected = ProtectedHeader::new_es384();
        let payload = b"test payload"; // 12 bytes (13 bytes as CBOR text string)
        let signature = [0xAA; 96]; // Mock P-384 signature (96 bytes)

        let x5chain_header = CoseHeaderPair {
            key: header_params::X5CHAIN,
            value: b"mock-cert", // Mock certificate data (9 bytes)
        };
        let unprotected = [x5chain_header];

        let mut buffer = [0u8; 1024];
        let encoded_len = CoseSign1::new(&mut buffer)
            .protected_header(&protected)
            .unprotected_headers(&unprotected)
            .encode(None, |enc| enc.encode_bytes(payload), |_| Ok(signature))
            .expect("Encoding failed");

        // Calculate expected size
        let tag18_size = 1; // COSE_Sign1 tag (18)
        let array_header_size = 1; // Array of 4 items
        let protected_size = CborEncoder::estimate_bytes_string_size(8); // protected header as byte string

        // Unprotected map: map_header(1) + key(33): 2 + value byte string(9 bytes): 10
        let unprotected_map_header = CborEncoder::estimate_uint_size(1); // 1 entry
        let unprotected_key = CborEncoder::estimate_int_size(header_params::X5CHAIN as i64); // key 33
        let unprotected_value = CborEncoder::estimate_bytes_string_size(b"mock-cert".len()); // 9 byte string
        let unprotected_size = unprotected_map_header + unprotected_key + unprotected_value;

        let inner_payload_size = CborEncoder::estimate_bytes_string_size(payload.len());
        let payload_size = CborEncoder::estimate_bytes_string_size(inner_payload_size);
        let signature_size = CborEncoder::estimate_bytes_string_size(signature.len()); // 96 byte string

        let expected_size = tag18_size
            + array_header_size
            + protected_size
            + unprotected_size
            + payload_size
            + signature_size;
        assert_eq!(encoded_len, expected_size);

        // Verify COSE_Sign1 tag (18)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Tag, 18)
        );
        // Verify array of 4 items
        assert_eq!(
            buffer[1],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Array, 4)
        );
    }

    #[test]
    fn test_cose_sign1_encode_with_additional_tags() {
        let protected = ProtectedHeader::new_es384();
        let payload = b"test";
        let signature = [0xBB; 96];

        let mut buffer = [0u8; 1024];
        let additional_tags = [55799u64, 61u64]; // Self-described CBOR + CWT
        let encoded_len = CoseSign1::new(&mut buffer)
            .protected_header(&protected)
            .encode(
                Some(&additional_tags),
                |enc| enc.encode_bytes(payload),
                |_| Ok(signature),
            )
            .expect("Encoding failed");

        // Calculate expected size
        let tag_55799_size = CborEncoder::estimate_uint_size(55799); // Self-described CBOR tag
        let tag_61_size = CborEncoder::estimate_uint_size(61); // CWT tag
        let tag18_size = 1; // COSE_Sign1 tag (18)
        let array_header_size = 1; // Array of 4 items
        let protected_size = CborEncoder::estimate_bytes_string_size(8); // protected header as byte string
        let unprotected_size = CborEncoder::estimate_uint_size(0); // Empty map (0 entries)
        let inner_payload_size = CborEncoder::estimate_bytes_string_size(payload.len());
        let payload_size = CborEncoder::estimate_bytes_string_size(inner_payload_size);
        let signature_size = CborEncoder::estimate_bytes_string_size(signature.len()); // 96 byte string

        let expected_size = tag_55799_size
            + tag_61_size
            + tag18_size
            + array_header_size
            + protected_size
            + unprotected_size
            + payload_size
            + signature_size;
        assert_eq!(encoded_len, expected_size);

        // Tag 55799 encodes as: major type 6, additional info 25 (2-byte uint16), value 0xD9F7
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Tag, 25)
        );
        assert_eq!(buffer[1], 0xD9);
        assert_eq!(buffer[2], 0xF7);
    }
}

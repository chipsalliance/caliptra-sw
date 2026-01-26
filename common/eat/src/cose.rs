// Licensed under the Apache-2.0 license

//! COSE (CBOR Object Signing and Encryption) functionality
//!
//! This module provides structures and encoding functions for COSE Sign1
//! as defined in RFC 8152.

use crate::cbor::CborEncoder;
use crate::error::EatError;
use arrayvec::ArrayVec;

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
        // Estimate and validate buffer size
        let estimated_size = self.estimate_size();
        if buffer.len() < estimated_size {
            return Err(EatError::BufferTooSmall);
        }

        let mut encoder = CborEncoder::new(buffer);

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

        Ok(encoder.len())
    }
}

/// Default maximum size for the encoded protected header.
/// The current protected header uses at most the `alg`, `content_type`, and `kid` fields.
pub const DEFAULT_PROTECTED_HEADER_SIZE: usize = 256;

/// COSE Sign1 encoder with builder pattern and configurable protected header buffer
pub struct CoseSign1WithBuffer<'a, const PROTECTED_SIZE: usize> {
    encoder: CborEncoder<'a>,
    protected_header: Option<&'a ProtectedHeader<'a>>,
    unprotected_headers: Option<&'a [CoseHeaderPair<'a>]>,
    payload: Option<&'a [u8]>,
    signature: Option<&'a [u8]>,
}

/// Default COSE Sign1 encoder using [`DEFAULT_PROTECTED_HEADER_SIZE`].
pub type CoseSign1<'a> = CoseSign1WithBuffer<'a, DEFAULT_PROTECTED_HEADER_SIZE>;

impl<'a, const PROTECTED_SIZE: usize> CoseSign1WithBuffer<'a, PROTECTED_SIZE> {
    /// Create a new COSE Sign1 encoder with the given buffer
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            encoder: CborEncoder::new(buffer),
            protected_header: None,
            unprotected_headers: None,
            payload: None,
            signature: None,
        }
    }

    /// Create COSE Sign1 signature context (as per RFC 8152)
    ///
    /// Creates the Sig_structure for COSE_Sign1 as defined in RFC 8152 Section 4.4:
    /// ```text
    /// Sig_structure = [
    ///    "Signature1",   // Context string for COSE_Sign1
    ///    protected,      // Protected header (serialized)
    ///    external_aad,   // Empty for basic use
    ///    payload         // The payload to be signed
    /// ]
    /// ```
    ///
    /// For most algorithms, this data should be hashed before signing.
    pub fn get_signature_context(&self, context_buffer: &mut [u8]) -> Result<usize, EatError> {
        // Encode protected header to temporary buffer
        let protected_buffer = self.encode_protected_header_to_buffer()?;
        let payload = self.payload.ok_or(EatError::MissingMandatoryClaim)?;

        // Create signature context
        let mut encoder = CborEncoder::new(context_buffer);

        // CBOR encode the Sig_structure array
        encoder.encode_array_header(4)?; // Array of 4 items

        // "Signature1" as text string
        encoder.encode_text("Signature1")?;

        // Protected header as byte string
        encoder.encode_bytes(&protected_buffer)?;

        // External AAD as empty byte string
        encoder.encode_bytes(&[])?;

        // Payload as byte string
        encoder.encode_bytes(payload)?;

        Ok(encoder.len())
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

    /// Encode the protected header into an ArrayVec buffer
    fn encode_protected_header_to_buffer(&self) -> Result<ArrayVec<u8, PROTECTED_SIZE>, EatError> {
        let mut protected_buffer = ArrayVec::new();
        let protected = self
            .protected_header
            .ok_or(EatError::MissingMandatoryClaim)?;

        // Encode into a temporary array, then copy to ArrayVec
        let mut temp_buffer = [0u8; PROTECTED_SIZE];
        let len = protected.encode(&mut temp_buffer)?;
        protected_buffer
            .try_extend_from_slice(&temp_buffer[..len])
            .map_err(|_| EatError::BufferTooSmall)?;

        Ok(protected_buffer)
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

    /// Set the payload
    pub fn payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the signature
    pub fn signature(mut self, signature: &'a [u8]) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Encode the COSE_Sign1 structure with optional outer tags
    /// Always encodes tag 18 (COSE_Sign1). Additional outer tags can be provided.
    /// If additional_tags is Some, they are encoded before tag 18.
    pub fn encode(mut self, additional_tags: Option<&[u64]>) -> Result<usize, EatError> {
        // Encode additional tags first if provided
        if let Some(tags) = additional_tags {
            for tag in tags {
                self.encoder.encode_tag(*tag)?;
            }
        }

        // Always encode COSE_Sign1 tag (18)
        self.encoder.encode_cose_sign1_tag()?;

        // Then encode the COSE_Sign1 array
        self.encoder.encode_array_header(4)?;

        // Encode protected header to temporary buffer
        let protected_buffer = self.encode_protected_header_to_buffer()?;
        self.encoder.encode_bytes(&protected_buffer)?;

        // Unprotected header as map
        let unprotected = self.unprotected_headers.unwrap_or(&[]);
        Self::encode_unprotected_header(&mut self.encoder, unprotected)?;

        // Payload as byte string
        let payload = self.payload.ok_or(EatError::MissingMandatoryClaim)?;
        self.encoder.encode_bytes(payload)?;

        // Signature as byte string
        let signature = self.signature.ok_or(EatError::MissingMandatoryClaim)?;
        self.encoder.encode_bytes(signature)?;

        Ok(self.encoder.len())
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
        let header = ProtectedHeader::new_es384();
        assert_eq!(header.alg, cose_alg::ESP384);
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
        let payload = b"test payload";

        let mut buffer = [0u8; 512];
        let cose = CoseSign1::new(&mut buffer)
            .protected_header(&protected)
            .payload(payload);

        let mut context_buffer = [0u8; 1024];
        let context_len = cose
            .get_signature_context(&mut context_buffer)
            .expect("Failed to get signature context");

        // Array(4): 1 + "Signature1"(10 chars): 11 + protected(8 bytes): 9 + empty AAD: 1 + payload(12 bytes): 13 = 35 bytes
        assert_eq!(context_len, 35);

        // Verify structure starts with array of 4 items
        assert_eq!(
            context_buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Array, 4)
        );
    }

    #[test]
    fn test_cose_sign1_encode_complete() {
        let protected = ProtectedHeader::new_es384();
        let payload = b"test payload"; // 12 bytes
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
            .payload(payload)
            .signature(&signature)
            .encode(None)
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

        let payload_size = CborEncoder::estimate_bytes_string_size(payload.len()); // 12 byte string
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
            .payload(payload)
            .signature(&signature)
            .encode(Some(&additional_tags))
            .expect("Encoding failed");

        // Calculate expected size
        let tag_55799_size = CborEncoder::estimate_uint_size(55799); // Self-described CBOR tag
        let tag_61_size = CborEncoder::estimate_uint_size(61); // CWT tag
        let tag18_size = 1; // COSE_Sign1 tag (18)
        let array_header_size = 1; // Array of 4 items
        let protected_size = CborEncoder::estimate_bytes_string_size(8); // protected header as byte string
        let unprotected_size = CborEncoder::estimate_uint_size(0); // Empty map (0 entries)
        let payload_size = CborEncoder::estimate_bytes_string_size(payload.len()); // 4 byte string
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

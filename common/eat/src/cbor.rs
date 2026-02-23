// Licensed under the Apache-2.0 license

//! Generic CBOR encoding functionality
//!
//! This module provides a no_std compatible CBOR encoder with a fixed buffer.
//! It implements the core CBOR data types according to RFC 8949.

use crate::error::EatError;

/// CBOR major types (RFC 8949)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MajorType {
    UnsignedInt = 0,
    NegativeInt = 1,
    ByteString = 2,
    TextString = 3,
    Array = 4,
    Map = 5,
    Tag = 6,
    Simple = 7,
}

impl From<MajorType> for u8 {
    fn from(val: MajorType) -> Self {
        val as u8
    }
}

/// CBOR tag values (RFC 8949)
pub mod tag {
    pub const COSE_SIGN1: u64 = 18;
    pub const CWT: u64 = 61;
    pub const SELF_DESCRIBED_CBOR: u64 = 55799;
    pub const OID: u64 = 111;
    pub const UUID: u64 = 37;
}

/// Construct a CBOR initial byte from major type and additional info
#[inline]
pub const fn cbor_initial_byte(major_type: MajorType, additional_info: u8) -> u8 {
    ((major_type as u8) << 5) | additional_info
}

/// Trait for types that can be encoded to CBOR format
pub trait CborEncodable {
    /// Encode this value into the provided CBOR encoder
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError>;
}

// Allow references to types that are already CborEncodable
impl<T: CborEncodable + ?Sized> CborEncodable for &T {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        (*self).encode(encoder)
    }
}

// Optional: allow mutable references too
impl<T: CborEncodable + ?Sized> CborEncodable for &mut T {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        (**self).encode(encoder)
    }
}

// CBOR encoder with fixed buffer
pub struct CborEncoder<'a> {
    buffer: &'a mut [u8],
    pos: usize,
}

impl<'a> CborEncoder<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    fn write_byte(&mut self, byte: u8) -> Result<(), EatError> {
        if let Some(buf_byte) = self.buffer.get_mut(self.pos) {
            *buf_byte = byte;
            self.pos = self.pos.checked_add(1).ok_or(EatError::BufferTooSmall)?;
            Ok(())
        } else {
            Err(EatError::BufferTooSmall)
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EatError> {
        let end_pos = self
            .pos
            .checked_add(bytes.len())
            .ok_or(EatError::BufferTooSmall)?;
        if end_pos > self.buffer.len() {
            return Err(EatError::BufferTooSmall);
        }
        if let Some(buf_slice) = self.buffer.get_mut(self.pos..end_pos) {
            buf_slice.copy_from_slice(bytes);
            self.pos = end_pos;
            Ok(())
        } else {
            Err(EatError::BufferTooSmall)
        }
    }

    // Encode major type + additional info according to CBOR rules
    fn encode_type_value(&mut self, major_type: MajorType, value: u64) -> Result<(), EatError> {
        let major: u8 = major_type.into();
        let major = major << 5;

        if value <= 23 {
            self.write_byte(major | value as u8)?;
        } else if value <= 0xff {
            self.write_byte(major | 24)?;
            self.write_byte(value as u8)?;
        } else if value <= 0xffff {
            self.write_byte(major | 25)?;
            let bytes = (value as u16).to_be_bytes();
            self.write_bytes(&bytes)?;
        } else if value <= 0xffffffff {
            self.write_byte(major | 26)?;
            let bytes = (value as u32).to_be_bytes();
            self.write_bytes(&bytes)?;
        } else {
            self.write_byte(major | 27)?;
            let bytes = value.to_be_bytes();
            self.write_bytes(&bytes)?;
        }
        Ok(())
    }

    // Major type 0: Unsigned integer
    pub fn encode_uint(&mut self, value: u64) -> Result<(), EatError> {
        self.encode_type_value(MajorType::UnsignedInt, value)
    }

    // Major type 1: Negative integer (-1 - n)
    pub fn encode_nint(&mut self, value: i64) -> Result<(), EatError> {
        if value >= 0 {
            return Err(EatError::InvalidData);
        }
        // Safe arithmetic: for negative value, -1 - value is always positive
        let positive_value = (value.checked_mul(-1).ok_or(EatError::InvalidData)?)
            .checked_sub(1)
            .ok_or(EatError::InvalidData)? as u64;
        self.encode_type_value(MajorType::NegativeInt, positive_value)
    }

    // Encode integer (automatically choose positive or negative)
    pub fn encode_int(&mut self, value: i64) -> Result<(), EatError> {
        if value >= 0 {
            self.encode_uint(value as u64)
        } else {
            self.encode_nint(value)
        }
    }

    // Major type 2: Byte string
    pub fn encode_bytes(&mut self, bytes: &[u8]) -> Result<(), EatError> {
        self.encode_type_value(MajorType::ByteString, bytes.len() as u64)?;
        self.write_bytes(bytes)?;
        Ok(())
    }

    // Major type 3: Text string
    pub fn encode_text(&mut self, text: &str) -> Result<(), EatError> {
        let bytes = text.as_bytes();
        self.encode_type_value(MajorType::TextString, bytes.len() as u64)?;
        self.write_bytes(bytes)?;
        Ok(())
    }

    // Major type 4: Array
    pub fn encode_array_header(&mut self, len: u64) -> Result<(), EatError> {
        self.encode_type_value(MajorType::Array, len)
    }

    // Major type 5: Map
    pub fn encode_map_header(&mut self, len: u64) -> Result<(), EatError> {
        self.encode_type_value(MajorType::Map, len)
    }

    // Major type 6: Tag
    pub fn encode_tag(&mut self, tag: u64) -> Result<(), EatError> {
        self.encode_type_value(MajorType::Tag, tag)
    }

    // Major type 7: Simple value (boolean)
    pub fn encode_bool(&mut self, value: bool) -> Result<(), EatError> {
        let value = if value { 21 } else { 20 };
        self.encode_type_value(MajorType::Simple, value)
    }

    // Encode with self-described CBOR tag (55799)
    pub fn encode_self_described_cbor(&mut self) -> Result<(), EatError> {
        self.encode_tag(tag::SELF_DESCRIBED_CBOR)
    }

    // Encode with CWT tag (61)
    pub fn encode_cwt_tag(&mut self) -> Result<(), EatError> {
        self.encode_tag(tag::CWT)
    }

    // Encode with COSE_Sign1 tag (18)
    pub fn encode_cose_sign1_tag(&mut self) -> Result<(), EatError> {
        self.encode_tag(tag::COSE_SIGN1)
    }

    // Helper function to estimate size based on value (mirrors encode_type_value logic)
    #[inline]
    fn estimate_type_value_size(value: u64) -> usize {
        if value <= 23 {
            1 // Major type + value in same byte
        } else if value <= 0xff {
            2 // Major type + 1 byte
        } else if value <= 0xffff {
            3 // Major type + 2 bytes
        } else if value <= 0xffffffff {
            5 // Major type + 4 bytes
        } else {
            9 // Major type + 8 bytes
        }
    }

    /// Estimate the encoded size of a CBOR unsigned integer
    ///
    /// This utility function calculates how many bytes will be needed to encode
    /// an unsigned integer value according to CBOR encoding rules (RFC 8949).
    ///
    /// CBOR encoding sizes:
    /// - 0 to 23: 1 byte (major type + value in lower 5 bits)
    /// - 24 to 255: 2 bytes (major type + 1 byte value)
    /// - 256 to 65535: 3 bytes (major type + 2 byte value)
    /// - 65536 to 4294967295: 5 bytes (major type + 4 byte value)
    /// - Beyond u32: 9 bytes (major type + 8 byte value)
    ///
    /// This mirrors the logic in `encode_type_value` but returns the size
    /// instead of encoding.
    #[inline]
    pub fn estimate_uint_size(value: u64) -> usize {
        Self::estimate_type_value_size(value)
    }

    /// Estimate the encoded size of a CBOR integer (positive or negative)
    ///
    /// This utility function calculates how many bytes will be needed to encode
    /// an integer value according to CBOR encoding rules (RFC 8949).
    ///
    /// CBOR encoding sizes:
    /// - -24 to 23: 1 byte (major type + value in lower 5 bits)
    /// - -256 to -25 or 24 to 255: 2 bytes (major type + 1 byte value)
    /// - -65536 to -257 or 256 to 65535: 3 bytes (major type + 2 byte value)
    /// - i32 range: 5 bytes (major type + 4 byte value)
    /// - Beyond i32: 9 bytes (major type + 8 byte value)
    ///
    /// This mirrors the logic in `encode_int` but returns the size
    /// instead of encoding.
    #[inline]
    pub fn estimate_int_size(value: i64) -> usize {
        // Convert negative values to their CBOR representation
        let abs_value = if value >= 0 {
            value as u64
        } else {
            // For negative integers, CBOR encodes as (-1 - value)
            // Safe because value is negative
            (value.saturating_mul(-1).saturating_sub(1)) as u64
        };

        Self::estimate_type_value_size(abs_value)
    }

    /// Estimate the encoded size of a CBOR byte string (major type 2)
    ///
    /// This utility function calculates the total bytes needed to encode
    /// a byte string: the header (major type + length) plus the actual bytes.
    ///
    /// Returns: header_size + data_length
    #[inline]
    pub fn estimate_bytes_string_size(data_len: usize) -> usize {
        Self::estimate_uint_size(data_len as u64) + data_len
    }

    /// Estimate the encoded size of a CBOR text string (major type 3)
    ///
    /// This utility function calculates the total bytes needed to encode
    /// a text string: the header (major type + length) plus the actual bytes.
    ///
    /// Returns: header_size + data_length
    #[inline]
    pub fn estimate_text_string_size(text_len: usize) -> usize {
        Self::estimate_uint_size(text_len as u64) + text_len
    }
}

/// CBOR-tagged OID (Object Identifier)
///
/// Encodes Object Identifiers using CBOR tag 111 as specified in RFC 8949.
/// The OID value must be in X.690 BER encoding (content octets only, without the
/// UNIVERSAL TAG 6 prefix or length byte).
///
/// # CBOR Encoding
///
/// The structure is encoded as:
/// - Tag 111 (CBOR tag for OID)
/// - Byte string containing the X.690 BER encoded OID value
///
/// # Example
///
/// For an OID like {1 3 6 1 4 1 42623 1 2 1}:
/// ```text
/// BER:  06 0B 2B 06 01 04 01 82 CD 1F 01 02 01
/// CBOR: D8 6F 4B 2B 06 01 04 01 82 CD 1F 01 02 01
///       └───┘ └┘ └──────────────────────────────┘
///       tag   len    OID value (X.690)
///       111   11
/// ```
/// The `oid` field contains: `[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x01]`
///
/// # Usage
///
/// ```
/// use ocp_eat::TaggedOid;
///
/// let oid_bytes = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x01];
/// let tagged_oid = TaggedOid::new(oid_bytes);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TaggedOid<'a> {
    /// OID value in X.690 BER encoding (content octets only)
    pub oid: &'a [u8],
}

impl<'a> TaggedOid<'a> {
    /// Create a new tagged OID
    ///
    /// # Arguments
    /// * `oid` - OID value encoded using X.690 BER (content octets, no tag/length)
    pub const fn new(oid: &'a [u8]) -> Self {
        Self { oid }
    }
}

impl CborEncodable for TaggedOid<'_> {
    /// Encode the tagged OID to CBOR
    ///
    /// Produces: tag(111) followed by byte string containing the X.690 encoded OID value
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        // Tag 111 for OID (RFC 8949 Section 3.4.5.3)
        encoder.encode_tag(tag::OID)?;
        encoder.encode_bytes(self.oid)?;
        Ok(())
    }
}

/// CBOR-tagged UUID (Universally Unique Identifier)
///
/// Encodes UUIDs using CBOR tag 37 as specified in RFC 9562.
/// The UUID value must be exactly 16 bytes in binary format.
///
/// # CBOR Encoding
///
/// The structure is encoded as:
/// - Tag 37 (CBOR tag for UUID)
/// - Byte string containing the 16-byte UUID value
///
/// # Example
///
/// For a UUID like `550e8400-e29b-41d4-a716-446655440000`:
/// ```text
/// Binary: 550e8400 e29b 41d4 a716 446655440000
/// CBOR:   D8 25 50 550e8400e29b41d4a716446655440000
///         └──┘ └┘ └──────────────────────────────┘
///         tag  len    16-byte UUID
///         37   16
/// ```
///
/// # Usage
///
/// ```
/// use ocp_eat::TaggedUuid;
///
/// let uuid_bytes = [
///     0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
///     0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
/// ];
/// let tagged_uuid = TaggedUuid::new(&uuid_bytes);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TaggedUuid<'a> {
    /// UUID value (exactly 16 bytes)
    pub uuid: &'a [u8],
}

impl<'a> TaggedUuid<'a> {
    /// Create a new tagged UUID
    ///
    /// # Arguments
    /// * `uuid` - 16-byte UUID value in binary format
    ///
    pub const fn new(uuid: &'a [u8; 16]) -> Self {
        Self { uuid }
    }
}

impl CborEncodable for TaggedUuid<'_> {
    /// Encode the tagged UUID to CBOR
    ///
    /// Produces: tag(37) followed by byte string containing the 16-byte UUID value
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        // Tag 37 for UUID (RFC 9562 Section 4)
        encoder.encode_tag(tag::UUID)?;
        encoder.encode_bytes(self.uuid)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_int_size_single_byte() {
        // Test range -24 to 23 (fits in 1 byte)
        assert_eq!(CborEncoder::estimate_int_size(-24), 1);
        assert_eq!(CborEncoder::estimate_int_size(-1), 1);
        assert_eq!(CborEncoder::estimate_int_size(0), 1);
        assert_eq!(CborEncoder::estimate_int_size(23), 1);
    }

    #[test]
    fn test_estimate_int_size_two_bytes() {
        // Test range -256 to -25 and 24 to 255 (fits in 2 bytes)
        assert_eq!(CborEncoder::estimate_int_size(-256), 2);
        assert_eq!(CborEncoder::estimate_int_size(-25), 2);
        assert_eq!(CborEncoder::estimate_int_size(24), 2);
        assert_eq!(CborEncoder::estimate_int_size(255), 2);
    }

    #[test]
    fn test_estimate_int_size_three_bytes() {
        // Test range -65536 to -257 and 256 to 65535 (fits in 3 bytes)
        assert_eq!(CborEncoder::estimate_int_size(-65536), 3);
        assert_eq!(CborEncoder::estimate_int_size(-257), 3);
        assert_eq!(CborEncoder::estimate_int_size(256), 3);
        assert_eq!(CborEncoder::estimate_int_size(65535), 3);
    }

    #[test]
    fn test_estimate_int_size_five_bytes() {
        // Test i32 range (fits in 5 bytes)
        assert_eq!(CborEncoder::estimate_int_size(-2147483648), 5);
        assert_eq!(CborEncoder::estimate_int_size(-65537), 5);
        assert_eq!(CborEncoder::estimate_int_size(65536), 5);
        assert_eq!(CborEncoder::estimate_int_size(2147483647), 5);
    }

    #[test]
    fn test_estimate_int_size_nine_bytes() {
        // Test values beyond u32 range (require 9 bytes)
        // For negative: need -1 - value > u32::MAX, so value < -4294967296
        assert_eq!(CborEncoder::estimate_int_size(-4294967297), 9);
        assert_eq!(CborEncoder::estimate_int_size(4294967296), 9);
        assert_eq!(CborEncoder::estimate_int_size(i64::MAX), 9);
        assert_eq!(CborEncoder::estimate_int_size(i64::MIN), 9);
    }

    #[test]
    fn test_estimate_uint_size_single_byte() {
        // Test range 0 to 23 (fits in 1 byte)
        assert_eq!(CborEncoder::estimate_uint_size(0), 1);
        assert_eq!(CborEncoder::estimate_uint_size(1), 1);
        assert_eq!(CborEncoder::estimate_uint_size(23), 1);
    }

    #[test]
    fn test_estimate_uint_size_two_bytes() {
        // Test range 24 to 255 (fits in 2 bytes)
        assert_eq!(CborEncoder::estimate_uint_size(24), 2);
        assert_eq!(CborEncoder::estimate_uint_size(100), 2);
        assert_eq!(CborEncoder::estimate_uint_size(255), 2);
    }

    #[test]
    fn test_estimate_uint_size_three_bytes() {
        // Test range 256 to 65535 (fits in 3 bytes)
        assert_eq!(CborEncoder::estimate_uint_size(256), 3);
        assert_eq!(CborEncoder::estimate_uint_size(500), 3);
        assert_eq!(CborEncoder::estimate_uint_size(65535), 3);
    }

    #[test]
    fn test_estimate_uint_size_five_bytes() {
        // Test u32 range (fits in 5 bytes)
        assert_eq!(CborEncoder::estimate_uint_size(65536), 5);
        assert_eq!(CborEncoder::estimate_uint_size(1000000), 5);
        assert_eq!(CborEncoder::estimate_uint_size(4294967295), 5);
    }

    #[test]
    fn test_estimate_uint_size_nine_bytes() {
        // Test values beyond u32 range (require 9 bytes)
        assert_eq!(CborEncoder::estimate_uint_size(4294967296), 9);
        assert_eq!(CborEncoder::estimate_uint_size(u64::MAX), 9);
    }

    #[test]
    fn test_estimate_uint_size_common_content_types() {
        // Common COSE content type values
        assert_eq!(CborEncoder::estimate_uint_size(0), 1); // content type 0
        assert_eq!(CborEncoder::estimate_uint_size(50), 2); // content type 50
        assert_eq!(CborEncoder::estimate_uint_size(100), 2); // content type 100
        assert_eq!(CborEncoder::estimate_uint_size(500), 3); // content type 500
    }

    #[test]
    fn test_estimate_bytes_string_size_small() {
        // Small byte strings (length 0-23): 1 byte header + data
        assert_eq!(CborEncoder::estimate_bytes_string_size(0), 1); // header(1) + data(0)
        assert_eq!(CborEncoder::estimate_bytes_string_size(10), 11); // header(1) + data(10)
        assert_eq!(CborEncoder::estimate_bytes_string_size(23), 24); // header(1) + data(23)
    }

    #[test]
    fn test_estimate_bytes_string_size_medium() {
        // Medium byte strings (length 24-255): 2 byte header + data
        assert_eq!(CborEncoder::estimate_bytes_string_size(24), 26); // header(2) + data(24)
        assert_eq!(CborEncoder::estimate_bytes_string_size(100), 102); // header(2) + data(100)
        assert_eq!(CborEncoder::estimate_bytes_string_size(255), 257); // header(2) + data(255)
    }

    #[test]
    fn test_estimate_bytes_string_size_large() {
        // Large byte strings (length 256-65535): 3 byte header + data
        assert_eq!(CborEncoder::estimate_bytes_string_size(256), 259); // header(3) + data(256)
        assert_eq!(CborEncoder::estimate_bytes_string_size(1024), 1027); // header(3) + data(1024)
        assert_eq!(CborEncoder::estimate_bytes_string_size(65535), 65538); // header(3) + data(65535)
    }

    #[test]
    fn test_estimate_text_string_size_small() {
        // Small text strings (length 0-23): 1 byte header + data
        assert_eq!(CborEncoder::estimate_text_string_size(0), 1); // header(1) + data(0)
        assert_eq!(CborEncoder::estimate_text_string_size(10), 11); // header(1) + data(10)
        assert_eq!(CborEncoder::estimate_text_string_size(23), 24); // header(1) + data(23)
    }

    #[test]
    fn test_estimate_text_string_size_medium() {
        // Medium text strings (length 24-255): 2 byte header + data
        assert_eq!(CborEncoder::estimate_text_string_size(24), 26); // header(2) + data(24)
        assert_eq!(CborEncoder::estimate_text_string_size(100), 102); // header(2) + data(100)
        assert_eq!(CborEncoder::estimate_text_string_size(255), 257); // header(2) + data(255)
    }

    #[test]
    fn test_estimate_text_string_size_large() {
        // Large text strings (length 256-65535): 3 byte header + data
        assert_eq!(CborEncoder::estimate_text_string_size(256), 259); // header(3) + data(256)
        assert_eq!(CborEncoder::estimate_text_string_size(1024), 1027); // header(3) + data(1024)
        assert_eq!(CborEncoder::estimate_text_string_size(65535), 65538); // header(3) + data(65535)
    }

    #[test]
    fn test_estimate_text_string_size_common_strings() {
        // Common COSE strings
        assert_eq!(
            CborEncoder::estimate_text_string_size("Signature1".len()),
            11
        ); // "Signature1" = 10 chars
        assert_eq!(CborEncoder::estimate_text_string_size("test".len()), 5); // "test" = 4 chars
        assert_eq!(
            CborEncoder::estimate_text_string_size("application/json".len()),
            17
        ); // "application/json" = 16 chars
        assert_eq!(
            CborEncoder::estimate_text_string_size("application/cbor-diagnostic".len()),
            29
        ); // "application/cbor-diagnostic" = 27 chars (requires 2-byte header)
    }

    #[test]
    fn test_encode_bool() {
        let mut buffer = [0u8; 1];
        let mut encoder = CborEncoder::new(&mut buffer);

        encoder.encode_bool(true).unwrap();
        assert_eq!(encoder.len(), 1);
        assert_eq!(encoder.buffer[0], 0xF5);

        let mut buffer = [0u8; 8];
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_bool(false).unwrap();
        assert_eq!(encoder.len(), 1);
        assert_eq!(encoder.buffer[0], 0xF4);
    }

    #[test]
    fn test_tagged_uuid_valid() {
        let uuid_bytes = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        let tagged_uuid = TaggedUuid::new(&uuid_bytes);

        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);
        tagged_uuid.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Expected: tag(37) + bytes(16)
        // Tag 37 = 0xD8 0x25 (2 bytes)
        // Bytes header for 16 bytes = 0x50 (1 byte)
        // 16 bytes of data
        // Total: 2 + 1 + 16 = 19 bytes
        assert_eq!(encoded_len, 19);

        // Verify tag 37 encoding
        assert_eq!(buffer[0], 0xD8); // Tag major type (6) with additional info 24
        assert_eq!(buffer[1], 0x25); // Tag number 37

        // Verify byte string header
        assert_eq!(buffer[2], 0x50); // Byte string (major type 2) with length 16

        // Verify UUID bytes
        assert_eq!(&buffer[3..19], &uuid_bytes);
    }

    #[test]
    fn test_tagged_oid_encode() {
        // Test OID encoding with tag 111
        let oid_bytes = &[
            0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x01,
        ];
        let tagged_oid = TaggedOid::new(oid_bytes);

        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);
        tagged_oid.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Expected: tag(111) + bytes(11)
        // Tag 111 = 0xD8 0x6F (2 bytes)
        // Bytes header for 11 bytes = 0x4B (1 byte)
        // 11 bytes of data
        // Total: 2 + 1 + 11 = 14 bytes
        assert_eq!(encoded_len, 14);

        // Verify tag 111 encoding
        assert_eq!(buffer[0], 0xD8); // Tag major type (6) with additional info 24
        assert_eq!(buffer[1], 0x6F); // Tag number 111

        // Verify byte string header
        assert_eq!(buffer[2], 0x4B); // Byte string (major type 2) with length 11

        // Verify OID bytes
        assert_eq!(&buffer[3..14], oid_bytes);
    }

    #[test]
    fn test_tagged_uuid_all_zeros() {
        // Nil UUID - all zeros
        let uuid_bytes = [0x00; 16];
        let tagged_uuid = TaggedUuid::new(&uuid_bytes);

        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);
        tagged_uuid.encode(&mut encoder).expect("Encoding failed");

        assert_eq!(encoder.len(), 19);
        assert_eq!(buffer[0], 0xD8);
        assert_eq!(buffer[1], 0x25);
        assert_eq!(buffer[2], 0x50);
        assert_eq!(&buffer[3..19], &uuid_bytes);
    }

    #[test]
    fn test_tagged_uuid_all_ones() {
        // Max UUID - all ones
        let uuid_bytes = [0xFF; 16];
        let tagged_uuid = TaggedUuid::new(&uuid_bytes);

        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);
        tagged_uuid.encode(&mut encoder).expect("Encoding failed");

        assert_eq!(encoder.len(), 19);
        assert_eq!(&buffer[3..19], &uuid_bytes);
    }

    #[test]
    fn test_tagged_uuid_buffer_too_small() {
        let uuid_bytes = [0xAB; 16];
        let tagged_uuid = TaggedUuid::new(&uuid_bytes);

        // Buffer too small to hold tag + length + UUID
        let mut buffer = [0u8; 10];
        let mut encoder = CborEncoder::new(&mut buffer);
        let result = tagged_uuid.encode(&mut encoder);

        assert!(result.is_err());
        assert!(matches!(result, Err(EatError::BufferTooSmall)));
    }

    #[test]
    fn test_tagged_uuid_creation() {
        let uuid_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0,
        ];
        let tagged_uuid = TaggedUuid::new(&uuid_bytes);
        assert_eq!(tagged_uuid.uuid.len(), 16);
        assert_eq!(tagged_uuid.uuid, &uuid_bytes);
    }

    #[test]
    fn test_tagged_oid_empty() {
        // Empty OID
        let oid_bytes: &[u8] = &[];
        let tagged_oid = TaggedOid::new(oid_bytes);

        let mut buffer = [0u8; 16];
        let mut encoder = CborEncoder::new(&mut buffer);
        tagged_oid
            .encode(&mut encoder)
            .expect("Empty OID should encode");

        // Tag 111 (2 bytes) + empty byte string (1 byte) = 3 bytes
        assert_eq!(encoder.len(), 3);
        assert_eq!(buffer[0], 0xD8);
        assert_eq!(buffer[1], 0x6F);
        assert_eq!(buffer[2], 0x40); // Byte string with length 0
    }

    #[test]
    fn test_tagged_oid_small() {
        // Small OID (< 23 bytes)
        let oid_bytes = &[0x2B, 0x06, 0x01];
        let tagged_oid = TaggedOid::new(oid_bytes);

        let mut buffer = [0u8; 16];
        let mut encoder = CborEncoder::new(&mut buffer);
        tagged_oid.encode(&mut encoder).expect("Encoding failed");

        // Tag 111 (2 bytes) + byte string header (1 byte) + 3 bytes = 6 bytes
        assert_eq!(encoder.len(), 6);
        assert_eq!(buffer[0], 0xD8);
        assert_eq!(buffer[1], 0x6F);
        assert_eq!(buffer[2], 0x43); // Byte string with length 3
        assert_eq!(&buffer[3..6], oid_bytes);
    }

    #[test]
    fn test_tagged_oid_medium() {
        // Medium OID (requires 2-byte length encoding)
        let oid_bytes = &[0xAB; 100];
        let tagged_oid = TaggedOid::new(oid_bytes);

        let mut buffer = [0u8; 128];
        let mut encoder = CborEncoder::new(&mut buffer);
        tagged_oid.encode(&mut encoder).expect("Encoding failed");

        // Tag 111 (2 bytes) + byte string header (2 bytes for length 100) + 100 bytes = 104 bytes
        assert_eq!(encoder.len(), 104);
        assert_eq!(buffer[0], 0xD8);
        assert_eq!(buffer[1], 0x6F);
        assert_eq!(buffer[2], 0x58); // Byte string major type with 1-byte length
        assert_eq!(buffer[3], 100); // Length = 100
    }

    #[test]
    fn test_tagged_oid_buffer_too_small() {
        let oid_bytes = &[0x2B, 0x06, 0x01, 0x04, 0x01];
        let tagged_oid = TaggedOid::new(oid_bytes);

        // Buffer too small
        let mut buffer = [0u8; 5];
        let mut encoder = CborEncoder::new(&mut buffer);
        let result = tagged_oid.encode(&mut encoder);

        assert!(result.is_err());
        assert!(matches!(result, Err(EatError::BufferTooSmall)));
    }

    #[test]
    fn test_tagged_oid_creation() {
        let oid_bytes = &[0x2B, 0x06, 0x01, 0x04];
        let tagged_oid = TaggedOid::new(oid_bytes);
        assert_eq!(tagged_oid.oid, oid_bytes);
    }

    #[test]
    fn test_tagged_oid_long() {
        // Long OID (testing large byte string encoding)
        let oid_bytes = &[0xFF; 300];
        let tagged_oid = TaggedOid::new(oid_bytes);

        let mut buffer = [0u8; 320];
        let mut encoder = CborEncoder::new(&mut buffer);
        tagged_oid.encode(&mut encoder).expect("Encoding failed");

        // Tag 111 (2 bytes) + byte string header (3 bytes for length 300) + 300 bytes = 305 bytes
        assert_eq!(encoder.len(), 305);
        assert_eq!(buffer[0], 0xD8);
        assert_eq!(buffer[1], 0x6F);
        assert_eq!(buffer[2], 0x59); // Byte string major type with 2-byte length
        assert_eq!(buffer[3], 0x01); // High byte of length (256 + 44 = 300)
        assert_eq!(buffer[4], 0x2C); // Low byte of length
    }

    #[test]
    fn test_encode_tag_small() {
        // Test small tag values (0-23)
        let mut buffer = [0u8; 8];
        let mut encoder = CborEncoder::new(&mut buffer);

        encoder.encode_tag(0).expect("Tag 0 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0xC0); // Major type 6, value 0

        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_tag(23).expect("Tag 23 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0xD7); // Major type 6, value 23
    }

    #[test]
    fn test_encode_tag_medium() {
        // Test medium tag values (24-255)
        let mut buffer = [0u8; 8];
        let mut encoder = CborEncoder::new(&mut buffer);

        encoder.encode_tag(24).expect("Tag 24 should encode");
        assert_eq!(encoder.len(), 2);
        assert_eq!(buffer[0], 0xD8); // Major type 6, additional info 24
        assert_eq!(buffer[1], 24);

        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_tag(255).expect("Tag 255 should encode");
        assert_eq!(encoder.len(), 2);
        assert_eq!(buffer[0], 0xD8);
        assert_eq!(buffer[1], 255);
    }

    #[test]
    fn test_encode_tag_large() {
        // Test large tag values (256-65535)
        let mut buffer = [0u8; 8];
        let mut encoder = CborEncoder::new(&mut buffer);

        encoder.encode_tag(256).expect("Tag 256 should encode");
        assert_eq!(encoder.len(), 3);
        assert_eq!(buffer[0], 0xD9); // Major type 6, additional info 25
        assert_eq!(buffer[1], 0x01); // High byte
        assert_eq!(buffer[2], 0x00); // Low byte

        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_tag(65535).expect("Tag 65535 should encode");
        assert_eq!(encoder.len(), 3);
        assert_eq!(buffer[0], 0xD9);
        assert_eq!(buffer[1], 0xFF);
        assert_eq!(buffer[2], 0xFF);
    }

    #[test]
    fn test_encode_array_header() {
        let mut buffer = [0u8; 8];

        // Small array (0-23 elements)
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder
            .encode_array_header(0)
            .expect("Array 0 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x80); // Major type 4, value 0

        let mut encoder = CborEncoder::new(&mut buffer);
        encoder
            .encode_array_header(5)
            .expect("Array 5 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x85); // Major type 4, value 5

        // Medium array (24-255 elements)
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder
            .encode_array_header(100)
            .expect("Array 100 should encode");
        assert_eq!(encoder.len(), 2);
        assert_eq!(buffer[0], 0x98); // Major type 4, additional info 24
        assert_eq!(buffer[1], 100);
    }

    #[test]
    fn test_encode_map_header() {
        let mut buffer = [0u8; 8];

        // Small map (0-23 pairs)
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_map_header(0).expect("Map 0 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0xA0); // Major type 5, value 0

        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_map_header(10).expect("Map 10 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0xAA); // Major type 5, value 10

        // Medium map (24-255 pairs)
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_map_header(50).expect("Map 50 should encode");
        assert_eq!(encoder.len(), 2);
        assert_eq!(buffer[0], 0xB8); // Major type 5, additional info 24
        assert_eq!(buffer[1], 50);
    }

    #[test]
    fn test_encode_bytes_edge_cases() {
        let mut buffer = [0u8; 64];

        // Empty byte string
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder
            .encode_bytes(&[])
            .expect("Empty bytes should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x40); // Byte string, length 0

        // Single byte
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder
            .encode_bytes(&[0xAB])
            .expect("Single byte should encode");
        assert_eq!(encoder.len(), 2);
        assert_eq!(buffer[0], 0x41); // Byte string, length 1
        assert_eq!(buffer[1], 0xAB);

        // 23 bytes (max inline length)
        let data = [0xCD; 23];
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_bytes(&data).expect("23 bytes should encode");
        assert_eq!(encoder.len(), 24);
        assert_eq!(buffer[0], 0x57); // Byte string, length 23
        assert_eq!(&buffer[1..24], &data);
    }

    #[test]
    fn test_encode_text_edge_cases() {
        let mut buffer = [0u8; 64];

        // Empty text string
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_text("").expect("Empty text should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x60); // Text string, length 0

        // Single character
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_text("A").expect("Single char should encode");
        assert_eq!(encoder.len(), 2);
        assert_eq!(buffer[0], 0x61); // Text string, length 1
        assert_eq!(buffer[1], b'A');

        // ASCII text
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_text("Hello").expect("ASCII should encode");
        assert_eq!(encoder.len(), 6);
        assert_eq!(buffer[0], 0x65); // Text string, length 5
        assert_eq!(&buffer[1..6], b"Hello");
    }

    #[test]
    fn test_encode_int_edge_cases() {
        let mut buffer = [0u8; 16];

        // Zero
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_int(0).expect("Zero should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x00);

        // Positive small (0-23)
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_int(23).expect("23 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x17);

        // Negative small (-1 to -24)
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_int(-1).expect("-1 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x20); // Major type 1, value 0 (represents -1)

        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_int(-24).expect("-24 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x37); // Major type 1, value 23 (represents -24)

        // i64::MAX
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder
            .encode_int(i64::MAX)
            .expect("i64::MAX should encode");
        assert_eq!(encoder.len(), 9);
        assert_eq!(buffer[0], 0x1B); // Unsigned int, 8-byte value follows

        // Large negative value (but not i64::MIN which would overflow)
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_int(-1000).expect("-1000 should encode");
        assert_eq!(encoder.len(), 3);
        assert_eq!(buffer[0], 0x39); // Negative int, 2-byte value follows
    }

    #[test]
    fn test_encode_uint_edge_cases() {
        let mut buffer = [0u8; 16];

        // Zero
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_uint(0).expect("Zero should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x00);

        // Small value (0-23)
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder.encode_uint(23).expect("23 should encode");
        assert_eq!(encoder.len(), 1);
        assert_eq!(buffer[0], 0x17);

        // u64::MAX
        let mut encoder = CborEncoder::new(&mut buffer);
        encoder
            .encode_uint(u64::MAX)
            .expect("u64::MAX should encode");
        assert_eq!(encoder.len(), 9);
        assert_eq!(buffer[0], 0x1B); // Unsigned int, 8-byte value follows
    }

    #[test]
    fn test_cbor_encodable_trait_with_references() {
        // Test that references to CborEncodable types also work
        let uuid_bytes = [0xAB; 16];
        let tagged_uuid = TaggedUuid::new(&uuid_bytes);
        let uuid_ref = &tagged_uuid;

        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);
        uuid_ref
            .encode(&mut encoder)
            .expect("Reference should encode");
        assert_eq!(encoder.len(), 19);
    }

    #[test]
    fn test_encoder_position_tracking() {
        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);

        assert_eq!(encoder.len(), 0);
        assert!(encoder.is_empty());

        // Encode 10 (single byte: 0x0A)
        encoder.encode_uint(10).expect("Should encode");
        assert_eq!(encoder.len(), 1);
        assert!(!encoder.is_empty());

        // Encode "test" (1 byte header + 4 bytes text = 5 bytes)
        encoder.encode_text("test").expect("Should encode");
        assert_eq!(encoder.len(), 6); // 1 (previous) + 1 (header) + 4 (text)
    }

    // Tests that verify our CBOR encoding can be decoded by external crates
    // Using minicbor which is no_std compatible
    #[cfg(test)]
    mod interop_tests {
        use super::*;
        use minicbor::Decoder;

        #[test]
        fn test_decode_uint_with_minicbor() {
            let mut buffer = [0u8; 16];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                // Encode various uints
                encoder.encode_uint(0).unwrap();
                encoder.encode_uint(42).unwrap();
                encoder.encode_uint(1000).unwrap();
                encoder.encode_uint(65535).unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            assert_eq!(decoder.u64().unwrap(), 0);
            assert_eq!(decoder.u64().unwrap(), 42);
            assert_eq!(decoder.u64().unwrap(), 1000);
            assert_eq!(decoder.u64().unwrap(), 65535);
        }

        #[test]
        fn test_decode_int_with_minicbor() {
            let mut buffer = [0u8; 32];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                encoder.encode_int(0).unwrap();
                encoder.encode_int(-1).unwrap();
                encoder.encode_int(-100).unwrap();
                encoder.encode_int(12345).unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            assert_eq!(decoder.i64().unwrap(), 0);
            assert_eq!(decoder.i64().unwrap(), -1);
            assert_eq!(decoder.i64().unwrap(), -100);
            assert_eq!(decoder.i64().unwrap(), 12345);
        }

        #[test]
        fn test_decode_text_with_minicbor() {
            let mut buffer = [0u8; 64];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                encoder.encode_text("").unwrap();
                encoder.encode_text("hello").unwrap();
                encoder.encode_text("CBOR").unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            assert_eq!(decoder.str().unwrap(), "");
            assert_eq!(decoder.str().unwrap(), "hello");
            assert_eq!(decoder.str().unwrap(), "CBOR");
        }

        #[test]
        fn test_decode_bytes_with_minicbor() {
            let mut buffer = [0u8; 64];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                encoder.encode_bytes(&[]).unwrap();
                encoder.encode_bytes(&[0xAB, 0xCD, 0xEF]).unwrap();
                encoder.encode_bytes(&[0x00, 0xFF]).unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            assert_eq!(decoder.bytes().unwrap(), &[]);
            assert_eq!(decoder.bytes().unwrap(), &[0xAB, 0xCD, 0xEF]);
            assert_eq!(decoder.bytes().unwrap(), &[0x00, 0xFF]);
        }

        #[test]
        fn test_decode_bool_with_minicbor() {
            let mut buffer = [0u8; 8];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                encoder.encode_bool(true).unwrap();
                encoder.encode_bool(false).unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            assert!(decoder.bool().unwrap());
            assert!(!decoder.bool().unwrap());
        }

        #[test]
        fn test_decode_array_with_minicbor() {
            let mut buffer = [0u8; 64];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                // Empty array
                encoder.encode_array_header(0).unwrap();

                // Array with 3 integers
                encoder.encode_array_header(3).unwrap();
                encoder.encode_uint(1).unwrap();
                encoder.encode_uint(2).unwrap();
                encoder.encode_uint(3).unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            // Empty array
            assert_eq!(decoder.array().unwrap(), Some(0));

            // Array with 3 elements
            assert_eq!(decoder.array().unwrap(), Some(3));
            assert_eq!(decoder.u64().unwrap(), 1);
            assert_eq!(decoder.u64().unwrap(), 2);
            assert_eq!(decoder.u64().unwrap(), 3);
        }

        #[test]
        fn test_decode_map_with_minicbor() {
            let mut buffer = [0u8; 64];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                // Empty map
                encoder.encode_map_header(0).unwrap();

                // Map with 2 entries: {1: "a", 2: "b"}
                encoder.encode_map_header(2).unwrap();
                encoder.encode_uint(1).unwrap();
                encoder.encode_text("a").unwrap();
                encoder.encode_uint(2).unwrap();
                encoder.encode_text("b").unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            // Empty map
            assert_eq!(decoder.map().unwrap(), Some(0));

            // Map with 2 entries
            assert_eq!(decoder.map().unwrap(), Some(2));
            assert_eq!(decoder.u64().unwrap(), 1);
            assert_eq!(decoder.str().unwrap(), "a");
            assert_eq!(decoder.u64().unwrap(), 2);
            assert_eq!(decoder.str().unwrap(), "b");
        }

        #[test]
        fn test_decode_tag_with_minicbor() {
            let mut buffer = [0u8; 32];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                // Tag 37 (UUID tag) with byte string
                encoder.encode_tag(37).unwrap();
                encoder.encode_bytes(&[0xAB; 16]).unwrap();

                // Tag 111 (OID tag) with byte string
                encoder.encode_tag(111).unwrap();
                encoder.encode_bytes(&[0x2B, 0x06, 0x01]).unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            assert_eq!(decoder.tag().unwrap().as_u64(), 37);
            assert_eq!(decoder.bytes().unwrap(), &[0xAB; 16]);

            assert_eq!(decoder.tag().unwrap().as_u64(), 111);
            assert_eq!(decoder.bytes().unwrap(), &[0x2B, 0x06, 0x01]);
        }

        #[test]
        fn test_decode_tagged_uuid_with_minicbor() {
            let uuid_bytes = [
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00,
            ];
            let tagged_uuid = TaggedUuid::new(&uuid_bytes);

            let mut buffer = [0u8; 32];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);
                tagged_uuid.encode(&mut encoder).unwrap();
                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            assert_eq!(decoder.tag().unwrap().as_u64(), 37);
            assert_eq!(decoder.bytes().unwrap(), &uuid_bytes);
        }

        #[test]
        fn test_decode_tagged_oid_with_minicbor() {
            let oid_bytes = &[
                0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x01,
            ];
            let tagged_oid = TaggedOid::new(oid_bytes);

            let mut buffer = [0u8; 32];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);
                tagged_oid.encode(&mut encoder).unwrap();
                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            assert_eq!(decoder.tag().unwrap().as_u64(), 111);
            assert_eq!(decoder.bytes().unwrap(), oid_bytes);
        }

        #[test]
        fn test_decode_complex_structure_with_minicbor() {
            let mut buffer = [0u8; 128];
            let len = {
                let mut encoder = CborEncoder::new(&mut buffer);

                // Create: {0: [1, 2, 3], 1: "hello", 2: true}
                encoder.encode_map_header(3).unwrap();

                encoder.encode_uint(0).unwrap();
                encoder.encode_array_header(3).unwrap();
                encoder.encode_uint(1).unwrap();
                encoder.encode_uint(2).unwrap();
                encoder.encode_uint(3).unwrap();

                encoder.encode_uint(1).unwrap();
                encoder.encode_text("hello").unwrap();

                encoder.encode_uint(2).unwrap();
                encoder.encode_bool(true).unwrap();

                encoder.len()
            };

            let encoded = &buffer[..len];
            let mut decoder = Decoder::new(encoded);

            // Map with 3 entries
            assert_eq!(decoder.map().unwrap(), Some(3));

            // First entry: 0: [1, 2, 3]
            assert_eq!(decoder.u64().unwrap(), 0);
            assert_eq!(decoder.array().unwrap(), Some(3));
            assert_eq!(decoder.u64().unwrap(), 1);
            assert_eq!(decoder.u64().unwrap(), 2);
            assert_eq!(decoder.u64().unwrap(), 3);

            // Second entry: 1: "hello"
            assert_eq!(decoder.u64().unwrap(), 1);
            assert_eq!(decoder.str().unwrap(), "hello");

            // Third entry: 2: true
            assert_eq!(decoder.u64().unwrap(), 2);
            assert!(decoder.bool().unwrap());
        }
    }
}

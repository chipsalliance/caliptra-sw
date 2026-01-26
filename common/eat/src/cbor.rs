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
}

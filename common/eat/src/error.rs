// Licensed under the Apache-2.0 license

//! Common error types for the OCP EAT library

/// Error type for EAT and CBOR operations
#[derive(Debug, PartialEq)]
pub enum EatError {
    BufferTooSmall,
    InvalidData,
    MissingMandatoryClaim,
    InvalidClaimSize,
    EncodingError,
    InvalidUtf8,
}

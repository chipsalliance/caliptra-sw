// Licensed under the Apache-2.0 license

//! Envelope Signed CSR EAT (Envelope Signed Certificate Signing Request Entity Attestation Token)
//!
//! This module implements CSR EAT claims according to the CDDL specification
//! for envelope-signed CSR EAT tokens.
//!
//! # CBOR Structure Example
//!
//! ```text
//! signed-cwt / 18([
//!   / protected / <<{
//!     / alg-id / 1 : 7,
//!     / content-type / 3 : "application/eat+cwt",
//!     / issuer-key-id / 4 : 'RT Alias Key'
//!   }>>,
//!   / unprotected / {},
//!   / payload / <<{
//!     / nonce / 10: h'AAAABBBBAAAABBBBAAAABBBB',
//!     / csr / -70001 : h'59025630820252308201d9a003020102021431a4e0',
//!     / attrib / -70002: [
//!       / tagged-oid-type / 111(h'6086480186F84D010F046301')
//!     ]
//!   }>>,
//!   / signature / h'FA45AAB345AB4988'
//! ])
//! ```

use crate::cbor::CborEncoder;
use crate::claim_keys::*;
use crate::error::EatError;

// Envelope Signed CSR specific private claim keys (must be < -65536 per RFC 8392)
const ENV_SIGNED_CSR_CLAIM_KEY_CSR: i64 = -70001;
const ENV_SIGNED_CSR_CLAIM_KEY_ATTRIB: i64 = -70002;

/// OCP Security OID definitions for Device Identity Provisioning
///
/// These OIDs are used in the CSR EAT attributes field to indicate key derivation methods
/// and other security properties according to the OCP Security DIP specification.
pub mod oids {
    /// OCP Security Branch OID: {1 3 6 1 4 1 42623 1}
    ///
    /// Base OID for all OCP Security specifications
    pub const OCP_SECURITY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01];

    /// Envelope-signed EAT profile OID: {1 3 6 1 4 1 42623 1 1}
    ///
    /// Identifies the OCP DIP Envelope-signed EAT profile
    pub const OCP_SECURITY_OID_EAT_PROFILE: &[u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x01];

    /// Key Derivation Attribute OID Branch: {1 3 6 1 4 1 42623 1 2}
    ///
    /// Base OID for key derivation attribute OIDs
    pub const OCP_SECURITY_OID_KDA: &[u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02];

    /// Key Derivation Attribute: Derived from Owner Entropy Fuse
    ///
    /// OID: {1 3 6 1 4 1 42623 1 2 1}
    ///
    /// Indicates the attestation key is derived from owner-provisioned entropy fuse
    pub const OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE: &[u8] = &[
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x01,
    ];

    /// Key Derivation Attribute: Derived from First Mutable Code
    ///
    /// OID: {1 3 6 1 4 1 42623 1 2 2}
    ///
    /// Indicates the attestation key is derived from first mutable code measurement
    pub const OCP_SECURITY_OID_KDA_FIRST_MUTABLE_CODE: &[u8] = &[
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x02,
    ];

    /// Key Derivation Attribute: Derived from Non-First Mutable Code
    ///
    /// OID: {1 3 6 1 4 1 42623 1 2 3}
    ///
    /// Indicates the attestation key is derived from non-first mutable code measurement
    pub const OCP_SECURITY_OID_KDA_NON_FIRST_MUTABLE_CODE: &[u8] = &[
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x03,
    ];

    /// Key Derivation Attribute: Derived from Owner Provisioned Key
    ///
    /// OID: {1 3 6 1 4 1 42623 1 2 4}
    ///
    /// Indicates the attestation key is derived from an owner-provisioned key
    pub const OCP_SECURITY_OID_KDA_OWNER_PROVISIONED_KEY: &[u8] = &[
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x04,
    ];
}

/// OID type for key attributes (tagged with CBOR tag 111 for OID)
///
/// Encodes Object Identifiers using CBOR tag 111 as specified in RFC 8949.
/// The OID value must be in X.690 BER encoding (content octets only, without the
/// UNIVERSAL TAG 6 prefix or length byte).
///
/// # Example
/// For OCP DIP Owner Entropy Fuse OID {1 3 6 1 4 1 42623 1 2 1}:
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
/// ```rust,ignore
/// use ocp_eat::csr_eat::{TaggedOid, oids};
///
/// let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
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
    pub fn new(oid: &'a [u8]) -> Self {
        Self { oid }
    }

    /// Encode the tagged OID to CBOR
    ///
    /// Produces: tag(111) followed by byte string containing the X.690 encoded OID value
    pub fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        // Tag 111 for OID (RFC 8949 Section 3.4.5.3)
        encoder.encode_tag(111)?;
        encoder.encode_bytes(self.oid)?;
        Ok(())
    }
}

/// Envelope Signed CSR EAT Claims
///
/// Payload structure for Envelope Signed CSR (Certificate Signing Request) EAT tokens.
/// Contains a CSR along with key attribute OIDs that describe the requested certificate's
/// key properties. Used in device identity provisioning workflows.
///
/// Reference: [OCP Security Device Identity Provisioning Specification]
/// (https://opencomputeproject.github.io/Security/device-identity-provisioning/)
#[derive(Debug, Clone, Copy)]
pub struct CsrEatClaims<'a> {
    /// Optional nonce (8-64 bytes)
    pub nonce: Option<&'a [u8]>,

    /// CSR in DER-encoded format (required)
    pub csr: &'a [u8],

    /// List of key attribute OIDs (required, at least one)
    pub attributes: &'a [TaggedOid<'a>],
}

impl<'a> CsrEatClaims<'a> {
    /// Create new CSR EAT claims
    ///
    /// # Arguments
    /// * `csr` - DER-encoded Certificate Signing Request
    /// * `attributes` - List of key attribute OIDs (must contain at least one)
    pub fn new(csr: &'a [u8], attributes: &'a [TaggedOid<'a>]) -> Self {
        Self {
            nonce: None,
            csr,
            attributes,
        }
    }

    /// Create CSR EAT claims with a nonce
    pub fn with_nonce(csr: &'a [u8], attributes: &'a [TaggedOid<'a>], nonce: &'a [u8]) -> Self {
        Self {
            nonce: Some(nonce),
            csr,
            attributes,
        }
    }

    /// Validate the CSR EAT claims
    pub fn validate(&self) -> Result<(), EatError> {
        // Validate nonce size if present (8-64 bytes per CDDL)
        if let Some(nonce) = self.nonce {
            if nonce.len() < 8 || nonce.len() > 64 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        // CSR must not be empty
        if self.csr.is_empty() {
            return Err(EatError::InvalidData);
        }

        // Must have at least one attribute
        if self.attributes.is_empty() {
            return Err(EatError::MissingMandatoryClaim);
        }

        Ok(())
    }

    /// Encode CSR EAT claims to CBOR
    ///
    /// Encodes the claims as a CBOR map according to the CDDL specification.
    pub fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        // Validate before encoding
        self.validate()?;

        // Count the number of claims
        let claim_count = 2 + if self.nonce.is_some() { 1 } else { 0 };

        // Start CBOR map
        encoder.encode_map_header(claim_count)?;

        // Optional nonce claim
        if let Some(nonce) = self.nonce {
            encoder.encode_int(CLAIM_KEY_NONCE)?;
            encoder.encode_bytes(nonce)?;
        }

        // CSR claim (required)
        encoder.encode_int(ENV_SIGNED_CSR_CLAIM_KEY_CSR)?;
        encoder.encode_bytes(self.csr)?;

        // Attributes claim (required, array of tagged OIDs)
        encoder.encode_int(ENV_SIGNED_CSR_CLAIM_KEY_ATTRIB)?;
        encoder.encode_array_header(self.attributes.len() as u64)?;
        for attr in self.attributes {
            attr.encode(encoder)?;
        }

        Ok(())
    }

    /// Estimate the buffer size needed for encoding
    pub fn estimate_buffer_size(&self) -> usize {
        let mut size = 10; // Map overhead

        // Nonce
        if let Some(nonce) = self.nonce {
            size += 5 + nonce.len(); // Key + byte string overhead + data
        }

        // CSR
        size += 5 + self.csr.len(); // Key + byte string overhead + data

        // Attributes
        size += 5; // Key + array overhead
        for attr in self.attributes {
            size += 3 + attr.oid.len(); // Tag + byte string overhead + data
        }

        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock CSR data (simplified for testing)
    const MOCK_CSR: &[u8] = &[
        0x30, 0x82, 0x01, 0x23, // SEQUENCE header
        0x30, 0x81, 0xd0, // TBSRequest SEQUENCE
        0xa0, 0x03, 0x02, 0x01, 0x00, // version
    ];

    #[test]
    fn test_tagged_oid_creation() {
        let oid = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        assert_eq!(oid.oid, oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
    }

    #[test]
    fn test_tagged_oid_encode() {
        let oid = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let mut buffer = [0u8; 64];
        let mut encoder = CborEncoder::new(&mut buffer);

        oid.encode(&mut encoder).expect("Failed to encode OID");

        // Verify tag 111 (0xD8 0x6F)
        assert_eq!(buffer[0], 0xD8);
        assert_eq!(buffer[1], 0x6F);
        // Verify byte string header (0x4B = bytes string with length 11)
        assert_eq!(buffer[2], 0x4B);
        // Verify OID content
        assert_eq!(
            &buffer[3..14],
            oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE
        );
    }

    #[test]
    fn test_csr_eat_claims_new() {
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];

        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        assert!(claims.nonce.is_none());
        assert_eq!(claims.csr, MOCK_CSR);
        assert_eq!(claims.attributes.len(), 1);
    }

    #[test]
    fn test_csr_eat_claims_with_nonce() {
        let nonce = [0xAA; 32];
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_FIRST_MUTABLE_CODE);
        let attributes = [attr];

        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        assert_eq!(claims.nonce, Some(nonce.as_ref()));
        assert_eq!(claims.csr, MOCK_CSR);
        assert_eq!(claims.attributes.len(), 1);
    }

    #[test]
    fn test_validate_success() {
        let nonce = [0u8; 16]; // Valid nonce (16 bytes)
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];

        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        assert!(claims.validate().is_ok());
    }

    #[test]
    fn test_validate_nonce_too_short() {
        let nonce = [0u8; 7]; // Too short (< 8 bytes)
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];

        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        assert_eq!(claims.validate(), Err(EatError::InvalidClaimSize));
    }

    #[test]
    fn test_validate_nonce_too_long() {
        let nonce = [0u8; 65]; // Too long (> 64 bytes)
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];

        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        assert_eq!(claims.validate(), Err(EatError::InvalidClaimSize));
    }

    #[test]
    fn test_validate_empty_csr() {
        let empty_csr = &[];
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];

        let claims = CsrEatClaims::new(empty_csr, &attributes);

        assert_eq!(claims.validate(), Err(EatError::InvalidData));
    }

    #[test]
    fn test_validate_empty_attributes() {
        let attributes = [];
        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        assert_eq!(claims.validate(), Err(EatError::MissingMandatoryClaim));
    }

    #[test]
    fn test_encode_without_nonce() {
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];
        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);

        assert!(claims.encode(&mut encoder).is_ok());

        let len = encoder.len();
        assert!(len > 0);

        // Verify map header (2 items)
        assert_eq!(buffer[0], 0xA2); // Map with 2 entries
    }

    #[test]
    fn test_encode_with_nonce() {
        let nonce = [0xAA; 16];
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];
        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);

        assert!(claims.encode(&mut encoder).is_ok());

        let len = encoder.len();
        assert!(len > 0);

        // Verify map header (3 items: nonce, csr, attributes)
        assert_eq!(buffer[0], 0xA3); // Map with 3 entries
    }

    #[test]
    fn test_encode_multiple_attributes() {
        let attr1 = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attr2 = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_FIRST_MUTABLE_CODE);
        let attr3 = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_PROVISIONED_KEY);
        let attributes = [attr1, attr2, attr3];

        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        let mut buffer = [0u8; 512];
        let mut encoder = CborEncoder::new(&mut buffer);

        assert!(claims.encode(&mut encoder).is_ok());
        assert!(encoder.len() > 0);
    }

    #[test]
    fn test_encode_buffer_too_small() {
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];
        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        let mut buffer = [0u8; 5]; // Deliberately too small
        let mut encoder = CborEncoder::new(&mut buffer);

        assert_eq!(claims.encode(&mut encoder), Err(EatError::BufferTooSmall));
    }

    #[test]
    fn test_estimate_buffer_size_without_nonce() {
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];
        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        let estimated = claims.estimate_buffer_size();
        assert!(estimated > 0);
        assert!(estimated > MOCK_CSR.len());
    }

    #[test]
    fn test_estimate_buffer_size_with_nonce() {
        let nonce = [0u8; 16];
        let attr = TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE);
        let attributes = [attr];
        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        let estimated = claims.estimate_buffer_size();
        assert!(estimated > 0);

        // Verify encoding actually fits in estimated size
        let mut buffer = [0u8; 512]; // Use fixed-size buffer for no_std
        let mut encoder = CborEncoder::new(&mut buffer);
        assert!(claims.encode(&mut encoder).is_ok());
        assert!(encoder.len() <= estimated);
    }

    #[test]
    fn test_all_oid_constants() {
        // Verify all OID constants have reasonable lengths
        assert!(oids::OCP_SECURITY.len() > 0);
        assert!(oids::OCP_SECURITY_OID_EAT_PROFILE.len() > 0);
        assert!(oids::OCP_SECURITY_OID_KDA.len() > 0);
        assert!(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE.len() > 0);
        assert!(oids::OCP_SECURITY_OID_KDA_FIRST_MUTABLE_CODE.len() > 0);
        assert!(oids::OCP_SECURITY_OID_KDA_NON_FIRST_MUTABLE_CODE.len() > 0);
        assert!(oids::OCP_SECURITY_OID_KDA_OWNER_PROVISIONED_KEY.len() > 0);

        // Verify all start with OCP Security prefix (0x2B 0x06 0x01 0x04 0x01 0x82 0xCD 0x1F 0x01)
        let prefix = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01];
        assert!(oids::OCP_SECURITY.starts_with(prefix));
        assert!(oids::OCP_SECURITY_OID_EAT_PROFILE.starts_with(prefix));
        assert!(oids::OCP_SECURITY_OID_KDA.starts_with(prefix));
        assert!(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE.starts_with(prefix));
        assert!(oids::OCP_SECURITY_OID_KDA_FIRST_MUTABLE_CODE.starts_with(prefix));
        assert!(oids::OCP_SECURITY_OID_KDA_NON_FIRST_MUTABLE_CODE.starts_with(prefix));
        assert!(oids::OCP_SECURITY_OID_KDA_OWNER_PROVISIONED_KEY.starts_with(prefix));
    }

    #[test]
    fn test_cbor_claim_keys() {
        // Verify CSR claim keys are negative and < -65536
        assert!(ENV_SIGNED_CSR_CLAIM_KEY_CSR < -65536);
        assert!(ENV_SIGNED_CSR_CLAIM_KEY_ATTRIB < -65536);

        // Verify standard nonce claim key
        assert_eq!(CLAIM_KEY_NONCE, 10);
    }
}

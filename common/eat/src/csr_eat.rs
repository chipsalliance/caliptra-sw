// Licensed under the Apache-2.0 license

//! Attested CSR EAT (Attested Certificate Signing Request Entity Attestation Token)
//!
//! This module implements CSR EAT claims according to the CDDL specification
//! for attested CSR EAT tokens.
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

use crate::cbor::{CborEncodable, CborEncoder};
use crate::claim_keys::*;
use crate::error::EatError;
use crate::TaggedOid;

// Attested CSR specific private claim keys (must be < -65536 per RFC 8392)
pub const CLAIM_KEY_ATTESTED_CSR: i64 = -70001;
pub const CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB: i64 = -70002;
pub const CLAIM_KEY_KEYPAIR_INVENTORY: i64 = -70003;

/// OCP Security OID definitions for Device Identity Provisioning
///
/// These OIDs are used in the CSR EAT attributes field to indicate key derivation methods
/// and other security properties according to the OCP Security DIP specification.
pub mod oids {
    /// OCP Security Branch OID: {1 3 6 1 4 1 42623 1}
    ///
    /// Base OID for all OCP Security specifications (PEN 42623)
    pub const OCP_SECURITY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCC, 0x7F, 0x01];

    /// Attested EAT profile OID: {1 3 6 1 4 1 42623 1 1}
    ///
    /// Identifies the OCP DIP Attested EAT profile
    pub const OCP_SECURITY_OID_EAT_PROFILE: &[u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCC, 0x7F, 0x01, 0x01];

    /// Key Derivation Attribute OID: {1 3 6 1 4 1 42623 1 2} (ocp-security-dip-kda)
    ///
    /// Identifies the OCP derivation-attributes OID that maps to the OCP derivation-component bitfield
    pub const OCP_SECURITY_OID_KDA: &[u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCC, 0x7F, 0x01, 0x02];
}

/// OCP derivation-component bitfield values (per OCP DIP specification Section 2.4.1 / 3.2)
pub mod derivation_components {
    /// Bit 0: Unique Device Secret (UDS)
    pub const UDS: u64 = 1 << 0;
    /// Bit 1: Field-programmable entropy (e.g. field entropy fuses)
    pub const FIELD_ENTROPY: u64 = 1 << 1;
    /// Bit 2: Owner-provisioned non-confidential fuse values
    pub const OWNER_PROVISIONED_NON_CONFIDENTIAL_FUSE: u64 = 1 << 2;
    /// Bit 3: Vendor-provisioned non-confidential fuse values
    pub const VENDOR_PROVISIONED_NON_CONFIDENTIAL_FUSE: u64 = 1 << 3;
    /// Bit 4: First mutable code layer (FMC)
    pub const FIRST_MUTABLE_CODE: u64 = 1 << 4;
    /// Bit 5: Runtime firmware layer
    pub const RUNTIME_FIRMWARE: u64 = 1 << 5;
}

/// Key derivation attribute entry (mapping from OID to bitfield)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAttributeEntry<'a> {
    pub oid: TaggedOid<'a>,
    pub bitfield: u64,
}

impl<'a> KeyAttributeEntry<'a> {
    pub const fn new(oid: TaggedOid<'a>, bitfield: u64) -> Self {
        Self { oid, bitfield }
    }

    /// Helper for standard OCP derivation component bitfield (ocp-security-dip-kda)
    pub const fn ocp(bitfield: u64) -> Self {
        Self {
            oid: TaggedOid::new(oids::OCP_SECURITY_OID_KDA),
            bitfield,
        }
    }

    pub fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        self.oid.encode(encoder)?;
        encoder.encode_uint(self.bitfield)?;
        Ok(())
    }

    pub fn estimate_buffer_size(&self) -> usize {
        self.oid.estimate_size() + CborEncoder::estimate_uint_size(self.bitfield)
    }
}

/// Attested CSR EAT Claims
///
/// Payload structure for Attested CSR (Certificate Signing Request) EAT tokens.
/// Contains a CSR along with key derivation attributes described as an OID -> bitfield map.
///
/// Reference: [OCP Security Device Identity Provisioning Specification]
/// (https://opencomputeproject.github.io/Security/device-identity-provisioning/)
#[derive(Debug, Clone, Copy)]
pub struct CsrEatClaims<'a> {
    /// Optional nonce (8-64 bytes)
    pub nonce: Option<&'a [u8]>,

    /// CSR in DER-encoded format (required)
    pub csr: &'a [u8],

    /// List of key derivation attribute entries (required, at least one)
    pub attributes: &'a [KeyAttributeEntry<'a>],
}

impl<'a> CsrEatClaims<'a> {
    /// Create new CSR EAT claims
    ///
    /// # Arguments
    /// * `csr` - DER-encoded Certificate Signing Request
    /// * `attributes` - List of key derivation attribute entries (must contain at least one)
    pub fn new(csr: &'a [u8], attributes: &'a [KeyAttributeEntry<'a>]) -> Self {
        Self {
            nonce: None,
            csr,
            attributes,
        }
    }

    /// Create CSR EAT claims with a nonce
    pub fn with_nonce(
        csr: &'a [u8],
        attributes: &'a [KeyAttributeEntry<'a>],
        nonce: &'a [u8],
    ) -> Self {
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
        encoder.encode_int(CLAIM_KEY_ATTESTED_CSR)?;
        encoder.encode_bytes(self.csr)?;

        // Attributes claim (required, key-attributes-map of TaggedOid -> bitfield uint)
        encoder.encode_int(CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB)?;
        encoder.encode_map_header(self.attributes.len() as u64)?;
        for attr in self.attributes {
            attr.encode(encoder)?;
        }

        Ok(())
    }

    /// Estimate the buffer size needed for encoding
    pub fn estimate_buffer_size(&self) -> usize {
        let claim_count = 2 + if self.nonce.is_some() { 1 } else { 0 };
        let mut size = CborEncoder::estimate_uint_size(claim_count as u64); // Map header

        // Nonce
        if let Some(nonce) = self.nonce {
            size += CborEncoder::estimate_int_size(CLAIM_KEY_NONCE)
                + CborEncoder::estimate_bytes_string_size(nonce.len());
        }

        // CSR
        size += CborEncoder::estimate_int_size(CLAIM_KEY_ATTESTED_CSR)
            + CborEncoder::estimate_bytes_string_size(self.csr.len());

        // Attributes claim: key + map header
        size += CborEncoder::estimate_int_size(CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB)
            + CborEncoder::estimate_uint_size(self.attributes.len() as u64);
        for attr in self.attributes {
            size += attr.estimate_buffer_size();
        }

        size
    }
}

/// Key pair inventory entry for discovery (KeyPairID = 0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPairInventoryEntry<'a> {
    pub keypair_id: u8,
    pub attributes: &'a [KeyAttributeEntry<'a>],
}

impl<'a> KeyPairInventoryEntry<'a> {
    pub const fn new(keypair_id: u8, attributes: &'a [KeyAttributeEntry<'a>]) -> Self {
        Self {
            keypair_id,
            attributes,
        }
    }

    pub fn validate(&self) -> Result<(), EatError> {
        if self.keypair_id == 0 {
            return Err(EatError::InvalidData);
        }
        if self.attributes.is_empty() {
            return Err(EatError::MissingMandatoryClaim);
        }
        Ok(())
    }

    pub fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        self.validate()?;
        // keypair-inventory-entry = [ keypair-id: 1..255, attributes: key-attributes-map ]
        encoder.encode_array_header(2)?;
        encoder.encode_uint(self.keypair_id as u64)?;
        encoder.encode_map_header(self.attributes.len() as u64)?;
        for attr in self.attributes {
            attr.encode(encoder)?;
        }
        Ok(())
    }

    pub fn estimate_buffer_size(&self) -> usize {
        let mut size = CborEncoder::estimate_uint_size(2)
            + CborEncoder::estimate_uint_size(self.keypair_id as u64)
            + CborEncoder::estimate_uint_size(self.attributes.len() as u64);
        for attr in self.attributes {
            size += attr.estimate_buffer_size();
        }
        size
    }
}

/// Key Pair Inventory EAT Claims (returned when KeyPairID = 0)
///
/// Reference: [OCP Security Device Identity Provisioning Specification]
/// (https://opencomputeproject.github.io/Security/device-identity-provisioning/) Section 2.3 / 3.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPairInventoryClaims<'a> {
    /// Optional nonce (8-64 bytes)
    pub nonce: Option<&'a [u8]>,

    /// Keypair inventory entries
    pub entries: &'a [KeyPairInventoryEntry<'a>],
}

impl<'a> KeyPairInventoryClaims<'a> {
    pub fn new(entries: &'a [KeyPairInventoryEntry<'a>]) -> Result<Self, EatError> {
        let claims = Self {
            nonce: None,
            entries,
        };
        claims.validate()?;
        Ok(claims)
    }

    pub fn with_nonce(
        entries: &'a [KeyPairInventoryEntry<'a>],
        nonce: &'a [u8],
    ) -> Result<Self, EatError> {
        let claims = Self {
            nonce: Some(nonce),
            entries,
        };
        claims.validate()?;
        Ok(claims)
    }

    pub fn validate(&self) -> Result<(), EatError> {
        if let Some(nonce) = self.nonce {
            if nonce.len() < 8 || nonce.len() > 64 {
                return Err(EatError::InvalidClaimSize);
            }
        }
        if self.entries.is_empty() {
            return Err(EatError::MissingMandatoryClaim);
        }
        for entry in self.entries {
            entry.validate()?;
        }
        Ok(())
    }

    pub fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        self.validate()?;

        let claim_count = 1 + if self.nonce.is_some() { 1 } else { 0 };
        encoder.encode_map_header(claim_count)?;

        if let Some(nonce) = self.nonce {
            encoder.encode_int(CLAIM_KEY_NONCE)?;
            encoder.encode_bytes(nonce)?;
        }

        encoder.encode_int(CLAIM_KEY_KEYPAIR_INVENTORY)?;
        encoder.encode_array_header(self.entries.len() as u64)?;
        for entry in self.entries {
            entry.encode(encoder)?;
        }

        Ok(())
    }

    pub fn estimate_buffer_size(&self) -> usize {
        let claim_count = 1 + if self.nonce.is_some() { 1 } else { 0 };
        let mut size = CborEncoder::estimate_uint_size(claim_count as u64);

        if let Some(nonce) = self.nonce {
            size += CborEncoder::estimate_int_size(CLAIM_KEY_NONCE)
                + CborEncoder::estimate_bytes_string_size(nonce.len());
        }

        // Inventory claim: key + array header
        size += CborEncoder::estimate_int_size(CLAIM_KEY_KEYPAIR_INVENTORY)
            + CborEncoder::estimate_uint_size(self.entries.len() as u64);

        for entry in self.entries {
            size += entry.estimate_buffer_size();
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
        let oid = TaggedOid::new(oids::OCP_SECURITY_OID_KDA);
        assert_eq!(oid.oid, oids::OCP_SECURITY_OID_KDA);
    }

    #[test]
    fn test_tagged_oid_encode() {
        let oid = TaggedOid::new(oids::OCP_SECURITY_OID_KDA);
        let mut buffer = [0u8; 64];
        let mut encoder = CborEncoder::new(&mut buffer);

        oid.encode(&mut encoder).expect("Failed to encode OID");

        // Verify tag 111 (0xD8 0x6F)
        assert_eq!(buffer[0], 0xD8);
        assert_eq!(buffer[1], 0x6F);
        // Verify byte string header (0x4A = bytes string with length 10)
        assert_eq!(buffer[2], 0x4A);
        // Verify OID content
        assert_eq!(&buffer[3..13], oids::OCP_SECURITY_OID_KDA);
    }

    #[test]
    fn test_key_attribute_entry_ocp() {
        let entry = KeyAttributeEntry::ocp(
            derivation_components::UDS | derivation_components::FIELD_ENTROPY,
        );
        assert_eq!(entry.oid.oid, oids::OCP_SECURITY_OID_KDA);
        assert_eq!(entry.bitfield, 0x03);
    }

    #[test]
    fn test_csr_eat_claims_new() {
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];

        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        assert!(claims.nonce.is_none());
        assert_eq!(claims.csr, MOCK_CSR);
        assert_eq!(claims.attributes.len(), 1);
    }

    #[test]
    fn test_csr_eat_claims_with_nonce() {
        let nonce = [0xAA; 32];
        let attr = KeyAttributeEntry::ocp(derivation_components::FIRST_MUTABLE_CODE);
        let attributes = [attr];

        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        assert_eq!(claims.nonce, Some(nonce.as_ref()));
        assert_eq!(claims.csr, MOCK_CSR);
        assert_eq!(claims.attributes.len(), 1);
    }

    #[test]
    fn test_validate_success() {
        let nonce = [0u8; 16]; // Valid nonce (16 bytes)
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];

        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        assert!(claims.validate().is_ok());
    }

    #[test]
    fn test_validate_nonce_too_short() {
        let nonce = [0u8; 7]; // Too short (< 8 bytes)
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];

        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        assert_eq!(claims.validate(), Err(EatError::InvalidClaimSize));
    }

    #[test]
    fn test_validate_nonce_too_long() {
        let nonce = [0u8; 65]; // Too long (> 64 bytes)
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];

        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        assert_eq!(claims.validate(), Err(EatError::InvalidClaimSize));
    }

    #[test]
    fn test_validate_empty_csr() {
        let empty_csr = &[];
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
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
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];
        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);

        assert!(claims.encode(&mut encoder).is_ok());

        let len = encoder.len();
        assert!(len > 0);

        // Verify map header (2 items: csr, attributes)
        assert_eq!(buffer[0], 0xA2);
    }

    #[test]
    fn test_encode_with_nonce() {
        let nonce = [0xAA; 16];
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];
        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);

        assert!(claims.encode(&mut encoder).is_ok());

        let len = encoder.len();
        assert!(len > 0);

        // Verify map header (3 items: nonce, csr, attributes)
        assert_eq!(buffer[0], 0xA3);
    }

    #[test]
    fn test_encode_buffer_too_small() {
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];
        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        let mut buffer = [0u8; 5]; // Deliberately too small
        let mut encoder = CborEncoder::new(&mut buffer);

        assert_eq!(claims.encode(&mut encoder), Err(EatError::BufferTooSmall));
    }

    #[test]
    fn test_estimate_buffer_size_without_nonce() {
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];
        let claims = CsrEatClaims::new(MOCK_CSR, &attributes);

        let estimated = claims.estimate_buffer_size();
        assert!(estimated > 0);
        assert!(estimated > MOCK_CSR.len());

        let mut buffer = [0u8; 512];
        let mut encoder = CborEncoder::new(&mut buffer);
        assert!(claims.encode(&mut encoder).is_ok());
        assert!(encoder.len() <= estimated);
    }

    #[test]
    fn test_estimate_buffer_size_with_nonce() {
        let nonce = [0u8; 16];
        let attr = KeyAttributeEntry::ocp(derivation_components::UDS);
        let attributes = [attr];
        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        let estimated = claims.estimate_buffer_size();
        assert!(estimated > 0);

        let mut buffer = [0u8; 512];
        let mut encoder = CborEncoder::new(&mut buffer);
        assert!(claims.encode(&mut encoder).is_ok());
        assert!(encoder.len() <= estimated);
    }

    #[test]
    fn test_all_oid_constants() {
        // Verify all start with OCP Security prefix (0x2B 0x06 0x01 0x04 0x01 0x82 0xCC 0x7F 0x01)
        let prefix = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCC, 0x7F, 0x01];
        assert!(oids::OCP_SECURITY.starts_with(prefix));
        assert!(oids::OCP_SECURITY_OID_EAT_PROFILE.starts_with(prefix));
        assert!(oids::OCP_SECURITY_OID_KDA.starts_with(prefix));
    }

    #[test]
    fn test_cbor_claim_keys() {
        // Verify CSR claim keys are negative and < -65536
        assert_eq!(CLAIM_KEY_ATTESTED_CSR, -70001);
        assert_eq!(CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB, -70002);
        assert_eq!(CLAIM_KEY_KEYPAIR_INVENTORY, -70003);
        // Verify standard nonce claim key
        assert_eq!(CLAIM_KEY_NONCE, 10);
    }

    #[test]
    fn test_keypair_inventory_encode() {
        let ldevid_attrs = [KeyAttributeEntry::ocp(
            derivation_components::UDS | derivation_components::FIELD_ENTROPY,
        )];
        let fmc_attrs = [KeyAttributeEntry::ocp(
            derivation_components::UDS
                | derivation_components::FIELD_ENTROPY
                | derivation_components::FIRST_MUTABLE_CODE,
        )];
        let rt_attrs = [KeyAttributeEntry::ocp(
            derivation_components::UDS
                | derivation_components::FIELD_ENTROPY
                | derivation_components::FIRST_MUTABLE_CODE
                | derivation_components::RUNTIME_FIRMWARE,
        )];

        let entries = [
            KeyPairInventoryEntry::new(1, &ldevid_attrs),
            KeyPairInventoryEntry::new(2, &fmc_attrs),
            KeyPairInventoryEntry::new(3, &rt_attrs),
        ];

        let claims = KeyPairInventoryClaims::new(&entries).unwrap();
        let mut buffer = [0u8; 512];
        let mut encoder = CborEncoder::new(&mut buffer);

        assert!(claims.encode(&mut encoder).is_ok());
        let len = encoder.len();
        assert!(len > 0);
        assert!(len <= claims.estimate_buffer_size());
        assert_eq!(buffer[0], 0xA1); // 1 map entry (keypair-inventory)
    }

    #[test]
    fn test_keypair_inventory_with_nonce() {
        let nonce = [0x55u8; 32];
        let ldevid_attrs = [KeyAttributeEntry::ocp(derivation_components::UDS)];
        let entries = [KeyPairInventoryEntry::new(1, &ldevid_attrs)];

        let claims = KeyPairInventoryClaims::with_nonce(&entries, &nonce).unwrap();
        let mut buffer = [0u8; 512];
        let mut encoder = CborEncoder::new(&mut buffer);

        assert!(claims.encode(&mut encoder).is_ok());
        let len = encoder.len();
        assert!(len > 0);
        assert!(len <= claims.estimate_buffer_size());
        assert_eq!(buffer[0], 0xA2); // 2 map entries (nonce + keypair-inventory)
    }

    #[test]
    fn test_keypair_inventory_validate() {
        let empty_entries: &[KeyPairInventoryEntry] = &[];
        assert_eq!(
            KeyPairInventoryClaims::new(empty_entries),
            Err(EatError::MissingMandatoryClaim)
        );

        let invalid_entry = [KeyPairInventoryEntry::new(1, &[])];
        assert_eq!(
            KeyPairInventoryClaims::new(&invalid_entry),
            Err(EatError::MissingMandatoryClaim)
        );

        let binding = [KeyAttributeEntry::ocp(derivation_components::UDS)];
        let valid_entry = [KeyPairInventoryEntry::new(1, &binding)];
        let nonce_short = [1u8; 7];
        assert_eq!(
            KeyPairInventoryClaims::with_nonce(&valid_entry, &nonce_short),
            Err(EatError::InvalidClaimSize)
        );

        // keypair_id must be in range 1..=255 per CDDL (u8 guarantees <= 255, test 0)
        let zero_id_entry = [KeyPairInventoryEntry::new(0, &binding)];
        assert_eq!(
            KeyPairInventoryClaims::new(&zero_id_entry),
            Err(EatError::InvalidData)
        );
    }

    #[test]
    fn test_csr_eat_claims_roundtrip_decode() {
        let nonce = [0x5au8; 32];
        let attr = KeyAttributeEntry::ocp(
            derivation_components::UDS | derivation_components::FIELD_ENTROPY,
        );
        let attributes = [attr];
        let claims = CsrEatClaims::with_nonce(MOCK_CSR, &attributes, &nonce);

        let mut buffer = [0u8; 512];
        let len = {
            let mut encoder = CborEncoder::new(&mut buffer);
            claims.encode(&mut encoder).unwrap();
            encoder.len()
        };
        let encoded = &buffer[..len];

        let mut decoder = minicbor::Decoder::new(encoded);
        let map_len = decoder.map().unwrap().unwrap();
        assert_eq!(map_len, 3);

        let mut decoded_nonce = [0u8; 32];
        let mut decoded_csr = [0u8; 12];
        let mut decoded_kda_bitfield = None;

        for _ in 0..map_len {
            let key = decoder.i64().unwrap();
            match key {
                CLAIM_KEY_NONCE => {
                    let b = decoder.bytes().unwrap();
                    decoded_nonce.copy_from_slice(b);
                }
                CLAIM_KEY_ATTESTED_CSR => {
                    let b = decoder.bytes().unwrap();
                    decoded_csr.copy_from_slice(b);
                }
                CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB => {
                    let attr_map_len = decoder.map().unwrap().unwrap();
                    assert_eq!(attr_map_len, 1);
                    let tag = decoder.tag().unwrap();
                    assert_eq!(tag, minicbor::data::Tag::new(111));
                    let oid_bytes = decoder.bytes().unwrap();
                    assert_eq!(oid_bytes, oids::OCP_SECURITY_OID_KDA);
                    decoded_kda_bitfield = Some(decoder.u64().unwrap());
                }
                other => panic!("Unexpected CBOR claim key: {}", other),
            }
        }

        assert_eq!(decoded_nonce, nonce);
        assert_eq!(decoded_csr, MOCK_CSR);
        assert_eq!(decoded_kda_bitfield, Some(0x03));
    }

    #[test]
    fn test_keypair_inventory_roundtrip_decode() {
        let nonce = [0x7eu8; 32];
        let ldevid_attrs = [KeyAttributeEntry::ocp(0x03)];
        let fmc_attrs = [KeyAttributeEntry::ocp(0x13)];
        let rt_attrs = [KeyAttributeEntry::ocp(0x33)];

        let entries = [
            KeyPairInventoryEntry::new(1, &ldevid_attrs),
            KeyPairInventoryEntry::new(2, &fmc_attrs),
            KeyPairInventoryEntry::new(3, &rt_attrs),
        ];

        let claims = KeyPairInventoryClaims::with_nonce(&entries, &nonce).unwrap();
        let mut buffer = [0u8; 512];
        let len = {
            let mut encoder = CborEncoder::new(&mut buffer);
            claims.encode(&mut encoder).unwrap();
            encoder.len()
        };
        let encoded = &buffer[..len];

        let mut decoder = minicbor::Decoder::new(encoded);
        let map_len = decoder.map().unwrap().unwrap();
        assert_eq!(map_len, 2);

        let mut decoded_nonce = [0u8; 32];
        let mut decoded_entries = [(0u32, 0u64); 3];

        for _ in 0..map_len {
            let key = decoder.i64().unwrap();
            match key {
                CLAIM_KEY_NONCE => {
                    let b = decoder.bytes().unwrap();
                    decoded_nonce.copy_from_slice(b);
                }
                CLAIM_KEY_KEYPAIR_INVENTORY => {
                    let arr_len = decoder.array().unwrap().unwrap();
                    assert_eq!(arr_len, 3);
                    for i in 0..arr_len {
                        let entry_len = decoder.array().unwrap().unwrap();
                        assert_eq!(entry_len, 2);
                        let id = decoder.u32().unwrap();
                        let attr_map_len = decoder.map().unwrap().unwrap();
                        assert_eq!(attr_map_len, 1);
                        let tag = decoder.tag().unwrap();
                        assert_eq!(tag, minicbor::data::Tag::new(111));
                        let oid_bytes = decoder.bytes().unwrap();
                        assert_eq!(oid_bytes, oids::OCP_SECURITY_OID_KDA);
                        let bitfield = decoder.u64().unwrap();
                        decoded_entries[i as usize] = (id, bitfield);
                    }
                }
                other => panic!("Unexpected CBOR claim key: {}", other),
            }
        }

        assert_eq!(decoded_nonce, nonce);
        assert_eq!(decoded_entries, [(1, 0x03), (2, 0x13), (3, 0x33)]);
    }
}

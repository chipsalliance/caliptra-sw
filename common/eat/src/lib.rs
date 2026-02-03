// Licensed under the Apache-2.0 license
#![no_std]

//! OCP EAT (Entity Attestation Token) encoder library
//!
//! This library provides a no_std compatible implementation for encoding
//! OCP Profile Entity Attestation Tokens using CBOR and COSE Sign1.
//!
//! # Features
//!
//! - No standard library dependencies (`no_std` compatible)
//! - Type-safe structured evidence API
//! - CBOR encoding with minimal memory footprint
//! - P-384 ECDSA signature support via COSE Sign1
//! - Compile-time validation of token structure
//!
//! # Usage
//!
//! ```rust,no_run
//! use ocp_eat::{
//!     ConciseEvidenceMap, EnvironmentMap, ClassMap, MeasurementMap,
//!     MeasurementValue, MeasurementFormat, EvidenceTripleRecord, EvTriplesMap, ConciseEvidence
//! };
//!
//! // Create structured evidence
//! let measurements = [];
//! let evidence_triple = EvidenceTripleRecord {
//!     environment: EnvironmentMap {
//!         class: ClassMap {
//!             class_id: "example-device",
//!             vendor: Some("Example Corp"),
//!             model: Some("Device-v1.0"),
//!         },
//!     },
//!     measurements: &measurements,
//! };
//!
//! // Create a binding for the evidence triple array to avoid temporary value issues
//! let evidence_triple_array = [evidence_triple];
//! let ev_triples_map = EvTriplesMap {
//!     evidence_triples: Some(&evidence_triple_array),
//!     identity_triples: None,
//!     dependency_triples: None,
//!     membership_triples: None,
//!     coswid_triples: None,
//!     attest_key_triples: None,
//! };
//!
//! let evidence_map = ConciseEvidenceMap {
//!     ev_triples: ev_triples_map,
//!     evidence_id: None,
//!     profile: None,
//! };
//!
//! let evidence = ConciseEvidence::Map(evidence_map);
//!
//! // Create measurement format
//! let measurement_format = MeasurementFormat::new(&evidence);
//! ```

pub mod cbor;
pub mod claim_keys;
pub mod cose;
pub mod csr_eat;
pub mod error;
pub mod ocp_profile;

/// CBOR tags for EAT tokens (RFC 8949, RFC 8392)
pub mod cbor_tags {
    /// Self-described CBOR tag (RFC 8949)
    pub const SELF_DESCRIBED_CBOR: u64 = 55799;
    /// CBOR Web Token tag (RFC 8392)
    pub const CWT: u64 = 61;
}

// Re-export error types
pub use error::EatError;

// Re-export CBOR encoder and trait for custom encoding
pub use cbor::{CborEncodable, CborEncoder};

// Re-export standard EAT/CWT claim keys (RFC 8392, RFC 9711)
// These are shared across both OCP Profile EAT and CSR EAT
pub use claim_keys::*;

// Re-export COSE Sign1 signing infrastructure
// Used to create signed EAT tokens with protected/unprotected headers
pub use cose::{
    header_params,  // COSE header parameter constants (ALG, CONTENT_TYPE, KID, X5CHAIN)
    CoseHeaderPair, // Key-value pair for unprotected headers
    CoseSign1,      // COSE Sign1 encoder with default buffer
    CoseSign1WithBuffer, // COSE Sign1 encoder with custom buffer size
    ProtectedHeader, // Protected header builder
    DEFAULT_PROTECTED_HEADER_SIZE, // Default protected header buffer size (256 bytes)
};

// Re-export OCP Profile EAT types for device attestation
// Reference: https://opencomputeproject.github.io/Security/ietf-eat-profile/HEAD/
pub use ocp_profile::{
    // Evidence structures (RATS CoRIM format)
    ClassMap,           // Device class identification
    ConciseEvidence,    // Top-level evidence container (tagged or map)
    ConciseEvidenceMap, // Evidence map with triples
    CorimLocatorMap,    // CoRIM reference locator with optional thumbprint
    DebugStatus,        // Debug state enumeration
    DigestEntry,        // Cryptographic digest (algorithm + value)

    DloaType,             // Digital Letter of Approval
    EnvironmentMap,       // Environment description (class info)
    EvTriplesMap,         // Evidence triples collection
    EvidenceTripleRecord, // Single evidence triple (environment + measurements)

    // Measurement structures
    MeasurementFormat, // Measurement with content type
    MeasurementMap,    // Single measurement entry
    MeasurementValue,  // Measurement value with digests/raw values
    // OCP EAT claims and metadata
    OcpEatClaims, // Complete OCP EAT token payload
    PrivateClaim, // Custom private claims (keys < -65536)
};

// Re-export Envelope Signed CSR EAT types for provisioning workflows
// Reference: https://opencomputeproject.github.io/Security/device-identity-provisioning/
pub use csr_eat::{
    CsrEatClaims, // CSR EAT token payload with nonce and attributes
    TaggedOid,    // CBOR-tagged OID for key attributes
};

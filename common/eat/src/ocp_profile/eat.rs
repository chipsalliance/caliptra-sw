// Licensed under the Apache-2.0 license

// EAT (Entity Attestation Token) structures and encoding
use crate::cbor::{CborEncodable, CborEncoder};
use crate::claim_keys::*;
use crate::error::EatError;
use crate::ocp_profile::concise_evidence::ConciseEvidence;

// Test-only imports
#[cfg(test)]
#[allow(unused_imports)]
use crate::ocp_profile::concise_evidence::{
    ClassMap, ConciseEvidenceMap, DigestEntry, EnvironmentMap, EvTriplesMap, EvidenceTripleRecord,
    MeasurementMap, MeasurementValue, TaggedConciseEvidence,
};

// OCP Profile-specific private claim keys
const OCP_CLAIM_KEY_RIM_LOCATORS: i64 = -70001;

// CoAP content format for concise-evidence-map (application/ce+cbor)
const COAP_CONTENT_FORMAT_CONCISE_EV_MAP: u16 = 10571;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum DebugStatus {
    Disabled = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct MeasurementFormat<'a> {
    pub content_type: u16,                     // CoAP content format
    pub concise_evidence: ConciseEvidence<'a>, // Structured evidence (required)
}

impl<'a> MeasurementFormat<'a> {
    /// Create a new measurement format with structured concise evidence
    pub fn new(concise_evidence: &'a ConciseEvidence<'a>) -> Self {
        Self {
            content_type: COAP_CONTENT_FORMAT_CONCISE_EV_MAP,
            concise_evidence: *concise_evidence,
        }
    }

    /// Encode measurement format using a caller-provided scratch buffer
    pub fn encode(
        &self,
        encoder: &mut CborEncoder,
        evidence_scratch_buffer: &mut [u8],
    ) -> Result<(), EatError> {
        encoder.encode_array_header(2)?; // [content_type, content_format]
        encoder.encode_uint(self.content_type as u64)?;

        let mut evidence_encoder = CborEncoder::new(evidence_scratch_buffer);

        // Encode the structured concise evidence
        self.concise_evidence.encode(&mut evidence_encoder)?;
        let encoded_len = evidence_encoder.len();

        // Encode the structured concise evidence as a byte string
        let evidence_slice = evidence_scratch_buffer
            .get(..encoded_len)
            .ok_or(EatError::BufferTooSmall)?;
        encoder.encode_bytes(evidence_slice)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DloaType<'a> {
    pub endorsement_id: &'a str,
    pub locator: &'a str,
    pub platform_label: &'a str,
    pub application_label: Option<&'a str>,
}

impl CborEncodable for DloaType<'_> {
    /// Encode DLOA type
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        // DLOA is encoded as an array [registrar, platform_label, ?application_label]
        let array_len = if self.application_label.is_some() {
            3
        } else {
            2
        };
        encoder.encode_array_header(array_len)?;

        // dloa_registrar: general-uri (text string) - using endorsement_id as registrar
        encoder.encode_text(self.endorsement_id)?;

        // dloa_platform_label: text
        encoder.encode_text(self.platform_label)?;

        // dloa_application_label: text (optional)
        if let Some(app_label) = self.application_label {
            encoder.encode_text(app_label)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CorimLocatorMap<'a> {
    pub href: &'a str,
    pub thumbprint: Option<&'a [u8]>,
}

impl CborEncodable for CorimLocatorMap<'_> {
    /// Encode CoRIM locator map
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let entries = if self.thumbprint.is_some() { 2 } else { 1 };
        encoder.encode_map_header(entries)?;

        // Key 0: href (can be uri or [+ uri])
        encoder.encode_int(0)?;
        encoder.encode_text(self.href)?;

        // Key 1: thumbprint (optional)
        if let Some(thumbprint) = self.thumbprint {
            encoder.encode_int(1)?;
            encoder.encode_bytes(thumbprint)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PrivateClaim<'a> {
    pub key: i32,        // Must be < -65536
    pub value: &'a [u8], // Limited to 100 bytes
}

impl CborEncodable for PrivateClaim<'_> {
    /// Encode private claim
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_int(self.key as i64)?;
        encoder.encode_bytes(self.value)?;
        Ok(())
    }
}

/// OCP Profile EAT Claims
///
/// Payload structure for OCP Profile Entity Attestation Tokens.
/// Implements the OCP EAT profile specification for device attestation and identity.
///
/// Reference: [OCP Security IETF EAT Profile Specification]
/// (https://opencomputeproject.github.io/Security/ietf-eat-profile/HEAD/)
#[derive(Debug, Clone, Copy)]
pub struct OcpEatClaims<'a> {
    // Mandatory claims
    pub nonce: &'a [u8],                           // Nonce for freshness (key 10)
    pub dbgstat: DebugStatus,                      // Debug status (key 263)
    pub eat_profile: &'a str,                      // EAT Profile OID (key 265)
    pub measurements: &'a [MeasurementFormat<'a>], // Concise evidence (key 273)

    // Optional claims
    pub issuer: Option<&'a str>,           // iss claim (key 1)
    pub cti: Option<&'a [u8]>,             // CTI claim for token uniqueness (key 7)
    pub ueid: Option<&'a [u8]>,            // Unique Entity ID (key 256)
    pub sueid: Option<&'a [u8]>,           // Secure Unique Entity ID (key 257)
    pub oemid: Option<&'a [u8]>,           // OEM ID (key 258)
    pub hwmodel: Option<&'a [u8]>,         // Hardware model (key 259)
    pub uptime: Option<u64>,               // Uptime in seconds (key 261)
    pub bootcount: Option<u64>,            // Boot count (key 267)
    pub bootseed: Option<&'a [u8]>,        // Boot seed (key 268)
    pub dloas: Option<&'a [DloaType<'a>]>, // DLOA claim (key 269)
    pub rim_locators: Option<&'a [CorimLocatorMap<'a>]>, // RIM locators (key -70001)

    // Private claims (up to 5, keys < -65536)
    pub private_claims: &'a [PrivateClaim<'a>],
}

// Helper functions for creating common structures
impl<'a> OcpEatClaims<'a> {
    /// Default OCP EAT Profile OID as per OCP specification
    pub const DEFAULT_PROFILE_OID: &'static str = "1.3.6.1.4.1.42623.1.3";

    /// Create a new OcpEatClaims with mandatory fields
    pub fn new(
        nonce: &'a [u8],
        dbgstat: DebugStatus,
        measurements: &'a [MeasurementFormat<'a>],
    ) -> Self {
        Self {
            nonce,
            dbgstat,
            eat_profile: Self::DEFAULT_PROFILE_OID,
            measurements,
            issuer: None,
            cti: None,
            ueid: None,
            sueid: None,
            oemid: None,
            hwmodel: None,
            uptime: None,
            bootcount: None,
            bootseed: None,
            dloas: None,
            rim_locators: None,
            private_claims: &[],
        }
    }

    /// Validate that claims meet OCP profile requirements
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), EatError> {
        // Check mandatory fields
        if self.nonce.len() < 8 || self.nonce.len() > 64 {
            return Err(EatError::InvalidClaimSize);
        }

        if self.eat_profile.is_empty() {
            return Err(EatError::MissingMandatoryClaim);
        }

        if self.measurements.is_empty() {
            return Err(EatError::MissingMandatoryClaim);
        }

        // Validate optional claims size constraints
        if let Some(issuer) = self.issuer {
            if issuer.is_empty() || issuer.len() > 100 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        if let Some(cti) = self.cti {
            if cti.len() < 8 || cti.len() > 64 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        if let Some(ueid) = self.ueid {
            if ueid.len() < 7 || ueid.len() > 33 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        if let Some(hwmodel) = self.hwmodel {
            if hwmodel.is_empty() || hwmodel.len() > 32 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        if let Some(bootseed) = self.bootseed {
            if bootseed.len() < 32 || bootseed.len() > 64 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        // Validate private claims
        for private_claim in self.private_claims {
            if private_claim.key >= -65536 {
                return Err(EatError::InvalidData);
            }
            if private_claim.value.len() > 100 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        // Validate measurements format - structured evidence is always valid
        // No additional validation needed for structured concise evidence

        Ok(())
    }

    /// Calculate required buffer size for encoding (approximation)
    pub fn estimate_buffer_size(&self) -> usize {
        let mut size: usize = 0;

        // Base overhead for CBOR structure
        size = size.saturating_add(100); // Tags, headers, map structures

        // Mandatory claims
        size = size.saturating_add(self.nonce.len()).saturating_add(10);
        size = size
            .saturating_add(self.eat_profile.len())
            .saturating_add(10);
        size = size.saturating_add(10); // dbgstat

        // Measurements (estimated based on structured evidence)
        for _measurement in self.measurements {
            size = size.saturating_add(200); // Estimated size for structured concise evidence
        }

        // Optional claims
        if let Some(issuer) = self.issuer {
            size = size.saturating_add(issuer.len()).saturating_add(20);
        }
        if let Some(cti) = self.cti {
            size = size.saturating_add(cti.len()).saturating_add(10);
        }
        if let Some(ueid) = self.ueid {
            size = size.saturating_add(ueid.len()).saturating_add(10);
        }
        if let Some(sueid) = self.sueid {
            size = size.saturating_add(sueid.len()).saturating_add(10);
        }
        if let Some(oemid) = self.oemid {
            size = size.saturating_add(oemid.len()).saturating_add(10);
        }
        if let Some(hwmodel) = self.hwmodel {
            size = size.saturating_add(hwmodel.len()).saturating_add(10);
        }
        if let Some(bootseed) = self.bootseed {
            size = size.saturating_add(bootseed.len()).saturating_add(10);
        }
        if let Some(dloas) = self.dloas {
            for dloa in dloas {
                size = size
                    .saturating_add(dloa.endorsement_id.len())
                    .saturating_add(dloa.locator.len())
                    .saturating_add(20);
            }
        }
        if let Some(rim_locators) = self.rim_locators {
            for locator in rim_locators {
                size = size.saturating_add(locator.href.len()).saturating_add(20);
                if let Some(thumbprint) = locator.thumbprint {
                    size = size.saturating_add(thumbprint.len());
                }
            }
        }

        // Private claims
        for private_claim in self.private_claims {
            size = size
                .saturating_add(private_claim.value.len())
                .saturating_add(10);
        }

        // Add 20% safety margin using saturating arithmetic
        size.saturating_add(size / 5)
    }

    /// Count the number of map entries for CBOR encoding
    fn count_map_entries(&self) -> Result<u64, EatError> {
        let mut count: u64 = 4; // Mandatory claims: nonce, dbgstat, eat_profile, measurements

        // Count optional claims
        if self.issuer.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.cti.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.ueid.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.sueid.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.oemid.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.hwmodel.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.uptime.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.bootcount.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.bootseed.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.dloas.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.rim_locators.is_some() {
            count = count.checked_add(1).ok_or(EatError::EncodingError)?;
        }

        // Count private claims (safe cast since len() returns usize which fits in u64)
        count = count
            .checked_add(self.private_claims.len() as u64)
            .ok_or(EatError::EncodingError)?;

        Ok(count)
    }

    /// Encode debug status into CBOR encoder
    fn encode_debug_status(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_uint(self.dbgstat as u64)
    }

    /// Encode OCP EAT claims using a caller-provided evidence scratch buffer
    pub fn encode(
        &self,
        encoder: &mut CborEncoder,
        evidence_scratch_buffer: &mut [u8],
    ) -> Result<(), EatError> {
        let claim_count = self.count_map_entries()?;
        encoder.encode_map_header(claim_count)?;

        // Encode mandatory claims in deterministic order (by claim key)

        // Key 10: nonce
        encoder.encode_int(CLAIM_KEY_NONCE)?;
        encoder.encode_bytes(self.nonce)?;

        // Key 263: dbgstat
        encoder.encode_int(CLAIM_KEY_DBGSTAT)?;
        self.encode_debug_status(encoder)?;

        // Key 265: eat_profile
        encoder.encode_int(CLAIM_KEY_EAT_PROFILE)?;
        // Tag 111 is for OID as per CBOR spec
        encoder.encode_tag(111)?;
        encoder.encode_bytes(self.eat_profile.as_bytes())?;

        // Key 273: measurements
        encoder.encode_int(CLAIM_KEY_MEASUREMENTS)?;
        encoder.encode_array_header(self.measurements.len() as u64)?;
        for measurement in self.measurements {
            measurement.encode(encoder, evidence_scratch_buffer)?;
        }

        // Encode optional claims in deterministic order
        // Key 1: issuer
        if let Some(issuer) = self.issuer {
            encoder.encode_int(CLAIM_KEY_ISSUER)?;
            encoder.encode_text(issuer)?;
        }

        // Key 7: cti
        if let Some(cti) = self.cti {
            encoder.encode_int(CLAIM_KEY_CTI)?;
            encoder.encode_bytes(cti)?;
        }

        if let Some(ueid) = self.ueid {
            encoder.encode_int(CLAIM_KEY_UEID)?;
            encoder.encode_bytes(ueid)?;
        }

        if let Some(sueid) = self.sueid {
            encoder.encode_int(CLAIM_KEY_SUEID)?;
            encoder.encode_bytes(sueid)?;
        }

        if let Some(oemid) = self.oemid {
            encoder.encode_int(CLAIM_KEY_OEMID)?;
            encoder.encode_bytes(oemid)?;
        }

        if let Some(hwmodel) = self.hwmodel {
            encoder.encode_int(CLAIM_KEY_HWMODEL)?;
            encoder.encode_bytes(hwmodel)?;
        }

        if let Some(uptime) = self.uptime {
            encoder.encode_int(CLAIM_KEY_UPTIME)?;
            encoder.encode_uint(uptime)?;
        }

        if let Some(bootcount) = self.bootcount {
            encoder.encode_int(CLAIM_KEY_BOOTCOUNT)?;
            encoder.encode_uint(bootcount)?;
        }

        if let Some(bootseed) = self.bootseed {
            encoder.encode_int(CLAIM_KEY_BOOTSEED)?;
            encoder.encode_bytes(bootseed)?;
        }

        if let Some(dloas) = self.dloas {
            encoder.encode_int(CLAIM_KEY_DLOAS)?;
            encoder.encode_array_header(dloas.len() as u64)?;
            for dloa in dloas {
                dloa.encode(encoder)?;
            }
        }

        if let Some(rim_locators) = self.rim_locators {
            encoder.encode_int(OCP_CLAIM_KEY_RIM_LOCATORS)?;
            encoder.encode_array_header(rim_locators.len() as u64)?;
            for locator in rim_locators {
                locator.encode(encoder)?;
            }
        }

        // Encode private claims
        for private_claim in self.private_claims {
            private_claim.encode(encoder)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocp_profile::concise_evidence::*;

    #[test]
    fn test_debug_status() {
        assert_eq!(DebugStatus::Disabled as u8, 1);
    }

    #[test]
    fn test_dloa_type_encode_without_app_label() {
        let dloa = DloaType {
            endorsement_id: "https://example.com",
            locator: "loc1",
            platform_label: "platform1",
            application_label: None,
        };

        let mut buffer = [0u8; 128];
        let mut encoder = CborEncoder::new(&mut buffer);
        dloa.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size
        let array_header = CborEncoder::estimate_uint_size(2); // 2-element array
        let endorsement_id_size = CborEncoder::estimate_text_string_size(dloa.endorsement_id.len());
        let platform_label_size = CborEncoder::estimate_text_string_size(dloa.platform_label.len());

        let expected_size = array_header + endorsement_id_size + platform_label_size;
        assert_eq!(encoded_len, expected_size);

        // Verify array header
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Array, 2)
        );
    }

    #[test]
    fn test_dloa_type_encode_with_app_label() {
        let dloa = DloaType {
            endorsement_id: "https://example.com",
            locator: "loc1",
            platform_label: "platform1",
            application_label: Some("app1"),
        };

        let mut buffer = [0u8; 128];
        let mut encoder = CborEncoder::new(&mut buffer);
        dloa.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size
        let array_header = CborEncoder::estimate_uint_size(3); // 3-element array
        let endorsement_id_size = CborEncoder::estimate_text_string_size(dloa.endorsement_id.len());
        let platform_label_size = CborEncoder::estimate_text_string_size(dloa.platform_label.len());
        let app_label_size = CborEncoder::estimate_text_string_size("app1".len());

        let expected_size =
            array_header + endorsement_id_size + platform_label_size + app_label_size;
        assert_eq!(encoded_len, expected_size);

        // Verify array header
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Array, 3)
        );
    }

    #[test]
    fn test_corim_locator_map_without_thumbprint() {
        let locator = CorimLocatorMap {
            href: "https://example.com/rim",
            thumbprint: None,
        };

        let mut buffer = [0u8; 128];
        let mut encoder = CborEncoder::new(&mut buffer);
        locator.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size
        let map_header = CborEncoder::estimate_uint_size(1); // 1 entry
        let key_size = CborEncoder::estimate_int_size(0); // key 0
        let href_size = CborEncoder::estimate_text_string_size(locator.href.len());

        let expected_size = map_header + key_size + href_size;
        assert_eq!(encoded_len, expected_size);

        // Verify map header
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 1)
        );
    }

    #[test]
    fn test_corim_locator_map_with_thumbprint() {
        let thumbprint = [0xAB; 32];
        let locator = CorimLocatorMap {
            href: "https://example.com/rim",
            thumbprint: Some(&thumbprint),
        };

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);
        locator.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size
        let map_header = CborEncoder::estimate_uint_size(2); // 2 entries
        let key0_size = CborEncoder::estimate_int_size(0);
        let href_size = CborEncoder::estimate_text_string_size(locator.href.len());
        let key1_size = CborEncoder::estimate_int_size(1);
        let thumbprint_size = CborEncoder::estimate_bytes_string_size(thumbprint.len());

        let expected_size = map_header + key0_size + href_size + key1_size + thumbprint_size;
        assert_eq!(encoded_len, expected_size);

        // Verify map header
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 2)
        );
    }

    #[test]
    fn test_private_claim_encode() {
        let value = b"test-value";
        let claim = PrivateClaim { key: -70000, value };

        let mut buffer = [0u8; 64];
        let mut encoder = CborEncoder::new(&mut buffer);
        claim.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size
        let key_size = CborEncoder::estimate_int_size(claim.key as i64);
        let value_size = CborEncoder::estimate_bytes_string_size(value.len());

        let expected_size = key_size + value_size;
        assert_eq!(encoded_len, expected_size);
    }

    #[test]
    fn test_ocp_eat_claims_new() {
        let nonce = [0x01; 16];
        let measurements = [];

        let claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements);

        assert_eq!(claims.nonce, &nonce);
        assert_eq!(claims.eat_profile, OcpEatClaims::DEFAULT_PROFILE_OID);
        assert!(claims.issuer.is_none());
        assert!(claims.cti.is_none());
        assert_eq!(claims.private_claims.len(), 0);
    }

    #[test]
    fn test_ocp_eat_claims_validate_valid() {
        let nonce = [0x01; 16];
        let measurements = [];

        let claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements);

        // Empty measurements should fail validation
        assert_eq!(claims.validate(), Err(EatError::MissingMandatoryClaim));
    }

    #[test]
    fn test_ocp_eat_claims_validate_nonce_too_short() {
        let nonce = [0x01; 7]; // Too short (< 8)
        let measurements = [];

        let claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements);

        assert_eq!(claims.validate(), Err(EatError::InvalidClaimSize));
    }

    #[test]
    fn test_ocp_eat_claims_validate_nonce_too_long() {
        let nonce = [0x01; 65]; // Too long (> 64)
        let measurements = [];

        let claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements);

        assert_eq!(claims.validate(), Err(EatError::InvalidClaimSize));
    }

    #[test]
    fn test_ocp_eat_claims_validate_invalid_private_claim_key() {
        let nonce = [0x01; 16];
        // Need at least one measurement to pass that check
        let digest = [0xAB; 48];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];
        let measurement_value = MeasurementValue {
            version: None,
            svn: None,
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        };
        let measurement_map = MeasurementMap {
            key: 0,
            mval: measurement_value,
        };
        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.1234",
            vendor: Some("TestVendor"),
            model: Some("TestModel"),
        };
        let environment = EnvironmentMap { class: class_map };
        let measurements_array = [measurement_map];
        let evidence_triple = EvidenceTripleRecord {
            environment,
            measurements: &measurements_array,
        };
        let evidence_triples_array = [evidence_triple];
        let evidence_map = ConciseEvidenceMap {
            ev_triples: EvTriplesMap {
                evidence_triples: Some(&evidence_triples_array),
                identity_triples: None,
                dependency_triples: None,
                membership_triples: None,
                coswid_triples: None,
                attest_key_triples: None,
            },
            evidence_id: None,
            profile: None,
        };
        let measurement = MeasurementFormat {
            content_type: COAP_CONTENT_FORMAT_CONCISE_EV_MAP,
            concise_evidence: ConciseEvidence::Tagged(TaggedConciseEvidence {
                concise_evidence: evidence_map,
            }),
        };
        let measurements = [measurement];

        let private_claim = PrivateClaim {
            key: -65536, // Invalid: must be < -65536
            value: b"test",
        };

        let claims = OcpEatClaims {
            nonce: &nonce,
            dbgstat: DebugStatus::Disabled,
            eat_profile: OcpEatClaims::DEFAULT_PROFILE_OID,
            measurements: &measurements,
            issuer: None,
            cti: None,
            ueid: None,
            sueid: None,
            oemid: None,
            hwmodel: None,
            uptime: None,
            bootcount: None,
            bootseed: None,
            dloas: None,
            rim_locators: None,
            private_claims: &[private_claim],
        };

        assert_eq!(claims.validate(), Err(EatError::InvalidData));
    }

    #[test]
    fn test_ocp_eat_claims_validate_private_claim_value_too_large() {
        let nonce = [0x01; 16];
        // Need at least one measurement to pass that check
        let digest = [0xAB; 48];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];
        let measurement_value = MeasurementValue {
            version: None,
            svn: None,
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        };
        let measurement_map = MeasurementMap {
            key: 0,
            mval: measurement_value,
        };
        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.1234",
            vendor: Some("TestVendor"),
            model: Some("TestModel"),
        };
        let environment = EnvironmentMap { class: class_map };
        let measurements_array = [measurement_map];
        let evidence_triple = EvidenceTripleRecord {
            environment,
            measurements: &measurements_array,
        };
        let evidence_triples_array = [evidence_triple];
        let evidence_map = ConciseEvidenceMap {
            ev_triples: EvTriplesMap {
                evidence_triples: Some(&evidence_triples_array),
                identity_triples: None,
                dependency_triples: None,
                membership_triples: None,
                coswid_triples: None,
                attest_key_triples: None,
            },
            evidence_id: None,
            profile: None,
        };
        let measurement = MeasurementFormat {
            content_type: COAP_CONTENT_FORMAT_CONCISE_EV_MAP,
            concise_evidence: ConciseEvidence::Tagged(TaggedConciseEvidence {
                concise_evidence: evidence_map,
            }),
        };
        let measurements = [measurement];
        let large_value = [0xFF; 101]; // Too large (> 100)

        let private_claim = PrivateClaim {
            key: -70000,
            value: &large_value,
        };

        let claims = OcpEatClaims {
            nonce: &nonce,
            dbgstat: DebugStatus::Disabled,
            eat_profile: OcpEatClaims::DEFAULT_PROFILE_OID,
            measurements: &measurements,
            issuer: None,
            cti: None,
            ueid: None,
            sueid: None,
            oemid: None,
            hwmodel: None,
            uptime: None,
            bootcount: None,
            bootseed: None,
            dloas: None,
            rim_locators: None,
            private_claims: &[private_claim],
        };

        assert_eq!(claims.validate(), Err(EatError::InvalidClaimSize));
    }

    #[test]
    fn test_ocp_eat_claims_count_map_entries() {
        let nonce = [0x01; 16];
        let measurements = [];

        // Minimal claims
        let claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements);
        assert_eq!(claims.count_map_entries().unwrap(), 4); // nonce, dbgstat, eat_profile, measurements

        // With optional claims
        let claims_with_optional = OcpEatClaims {
            issuer: Some("issuer"),
            cti: Some(&[0x01; 16]),
            ueid: Some(&[0x02; 8]),
            ..claims
        };
        assert_eq!(claims_with_optional.count_map_entries().unwrap(), 7);
    }

    #[test]
    fn test_measurement_format_content_type() {
        // Test that measurement format has correct content type
        let digest = [0xAB; 48];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];

        let measurement_value = MeasurementValue {
            version: None,
            svn: None,
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        };

        let measurement_map = MeasurementMap {
            key: 0,
            mval: measurement_value,
        };

        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.1234",
            vendor: Some("TestVendor"),
            model: Some("TestModel"),
        };

        let environment = EnvironmentMap { class: class_map };

        let measurements_array = [measurement_map];
        let evidence_triple = EvidenceTripleRecord {
            environment,
            measurements: &measurements_array,
        };
        let evidence_triples_array = [evidence_triple];

        let evidence_map = ConciseEvidenceMap {
            ev_triples: EvTriplesMap {
                evidence_triples: Some(&evidence_triples_array),
                identity_triples: None,
                dependency_triples: None,
                membership_triples: None,
                coswid_triples: None,
                attest_key_triples: None,
            },
            evidence_id: None,
            profile: None,
        };

        let measurement = MeasurementFormat {
            content_type: COAP_CONTENT_FORMAT_CONCISE_EV_MAP,
            concise_evidence: ConciseEvidence::Tagged(TaggedConciseEvidence {
                concise_evidence: evidence_map,
            }),
        };

        assert_eq!(measurement.content_type, COAP_CONTENT_FORMAT_CONCISE_EV_MAP);
    }

    #[test]
    fn test_ocp_eat_claims_estimate_buffer_size() {
        let nonce = [0x01; 16];
        let measurements = [];

        let claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements);

        let estimated_size = claims.estimate_buffer_size();
        assert!(estimated_size > 0);

        // Estimate should include 20% safety margin
        assert!(estimated_size > 100); // Should be larger than base overhead
    }
}

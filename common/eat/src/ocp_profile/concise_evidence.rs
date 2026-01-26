// Licensed under the Apache-2.0 license

// Concise Evidence structures and encoding for RATS CoRIM compliance
use crate::cbor::{CborEncodable, CborEncoder};
use crate::error::EatError;

// CBOR tag for tagged concise evidence
const CBOR_TAG_CONCISE_EVIDENCE: u64 = 571;

// Concise Evidence Map keys (RATS CoRIM)
pub const CE_EV_TRIPLES: i32 = 0;
pub const CE_EVIDENCE_ID: i32 = 1;
pub const CE_PROFILE: i32 = 2;

// Evidence Triples Map keys
pub const CE_EVIDENCE_TRIPLES: i32 = 0;
pub const CE_IDENTITY_TRIPLES: i32 = 1;
pub const CE_DEPENDENCY_TRIPLES: i32 = 2;
pub const CE_MEMBERSHIP_TRIPLES: i32 = 3;
pub const CE_COSWID_TRIPLES: i32 = 4;
pub const CE_ATTEST_KEY_TRIPLES: i32 = 5;

// CoSWID Evidence Map keys
pub const CE_COSWID_TAG_ID: i32 = 0;
pub const CE_COSWID_EVIDENCE: i32 = 1;
pub const CE_AUTHORIZED_BY: i32 = 2;

#[derive(Debug, Clone, Copy)]
pub struct DigestEntry<'a> {
    pub alg_id: i32,     // Algorithm identifier (e.g., SHA-256 = -16)
    pub value: &'a [u8], // Digest value
}

impl CborEncodable for DigestEntry<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?; // [alg_id, value]
        encoder.encode_int(self.alg_id as i64)?;
        encoder.encode_bytes(self.value)?;
        Ok(())
    }
}

// Integrity register identifier choice (uint or text)
#[derive(Debug, Clone, Copy)]
pub enum IntegrityRegisterIdChoice<'a> {
    Uint(u64),
    Text(&'a str),
}

impl CborEncodable for IntegrityRegisterIdChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            IntegrityRegisterIdChoice::Uint(value) => encoder.encode_uint(*value),
            IntegrityRegisterIdChoice::Text(text) => encoder.encode_text(text),
        }
    }
}

// Integrity register entry
#[derive(Debug, Clone, Copy)]
pub struct IntegrityRegisterEntry<'a> {
    pub id: IntegrityRegisterIdChoice<'a>,
    pub digests: &'a [DigestEntry<'a>], // digests-type
}

impl CborEncodable for IntegrityRegisterEntry<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        // Encode the key (register ID)
        self.id.encode(encoder)?;

        // Encode the value (digests array)
        encoder.encode_array_header(self.digests.len() as u64)?;
        for digest in self.digests {
            digest.encode(encoder)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MeasurementValue<'a> {
    pub version: Option<&'a str>,
    pub svn: Option<u64>, // Security Version Number
    pub digests: Option<&'a [DigestEntry<'a>]>,
    pub integrity_registers: Option<&'a [IntegrityRegisterEntry<'a>]>, // Map of register ID -> digests
    pub raw_value: Option<&'a [u8]>,
    pub raw_value_mask: Option<&'a [u8]>,
}

impl CborEncodable for MeasurementValue<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut map_entries = 0u64;

        // Count entries
        if self.version.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.svn.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.digests.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.integrity_registers.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.raw_value.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.raw_value_mask.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }

        encoder.encode_map_header(map_entries)?;

        // Encode entries in deterministic order (sorted by numeric key)
        // Key 0: version
        if let Some(version) = self.version {
            encoder.encode_int(0)?;
            encoder.encode_text(version)?;
        }

        // Key 1: svn
        if let Some(svn) = self.svn {
            encoder.encode_int(1)?;
            encoder.encode_uint(svn)?;
        }

        // Key 2: digests
        if let Some(digests) = self.digests {
            encoder.encode_int(2)?;
            encoder.encode_array_header(digests.len() as u64)?;
            for digest in digests {
                digest.encode(encoder)?;
            }
        }

        // Key 4: raw-value
        if let Some(raw_value) = self.raw_value {
            encoder.encode_int(4)?;
            encoder.encode_bytes(raw_value)?;
        }

        // Key 5: raw-value-mask (deprecated but still supported)
        if let Some(raw_mask) = self.raw_value_mask {
            encoder.encode_int(5)?;
            encoder.encode_bytes(raw_mask)?;
        }

        // Key 14: integrity-registers
        if let Some(registers) = self.integrity_registers {
            encoder.encode_int(14)?;
            // Encode as map: { + integrity-register-id-type-choice => digests-type }
            encoder.encode_map_header(registers.len() as u64)?;
            for register in registers {
                register.encode(encoder)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MeasurementMap<'a> {
    pub key: u64, // Measurement key/identifier
    pub mval: MeasurementValue<'a>,
}

impl CborEncodable for MeasurementMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_map_header(2)?; // key and mval

        // Key 0: mkey (measured element type)
        encoder.encode_int(0)?;
        encoder.encode_uint(self.key)?;

        // Key 1: mval (measurement values)
        encoder.encode_int(1)?;
        self.mval.encode(encoder)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClassMap<'a> {
    pub class_id: &'a str,
    pub vendor: Option<&'a str>,
    pub model: Option<&'a str>,
}

impl CborEncodable for ClassMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut entries = 1u64; // class-id is mandatory
        if self.vendor.is_some() {
            entries = entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.model.is_some() {
            entries = entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }

        encoder.encode_map_header(entries)?;

        // Key 0: class-id (mandatory)
        encoder.encode_int(0)?;
        // For now, treat class_id as a text string that should be encoded as tagged OID
        // In a real implementation, you'd parse the OID string and encode it properly
        // Tag 111 is for OID as per CBOR spec
        encoder.encode_tag(111)?;
        encoder.encode_bytes(self.class_id.as_bytes())?;

        // Key 1: vendor (optional)
        if let Some(vendor) = self.vendor {
            encoder.encode_int(1)?;
            encoder.encode_text(vendor)?;
        }

        // Key 2: model (optional)
        if let Some(model) = self.model {
            encoder.encode_int(2)?;
            encoder.encode_text(model)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EnvironmentMap<'a> {
    pub class: ClassMap<'a>,
}

impl CborEncodable for EnvironmentMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_map_header(1)?; // Only class for now
                                       // Key 0: class
        encoder.encode_int(0)?;
        self.class.encode(encoder)?;
        Ok(())
    }
}

// Evidence identifier type choice
#[derive(Debug, Clone, Copy)]
pub enum EvidenceIdTypeChoice<'a> {
    TaggedUuid(&'a [u8]),
}

impl CborEncodable for EvidenceIdTypeChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            EvidenceIdTypeChoice::TaggedUuid(uuid) => {
                // Encode tagged UUID (needs proper tag)
                encoder.encode_bytes(uuid)
            }
        }
    }
}

// Profile type choice
#[derive(Debug, Clone, Copy)]
pub enum ProfileTypeChoice<'a> {
    Uri(&'a str),
    Oid(&'a str),
}

impl CborEncodable for ProfileTypeChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            ProfileTypeChoice::Uri(uri) => encoder.encode_text(uri),
            ProfileTypeChoice::Oid(oid) => {
                encoder.encode_tag(111)?; // OID tag
                encoder.encode_text(oid)
            }
        }
    }
}

// Domain type choice for dependencies and memberships
#[derive(Debug, Clone, Copy)]
pub enum DomainTypeChoice<'a> {
    Uuid(&'a [u8]),
    Uri(&'a str),
}

impl CborEncodable for DomainTypeChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            DomainTypeChoice::Uuid(uuid) => encoder.encode_bytes(uuid),
            DomainTypeChoice::Uri(uri) => encoder.encode_text(uri),
        }
    }
}

// Crypto key type choice for identity and attest key triples
#[derive(Debug, Clone, Copy)]
pub enum CryptoKeyTypeChoice<'a> {
    PublicKey(&'a [u8]),
    KeyId(&'a [u8]),
}

impl CborEncodable for CryptoKeyTypeChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            CryptoKeyTypeChoice::PublicKey(key_bytes) => encoder.encode_bytes(key_bytes),
            CryptoKeyTypeChoice::KeyId(key_id) => encoder.encode_bytes(key_id),
        }
    }
}

// Evidence triple record: [environment-map, [+ measurement-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvidenceTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub measurements: &'a [MeasurementMap<'a>],
}

impl CborEncodable for EvidenceTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Single environment map
        self.environment.encode(encoder)?;

        // Measurements array
        encoder.encode_array_header(self.measurements.len() as u64)?;
        for measurement in self.measurements {
            measurement.encode(encoder)?;
        }

        Ok(())
    }
}

// Identity triple record: [environment-map, [+ crypto-key]]
#[derive(Debug, Clone, Copy)]
pub struct EvIdentityTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub crypto_keys: &'a [CryptoKeyTypeChoice<'a>],
}

impl CborEncodable for EvIdentityTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Environment map
        self.environment.encode(encoder)?;

        // Crypto keys array
        encoder.encode_array_header(self.crypto_keys.len() as u64)?;
        for key in self.crypto_keys {
            key.encode(encoder)?;
        }

        Ok(())
    }
}

// Attest key triple record: [environment-map, [+ crypto-key]]
#[derive(Debug, Clone, Copy)]
pub struct EvAttestKeyTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub crypto_keys: &'a [CryptoKeyTypeChoice<'a>],
}

impl CborEncodable for EvAttestKeyTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Environment map
        self.environment.encode(encoder)?;

        // Crypto keys array
        encoder.encode_array_header(self.crypto_keys.len() as u64)?;
        for key in self.crypto_keys {
            key.encode(encoder)?;
        }

        Ok(())
    }
}

// Dependency triple record: [domain, [+ domain]]
#[derive(Debug, Clone, Copy)]
pub struct EvDependencyTripleRecord<'a> {
    pub domain: DomainTypeChoice<'a>,
    pub dependencies: &'a [DomainTypeChoice<'a>],
}

impl CborEncodable for EvDependencyTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Domain
        self.domain.encode(encoder)?;

        // Dependencies array
        encoder.encode_array_header(self.dependencies.len() as u64)?;
        for dep in self.dependencies {
            dep.encode(encoder)?;
        }

        Ok(())
    }
}

// Membership triple record: [domain, [+ environment-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvMembershipTripleRecord<'a> {
    pub domain: DomainTypeChoice<'a>,
    pub environments: &'a [EnvironmentMap<'a>],
}

impl CborEncodable for EvMembershipTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Domain
        self.domain.encode(encoder)?;

        // Environments array
        encoder.encode_array_header(self.environments.len() as u64)?;
        for env in self.environments {
            env.encode(encoder)?;
        }

        Ok(())
    }
}

// CoSWID evidence map
#[derive(Debug, Clone, Copy)]
pub struct EvCoswidEvidenceMap<'a> {
    pub coswid_tag_id: Option<&'a [u8]>,
    pub coswid_evidence: &'a [u8],
    pub authorized_by: Option<&'a [&'a CryptoKeyTypeChoice<'a>]>,
}

impl CborEncodable for EvCoswidEvidenceMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut map_entries = 1u64; // coswid_evidence is mandatory
        if self.coswid_tag_id.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.authorized_by.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }

        encoder.encode_map_header(map_entries)?;

        // Key 0: coswid-tag-id (optional)
        if let Some(tag_id) = self.coswid_tag_id {
            encoder.encode_int(CE_COSWID_TAG_ID as i64)?;
            encoder.encode_bytes(tag_id)?;
        }

        // Key 1: coswid-evidence (mandatory)
        encoder.encode_int(CE_COSWID_EVIDENCE as i64)?;
        encoder.encode_bytes(self.coswid_evidence)?;

        // Key 2: authorized-by (optional)
        if let Some(authorized_by) = self.authorized_by {
            encoder.encode_int(CE_AUTHORIZED_BY as i64)?;
            encoder.encode_array_header(authorized_by.len() as u64)?;
            for key in authorized_by {
                key.encode(encoder)?;
            }
        }

        Ok(())
    }
}

// CoSWID triple record: [environment-map, [+ ev-coswid-evidence-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvCoswidTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub coswid_evidence: &'a [EvCoswidEvidenceMap<'a>],
}

impl CborEncodable for EvCoswidTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Environment map
        self.environment.encode(encoder)?;

        // CoSWID evidence array
        encoder.encode_array_header(self.coswid_evidence.len() as u64)?;
        for evidence in self.coswid_evidence {
            evidence.encode(encoder)?;
        }

        Ok(())
    }
}

// Evidence triples map
#[derive(Debug, Clone, Copy)]
pub struct EvTriplesMap<'a> {
    pub evidence_triples: Option<&'a [EvidenceTripleRecord<'a>]>, // key 0
    pub identity_triples: Option<&'a [EvIdentityTripleRecord<'a>]>, // key 1
    pub dependency_triples: Option<&'a [EvDependencyTripleRecord<'a>]>, // key 2
    pub membership_triples: Option<&'a [EvMembershipTripleRecord<'a>]>, // key 3
    pub coswid_triples: Option<&'a [EvCoswidTripleRecord<'a>]>,   // key 4
    pub attest_key_triples: Option<&'a [EvAttestKeyTripleRecord<'a>]>, // key 5
}

impl CborEncodable for EvTriplesMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut map_entries = 0u64;
        if self.evidence_triples.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.identity_triples.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.dependency_triples.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.membership_triples.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.coswid_triples.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.attest_key_triples.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }

        encoder.encode_map_header(map_entries)?;

        // Key 0: evidence-triples
        if let Some(evidence_triples) = self.evidence_triples {
            encoder.encode_int(CE_EVIDENCE_TRIPLES as i64)?;
            encoder.encode_array_header(evidence_triples.len() as u64)?;
            for triple in evidence_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 1: identity-triples
        if let Some(identity_triples) = self.identity_triples {
            encoder.encode_int(CE_IDENTITY_TRIPLES as i64)?;
            encoder.encode_array_header(identity_triples.len() as u64)?;
            for triple in identity_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 2: dependency-triples
        if let Some(dependency_triples) = self.dependency_triples {
            encoder.encode_int(CE_DEPENDENCY_TRIPLES as i64)?;
            encoder.encode_array_header(dependency_triples.len() as u64)?;
            for triple in dependency_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 3: membership-triples
        if let Some(membership_triples) = self.membership_triples {
            encoder.encode_int(CE_MEMBERSHIP_TRIPLES as i64)?;
            encoder.encode_array_header(membership_triples.len() as u64)?;
            for triple in membership_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 4: coswid-triples
        if let Some(coswid_triples) = self.coswid_triples {
            encoder.encode_int(CE_COSWID_TRIPLES as i64)?;
            encoder.encode_array_header(coswid_triples.len() as u64)?;
            for triple in coswid_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 5: attest-key-triples
        if let Some(attest_key_triples) = self.attest_key_triples {
            encoder.encode_int(CE_ATTEST_KEY_TRIPLES as i64)?;
            encoder.encode_array_header(attest_key_triples.len() as u64)?;
            for triple in attest_key_triples {
                triple.encode(encoder)?;
            }
        }

        Ok(())
    }
}

// Concise evidence map
#[derive(Debug, Clone, Copy)]
pub struct ConciseEvidenceMap<'a> {
    pub ev_triples: EvTriplesMap<'a>, // key 0 (mandatory)
    pub evidence_id: Option<EvidenceIdTypeChoice<'a>>, // key 1
    pub profile: Option<ProfileTypeChoice<'a>>, // key 2
}

impl CborEncodable for ConciseEvidenceMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut map_entries = 1u64; // ev_triples is mandatory
        if self.evidence_id.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }
        if self.profile.is_some() {
            map_entries = map_entries.checked_add(1).ok_or(EatError::EncodingError)?;
        }

        encoder.encode_map_header(map_entries)?;

        // Key 0: ev-triples (mandatory)
        encoder.encode_int(CE_EV_TRIPLES as i64)?;
        self.ev_triples.encode(encoder)?;

        // Key 1: evidence-id (optional)
        if let Some(evidence_id) = &self.evidence_id {
            encoder.encode_int(CE_EVIDENCE_ID as i64)?;
            evidence_id.encode(encoder)?;
        }

        // Key 2: profile (optional)
        if let Some(profile) = &self.profile {
            encoder.encode_int(CE_PROFILE as i64)?;
            profile.encode(encoder)?;
        }

        Ok(())
    }
}

// Tagged concise evidence (CBOR tag 571)
#[derive(Debug, Clone, Copy)]
pub struct TaggedConciseEvidence<'a> {
    pub concise_evidence: ConciseEvidenceMap<'a>,
}

// Concise evidence choice
#[derive(Debug, Clone, Copy)]
pub enum ConciseEvidence<'a> {
    Map(ConciseEvidenceMap<'a>),
    Tagged(TaggedConciseEvidence<'a>),
}

impl CborEncodable for ConciseEvidence<'_> {
    /// Encode concise evidence (choice between map and tagged)
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            ConciseEvidence::Map(map) => map.encode(encoder),
            ConciseEvidence::Tagged(tagged) => {
                encoder.encode_tag(CBOR_TAG_CONCISE_EVIDENCE)?;
                tagged.concise_evidence.encode(encoder)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::CborEncoder;

    #[test]
    fn test_digest_entry_encode() {
        let digest = [0xAB; 48];
        let entry = DigestEntry {
            alg_id: -16, // SHA-384
            value: &digest,
        };

        let mut buffer = [0u8; 128];
        let mut encoder = CborEncoder::new(&mut buffer);
        entry.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: array(2) + int(-16) + bytes(48)
        let array_header = CborEncoder::estimate_uint_size(2);
        let alg_id_size = CborEncoder::estimate_int_size(-16);
        let value_size = CborEncoder::estimate_bytes_string_size(48);

        let expected_size = array_header + alg_id_size + value_size;
        assert_eq!(encoded_len, expected_size);

        // Verify array header
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Array, 2)
        );
    }

    #[test]
    fn test_integrity_register_id_choice_uint() {
        let id = IntegrityRegisterIdChoice::Uint(42);

        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);
        id.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();
        let expected_size = CborEncoder::estimate_uint_size(42);
        assert_eq!(encoded_len, expected_size);
    }

    #[test]
    fn test_integrity_register_id_choice_text() {
        let id = IntegrityRegisterIdChoice::Text("register-1");

        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);
        id.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();
        let expected_size = CborEncoder::estimate_text_string_size("register-1".len());
        assert_eq!(encoded_len, expected_size);
    }

    #[test]
    fn test_measurement_value_with_digests() {
        let digest = [0xCD; 32];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];

        let measurement = MeasurementValue {
            version: None,
            svn: None,
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        };

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);
        measurement.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: map(1) + key(2) + array(1) + digest_entry
        let expected_size = CborEncoder::estimate_uint_size(1) + // map header
                           CborEncoder::estimate_uint_size(2) + // key 2 for digests
                           CborEncoder::estimate_uint_size(1) + // array header
                           CborEncoder::estimate_uint_size(2) + // digest array header
                           CborEncoder::estimate_int_size(-16) + // alg_id
                           CborEncoder::estimate_bytes_string_size(32); // digest value
        assert_eq!(encoded_len, expected_size);

        // Verify map header (1 entry for digests)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 1)
        );
    }

    #[test]
    fn test_measurement_value_with_all_fields() {
        let digest = [0xEF; 32];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];
        let raw_value = [0x12; 16];
        let raw_mask = [0xFF; 16];

        let measurement = MeasurementValue {
            version: Some("1.0.0"),
            svn: Some(5),
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: Some(&raw_value),
            raw_value_mask: Some(&raw_mask),
        };

        let mut buffer = [0u8; 512];
        let mut encoder = CborEncoder::new(&mut buffer);
        measurement.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: map(5) + version + svn + digests + raw_value + raw_value_mask
        let expected_size = CborEncoder::estimate_uint_size(5) + // map header
                           CborEncoder::estimate_uint_size(0) + CborEncoder::estimate_text_string_size(5) + // version
                           CborEncoder::estimate_uint_size(1) + CborEncoder::estimate_uint_size(5) + // svn
                           CborEncoder::estimate_uint_size(2) + CborEncoder::estimate_uint_size(1) + // digests key + array
                           CborEncoder::estimate_uint_size(2) + CborEncoder::estimate_int_size(-16) + CborEncoder::estimate_bytes_string_size(32) + // digest entry
                           CborEncoder::estimate_uint_size(4) + CborEncoder::estimate_bytes_string_size(16) + // raw_value
                           CborEncoder::estimate_uint_size(5) + CborEncoder::estimate_bytes_string_size(16); // raw_value_mask
        assert_eq!(encoded_len, expected_size);

        // Verify map header (5 entries)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 5)
        );
    }

    #[test]
    fn test_measurement_map_encode() {
        let digest = [0x11; 48];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];

        let measurement_value = MeasurementValue {
            version: None,
            svn: Some(10),
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        };

        let measurement_map = MeasurementMap {
            key: 0,
            mval: measurement_value,
        };

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);
        measurement_map
            .encode(&mut encoder)
            .expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: map(2) + mkey + mval
        let expected_size = CborEncoder::estimate_uint_size(2) + // map header
                           CborEncoder::estimate_uint_size(0) + CborEncoder::estimate_uint_size(0) + // key 0 + mkey value
                           CborEncoder::estimate_uint_size(1) + // key 1
                           CborEncoder::estimate_uint_size(2) + // mval map header
                           CborEncoder::estimate_uint_size(1) + CborEncoder::estimate_uint_size(10) + // svn
                           CborEncoder::estimate_uint_size(2) + CborEncoder::estimate_uint_size(1) + // digests key + array
                           CborEncoder::estimate_uint_size(2) + CborEncoder::estimate_int_size(-16) + CborEncoder::estimate_bytes_string_size(48); // digest entry
        assert_eq!(encoded_len, expected_size);

        // Verify map header (2 entries: key=0 for mkey, key=1 for mval)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 2)
        );
    }

    #[test]
    fn test_class_map_minimal() {
        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.9999",
            vendor: None,
            model: None,
        };

        let mut buffer = [0u8; 128];
        let mut encoder = CborEncoder::new(&mut buffer);
        class_map.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: map(1) + key(0) + tag(111) + class_id
        let class_id_bytes = "1.3.6.1.4.1.9999".as_bytes();
        let expected_size = CborEncoder::estimate_uint_size(1) + // map header
                           CborEncoder::estimate_uint_size(0) + // key 0
                           CborEncoder::estimate_uint_size(111) + // tag 111
                           CborEncoder::estimate_bytes_string_size(class_id_bytes.len()); // class_id as bytes
        assert_eq!(encoded_len, expected_size);

        // Verify map header (1 entry for class_id only)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 1)
        );
    }

    #[test]
    fn test_class_map_complete() {
        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.9999",
            vendor: Some("ACME Corp"),
            model: Some("Model X"),
        };

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);
        class_map.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: map(3) + class_id + vendor + model
        let class_id_bytes = "1.3.6.1.4.1.9999".as_bytes();
        let expected_size = CborEncoder::estimate_uint_size(3) + // map header
                           CborEncoder::estimate_uint_size(0) + CborEncoder::estimate_uint_size(111) + CborEncoder::estimate_bytes_string_size(class_id_bytes.len()) + // class_id
                           CborEncoder::estimate_uint_size(1) + CborEncoder::estimate_text_string_size(9) + // vendor
                           CborEncoder::estimate_uint_size(2) + CborEncoder::estimate_text_string_size(7); // model
        assert_eq!(encoded_len, expected_size);

        // Verify map header (3 entries)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 3)
        );
    }

    #[test]
    fn test_environment_map_encode() {
        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.8888",
            vendor: Some("Vendor Inc"),
            model: None,
        };

        let environment = EnvironmentMap { class: class_map };

        let mut buffer = [0u8; 256];
        let mut encoder = CborEncoder::new(&mut buffer);
        environment.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: map(1) + key(0) + class_map
        let class_id_bytes = "1.3.6.1.4.1.8888".as_bytes();
        let expected_size = CborEncoder::estimate_uint_size(1) + // env map header
                           CborEncoder::estimate_uint_size(0) + // key 0
                           CborEncoder::estimate_uint_size(2) + // class map header (2 entries)
                           CborEncoder::estimate_uint_size(0) + CborEncoder::estimate_uint_size(111) + CborEncoder::estimate_bytes_string_size(class_id_bytes.len()) + // class_id
                           CborEncoder::estimate_uint_size(1) + CborEncoder::estimate_text_string_size(10); // vendor
        assert_eq!(encoded_len, expected_size);

        // Verify map header (1 entry for class)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 1)
        );
    }

    #[test]
    fn test_evidence_triple_record() {
        let digest = [0x22; 32];
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
            key: 1,
            mval: measurement_value,
        };
        let measurements_array = [measurement_map];

        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.7777",
            vendor: Some("Test Vendor"),
            model: Some("Test Model"),
        };

        let environment = EnvironmentMap { class: class_map };

        let evidence_triple = EvidenceTripleRecord {
            environment,
            measurements: &measurements_array,
        };

        let mut buffer = [0u8; 512];
        let mut encoder = CborEncoder::new(&mut buffer);
        evidence_triple
            .encode(&mut encoder)
            .expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: array(2) + environment + measurements_array
        let class_id_bytes = "1.3.6.1.4.1.7777".as_bytes();
        let expected_size = CborEncoder::estimate_uint_size(2) + // triple array header
                           CborEncoder::estimate_uint_size(1) + CborEncoder::estimate_uint_size(0) + // env map
                           CborEncoder::estimate_uint_size(3) + // class map header (3 entries)
                           CborEncoder::estimate_uint_size(0) + CborEncoder::estimate_uint_size(111) + CborEncoder::estimate_bytes_string_size(class_id_bytes.len()) + // class_id
                           CborEncoder::estimate_uint_size(1) + CborEncoder::estimate_text_string_size(11) + // vendor
                           CborEncoder::estimate_uint_size(2) + CborEncoder::estimate_text_string_size(10) + // model
                           CborEncoder::estimate_uint_size(1) + // measurements array header
                           CborEncoder::estimate_uint_size(2) + // measurement map header
                           CborEncoder::estimate_uint_size(0) + CborEncoder::estimate_uint_size(1) + // mkey
                           CborEncoder::estimate_uint_size(1) + // key 1
                           CborEncoder::estimate_uint_size(1) + // mval map header
                           CborEncoder::estimate_uint_size(2) + CborEncoder::estimate_uint_size(1) + // digests key + array
                           CborEncoder::estimate_uint_size(2) + CborEncoder::estimate_int_size(-16) + CborEncoder::estimate_bytes_string_size(32); // digest
        assert_eq!(encoded_len, expected_size);

        // Verify array header (2 elements: environment, measurements)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Array, 2)
        );
    }

    #[test]
    fn test_ev_triples_map_minimal() {
        let ev_triples = EvTriplesMap {
            evidence_triples: None,
            identity_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            attest_key_triples: None,
        };

        let mut buffer = [0u8; 32];
        let mut encoder = CborEncoder::new(&mut buffer);
        ev_triples.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // Calculate expected size: empty map
        let expected_size = CborEncoder::estimate_uint_size(0); // map header with 0 entries
        assert_eq!(encoded_len, expected_size);

        // Verify map header (0 entries)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 0)
        );
    }

    #[test]
    fn test_ev_triples_map_with_evidence() {
        let digest = [0x33; 48];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];

        let measurement_value = MeasurementValue {
            version: Some("2.0"),
            svn: None,
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        };

        let measurement_map = MeasurementMap {
            key: 2,
            mval: measurement_value,
        };
        let measurements_array = [measurement_map];

        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.6666",
            vendor: None,
            model: None,
        };

        let environment = EnvironmentMap { class: class_map };

        let evidence_triple = EvidenceTripleRecord {
            environment,
            measurements: &measurements_array,
        };
        let evidence_triples_array = [evidence_triple];

        let ev_triples = EvTriplesMap {
            evidence_triples: Some(&evidence_triples_array),
            identity_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            attest_key_triples: None,
        };

        let mut buffer = [0u8; 1024];
        let mut encoder = CborEncoder::new(&mut buffer);
        ev_triples.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // This is a complex nested structure, verify it encodes successfully
        assert!(encoded_len > 0);

        // Verify map header (1 entry for evidence_triples)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 1)
        );
    }

    #[test]
    fn test_concise_evidence_map_encode() {
        let digest = [0x44; 32];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];

        let measurement_value = MeasurementValue {
            version: None,
            svn: Some(3),
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        };

        let measurement_map = MeasurementMap {
            key: 0,
            mval: measurement_value,
        };
        let measurements_array = [measurement_map];

        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.5555",
            vendor: Some("Example Vendor"),
            model: Some("Example Model"),
        };

        let environment = EnvironmentMap { class: class_map };

        let evidence_triple = EvidenceTripleRecord {
            environment,
            measurements: &measurements_array,
        };
        let evidence_triples_array = [evidence_triple];

        let ev_triples = EvTriplesMap {
            evidence_triples: Some(&evidence_triples_array),
            identity_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            attest_key_triples: None,
        };

        let evidence_map = ConciseEvidenceMap {
            ev_triples,
            evidence_id: None,
            profile: None,
        };

        let mut buffer = [0u8; 1024];
        let mut encoder = CborEncoder::new(&mut buffer);
        evidence_map.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();

        // This is a complex nested structure, verify it encodes successfully
        assert!(encoded_len > 0);

        // Verify map header (1 entry for ev_triples)
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 1)
        );
    }

    #[test]
    fn test_concise_evidence_map_variant() {
        let digest = [0x55; 48];
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
        let measurements_array = [measurement_map];

        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.4444",
            vendor: None,
            model: None,
        };

        let environment = EnvironmentMap { class: class_map };

        let evidence_triple = EvidenceTripleRecord {
            environment,
            measurements: &measurements_array,
        };
        let evidence_triples_array = [evidence_triple];

        let ev_triples = EvTriplesMap {
            evidence_triples: Some(&evidence_triples_array),
            identity_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            attest_key_triples: None,
        };

        let evidence_map = ConciseEvidenceMap {
            ev_triples,
            evidence_id: None,
            profile: None,
        };

        let concise_evidence = ConciseEvidence::Map(evidence_map);

        let mut buffer = [0u8; 1024];
        let mut encoder = CborEncoder::new(&mut buffer);
        concise_evidence
            .encode(&mut encoder)
            .expect("Encoding failed");

        let encoded_len = encoder.len();

        // This is a complex nested structure, verify it encodes successfully
        assert!(encoded_len > 0);

        // Map variant should not have a tag
        assert_eq!(
            buffer[0],
            crate::cbor::cbor_initial_byte(crate::cbor::MajorType::Map, 1)
        );
    }

    #[test]
    fn test_concise_evidence_tagged_variant() {
        let digest = [0x66; 32];
        let digest_entry = DigestEntry {
            alg_id: -16,
            value: &digest,
        };
        let digests_array = [digest_entry];

        let measurement_value = MeasurementValue {
            version: Some("3.0"),
            svn: Some(7),
            digests: Some(&digests_array),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        };

        let measurement_map = MeasurementMap {
            key: 1,
            mval: measurement_value,
        };
        let measurements_array = [measurement_map];

        let class_map = ClassMap {
            class_id: "1.3.6.1.4.1.3333",
            vendor: Some("Tagged Vendor"),
            model: Some("Tagged Model"),
        };

        let environment = EnvironmentMap { class: class_map };

        let evidence_triple = EvidenceTripleRecord {
            environment,
            measurements: &measurements_array,
        };
        let evidence_triples_array = [evidence_triple];

        let ev_triples = EvTriplesMap {
            evidence_triples: Some(&evidence_triples_array),
            identity_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            attest_key_triples: None,
        };

        let evidence_map = ConciseEvidenceMap {
            ev_triples,
            evidence_id: None,
            profile: None,
        };

        let tagged = TaggedConciseEvidence {
            concise_evidence: evidence_map,
        };

        let concise_evidence = ConciseEvidence::Tagged(tagged);

        let mut buffer = [0u8; 1024];
        let mut encoder = CborEncoder::new(&mut buffer);
        concise_evidence
            .encode(&mut encoder)
            .expect("Encoding failed");

        let encoded_len = encoder.len();

        // This is a complex nested structure, verify it encodes successfully
        assert!(encoded_len > 0);

        // Tagged variant should start with a tag (major type 6)
        assert_eq!(buffer[0] & 0xE0, u8::from(crate::cbor::MajorType::Tag) << 5);
    }

    #[test]
    fn test_domain_type_choice_uuid() {
        let uuid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let domain = DomainTypeChoice::Uuid(&uuid);

        let mut buffer = [0u8; 64];
        let mut encoder = CborEncoder::new(&mut buffer);
        domain.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();
        let expected_size = CborEncoder::estimate_bytes_string_size(16);
        assert_eq!(encoded_len, expected_size);
    }

    #[test]
    fn test_domain_type_choice_uri() {
        let domain = DomainTypeChoice::Uri("https://example.com/domain");

        let mut buffer = [0u8; 64];
        let mut encoder = CborEncoder::new(&mut buffer);
        domain.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();
        let expected_size =
            CborEncoder::estimate_text_string_size("https://example.com/domain".len());
        assert_eq!(encoded_len, expected_size);
    }

    #[test]
    fn test_crypto_key_type_choice_public_key() {
        let public_key = [0xAB; 64];
        let key = CryptoKeyTypeChoice::PublicKey(&public_key);

        let mut buffer = [0u8; 128];
        let mut encoder = CborEncoder::new(&mut buffer);
        key.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();
        let expected_size = CborEncoder::estimate_bytes_string_size(64);
        assert_eq!(encoded_len, expected_size);
    }

    #[test]
    fn test_crypto_key_type_choice_key_id() {
        let key_id = [0xCD; 16];
        let key = CryptoKeyTypeChoice::KeyId(&key_id);

        let mut buffer = [0u8; 64];
        let mut encoder = CborEncoder::new(&mut buffer);
        key.encode(&mut encoder).expect("Encoding failed");

        let encoded_len = encoder.len();
        let expected_size = CborEncoder::estimate_bytes_string_size(16);
        assert_eq!(encoded_len, expected_size);
    }
}

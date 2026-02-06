// Licensed under the Apache-2.0 license
// OCP EAT Profile structures and encoding

mod concise_evidence;
mod eat;

// Re-export OCP EAT profile types
pub use eat::{
    CorimLocatorMap, DebugStatus, DloaType, MeasurementFormat, OcpEatClaims, PrivateClaim,
};

// Re-export only used items from the concise_evidence module
pub use concise_evidence::{
    ClassMap, ConciseEvidence, ConciseEvidenceMap, DigestEntry, EnvironmentMap, EvTriplesMap,
    EvidenceTripleRecord, IntegrityRegisterEntry, IntegrityRegisterIdChoice, MeasurementMap,
    MeasurementValue, TaggedConciseEvidence,
};

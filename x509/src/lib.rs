/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Main entry point for Caliptra X509 related functionality

--*/

#![cfg_attr(not(feature = "std"), no_std)]

mod cert_bldr;
mod der_helper;
mod fmc_alias_cert_ecc_384;
mod fmc_alias_cert_mldsa_87;
mod fmc_alias_csr;
mod idevid_csr_ecc_384;
mod idevid_csr_mldsa_87;
mod ldevid_cert_ecc_384;
mod ldevid_cert_mldsa_87;
mod rt_alias_cert_ecc_384;
mod rt_alias_cert_mldsa_87;
mod test_util;

pub use cert_bldr::{
    Ecdsa384CertBuilder, Ecdsa384CsrBuilder, Ecdsa384Signature, MlDsa87CertBuilder,
    MlDsa87CsrBuilder, Mldsa87Signature,
};
pub use der_helper::{der_encode_len, der_encode_uint, der_uint_len};
pub use fmc_alias_cert_ecc_384::{FmcAliasCertTbsEcc384, FmcAliasCertTbsEcc384Params};
pub use fmc_alias_cert_mldsa_87::{FmcAliasCertTbsMlDsa87, FmcAliasCertTbsMlDsa87Params};
pub use fmc_alias_csr::{FmcAliasCsrTbs, FmcAliasCsrTbsParams};
pub use idevid_csr_ecc_384::{InitDevIdCsrTbsEcc384, InitDevIdCsrTbsEcc384Params};
pub use idevid_csr_mldsa_87::{InitDevIdCsrTbsMlDsa87, InitDevIdCsrTbsMlDsa87Params};
pub use ldevid_cert_ecc_384::{LocalDevIdCertTbsEcc384, LocalDevIdCertTbsEcc384Params};
pub use ldevid_cert_mldsa_87::{LocalDevIdCertTbsMlDsa87, LocalDevIdCertTbsMlDsa87Params};
pub use rt_alias_cert_ecc_384::{RtAliasCertTbsEcc384, RtAliasCertTbsEcc384Params};
pub use rt_alias_cert_mldsa_87::{RtAliasCertTbsMlDsa87, RtAliasCertTbsMlDsa87Params};
use zeroize::Zeroize;

pub const NOT_BEFORE: &str = "20230101000000Z";
pub const NOT_AFTER: &str = "99991231235959Z";

/// Helper function to convert GeneralizedTime to UTCTime format
/// Returns None if the year is outside the valid range for UTCTime (1950-2049)
/// For years beyond 2049, returns the maximum UTC time value (491231235959Z)
fn generalized_to_utc_time(value: &[u8; 15]) -> Option<[u8; 13]> {
    // Special handling for NOT_AFTER constant (99991231235959Z)
    // If this is the "end of time" date, represent it as the max UTC time
    if value == NOT_AFTER.as_bytes() {
        // Maximum UTC time is 2049-12-31 23:59:59Z (491231235959Z)
        return Some([
            b'4', b'9', // Year 2049 (49)
            b'1', b'2', // Month December (12)
            b'3', b'1', // Day 31
            b'2', b'3', b'5', b'9', // Hours/Minutes/Seconds 23:59:59
            b'5', b'9', b'Z', // Zulu time zone
        ]);
    }

    // Try to convert the first 4 bytes to a year
    let year_str = core::str::from_utf8(&value[0..4]).ok()?;
    let year = year_str.parse::<u16>().ok()?;

    // UTCTime can only represent years between 1950-2049
    if !(1950..=2049).contains(&year) {
        return None;
    }

    // Convert to UTCTime (YYMMDDhhmmssZ)
    let mut result = [0u8; 13];
    // Copy the 2-digit year (last 2 digits)
    result[0] = value[2];
    result[1] = value[3];
    // Copy month, day, hour, minute, second, and Z
    result[2..13].copy_from_slice(&value[4..15]);

    Some(result)
}

#[derive(Debug, Zeroize)]
pub struct NotBefore {
    pub value: [u8; 15],
}

impl NotBefore {
    /// Returns the timestring as UTC time if the year is within valid range (1950-2049)
    /// ASN.1 UTCTime format has a 2-digit year representation.
    /// Returns None if the year is outside the valid range.
    pub fn as_utc_time(&self) -> Option<[u8; 13]> {
        generalized_to_utc_time(&self.value)
    }
}

impl Default for NotBefore {
    fn default() -> Self {
        let mut nb: NotBefore = NotBefore { value: [0u8; 15] };

        nb.value.copy_from_slice(NOT_BEFORE.as_bytes());
        nb
    }
}

#[derive(Debug, Zeroize)]
pub struct NotAfter {
    pub value: [u8; 15],
}

impl NotAfter {
    /// Returns the timestring as UTC time if the year is within valid range (1950-2049)
    /// ASN.1 UTCTime format has a 2-digit year representation.
    /// Returns None if the year is outside the valid range.
    pub fn as_utc_time(&self) -> Option<[u8; 13]> {
        generalized_to_utc_time(&self.value)
    }
}

impl Default for NotAfter {
    fn default() -> Self {
        let mut nf: NotAfter = NotAfter { value: [0u8; 15] };

        nf.value.copy_from_slice(NOT_AFTER.as_bytes());
        nf
    }
}

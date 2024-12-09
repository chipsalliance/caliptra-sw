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
mod idevid_csr_ecc_384;
mod idevid_csr_envelop;
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
pub use idevid_csr_ecc_384::{InitDevIdCsrTbsEcc384, InitDevIdCsrTbsEcc384Params};
pub use idevid_csr_envelop::InitDevIdCsrEnvelop;
pub use idevid_csr_mldsa_87::{InitDevIdCsrTbsMlDsa87, InitDevIdCsrTbsMlDsa87Params};
pub use ldevid_cert_ecc_384::{LocalDevIdCertTbsEcc384, LocalDevIdCertTbsEcc384Params};
pub use rt_alias_cert_ecc_384::{RtAliasCertTbsEcc384, RtAliasCertTbsEcc384Params};
use zeroize::Zeroize;

pub const NOT_BEFORE: &str = "20230101000000Z";
pub const NOT_AFTER: &str = "99991231235959Z";

#[derive(Debug, Zeroize)]
pub struct NotBefore {
    pub value: [u8; 15],
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

impl Default for NotAfter {
    fn default() -> Self {
        let mut nf: NotAfter = NotAfter { value: [0u8; 15] };

        nf.value.copy_from_slice(NOT_AFTER.as_bytes());
        nf
    }
}

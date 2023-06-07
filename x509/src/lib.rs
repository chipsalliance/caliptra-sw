/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Main entry point for Caliptra X509 related functionality

--*/

#![cfg_attr(not(feature = "std"), no_std)]

mod cert_bldr;
mod fmc_alias_cert;
mod idevid_csr;
mod ldevid_cert;
mod rt_alias_cert;
mod test_util;

pub use cert_bldr::{Ecdsa384CertBuilder, Ecdsa384CsrBuilder, Ecdsa384Signature};
pub use fmc_alias_cert::{FmcAliasCertTbs, FmcAliasCertTbsParams};
pub use idevid_csr::{InitDevIdCsrTbs, InitDevIdCsrTbsParams};
pub use ldevid_cert::{LocalDevIdCertTbs, LocalDevIdCertTbsParams};
pub use rt_alias_cert::{RtAliasCertTbs, RtAliasCertTbsParams};

#[derive(Debug)]
pub struct NotBefore {
    pub value: [u8; 15],
}

impl Default for NotBefore {
    fn default() -> Self {
        let not_before = "20230101000000Z";
        let mut nb: NotBefore = NotBefore { value: [0u8; 15] };

        nb.value.copy_from_slice(not_before.as_bytes());
        nb
    }
}

#[derive(Debug)]
pub struct NotAfter {
    pub value: [u8; 15],
}

impl Default for NotAfter {
    fn default() -> Self {
        let not_after = "99991231235959Z";
        let mut nf: NotAfter = NotAfter { value: [0u8; 15] };

        nf.value.copy_from_slice(not_after.as_bytes());
        nf
    }
}

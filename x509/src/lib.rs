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

pub struct NotBefore {
    pub not_before: [u8; 15],
}

impl Default for NotBefore {
    fn default() -> Self {
        let not_before = "20230101000000Z";
        let mut nb: NotBefore = NotBefore {
            not_before: [0u8; 15],
        };

        nb.not_before.copy_from_slice(not_before.as_bytes());
        nb
    }
}

pub struct NotAfter {
    pub not_after: [u8; 15],
}

impl Default for NotAfter {
    fn default() -> Self {
        let not_after = "99991231235959Z";
        let mut nb: NotAfter = NotAfter {
            not_after: [0u8; 15],
        };

        nb.not_after.copy_from_slice(not_after.as_bytes());
        nb
    }
}

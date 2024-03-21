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

/*++

Licensed under the Apache-2.0 license.

File Name:

    certify_key_extended_mldsa.rs

Abstract:

    File contains the CERTIFY_KEY_EXTENDED_MLDSA87 mailbox command, the ML-DSA-87
    (PQ) identity variant of CERTIFY_KEY_EXTENDED.

--*/

use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_drivers::{CaliptraError, CaliptraResult};

pub struct CertifyKeyExtendedMldsa87Cmd;

impl CertifyKeyExtendedMldsa87Cmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(_drivers: &mut Drivers) -> CaliptraResult<()> {
        // TODO(PQC): certify the requested key under the ML-DSA-87 identity and
        // return the certificate via CertifyKeyExtendedMldsa87Resp. Return
        // RUNTIME_PQC_NOT_INITIALIZED when pqc_mode is disabled.
        Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
    }
}

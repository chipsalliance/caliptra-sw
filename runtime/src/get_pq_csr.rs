/*++

Licensed under the Apache-2.0 license.

File Name:

    get_pq_csr.rs

Abstract:

    File contains the GET_PQ_CSR mailbox command, which returns the PQ.DevID
    ML-DSA-87 self-signed Certificate Signing Request.

--*/

use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_drivers::{CaliptraError, CaliptraResult};

pub struct GetPqCsrCmd;

impl GetPqCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(_drivers: &mut Drivers) -> CaliptraResult<()> {
        // TODO(PQC): regenerate the ML-DSA-87 keypair from the PQ seed, build
        // and sign the CSR TBS, and return it via GetPqCsrResp. Return
        // RUNTIME_PQC_NOT_INITIALIZED when pqc_mode is disabled.
        Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
    }
}

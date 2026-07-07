/*++

Licensed under the Apache-2.0 license.

File Name:

    invoke_dpe_mldsa.rs

Abstract:

    File contains the INVOKE_DPE_MLDSA87 mailbox command, which executes a DPE
    command using the ML-DSA-87 (PQ) identity.

--*/

use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_drivers::{CaliptraError, CaliptraResult};

pub struct InvokeDpeMldsa87Cmd;

impl InvokeDpeMldsa87Cmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(_drivers: &mut Drivers) -> CaliptraResult<()> {
        // TODO(PQC): create the ML-DSA DPE environment and execute the DPE
        // command (CertifyKey, Sign, DeriveContext). Return
        // RUNTIME_PQC_NOT_INITIALIZED when pqc_mode is disabled.
        Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
    }
}

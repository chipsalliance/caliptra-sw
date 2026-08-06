/*++

Licensed under the Apache-2.0 license.

File Name:

    certify_key_extended_mldsa.rs

Abstract:

    File contains the CERTIFY_KEY_EXTENDED_MLDSA87 mailbox command, the ML-DSA-87
    (PQ) identity variant of CERTIFY_KEY_EXTENDED.

--*/

use crate::{CaliptraDpeProfile, CertifyKeyExtendedCmd, Drivers};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::CertifyKeyExtendedMldsa87Req;
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::{FromZeros, IntoBytes};

pub struct CertifyKeyExtendedMldsa87Cmd;

impl CertifyKeyExtendedMldsa87Cmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = CertifyKeyExtendedMldsa87Req::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        // The ML-DSA DPE identity is the PQ.DevID, which only exists once a seed
        // has been provisioned via SET_PQ_SEED.
        if !drivers.persistent_data.get().pqc_mode_enabled() {
            return Err(CaliptraError::RUNTIME_PQC_NOT_INITIALIZED);
        }

        // The mldsa variant of the certify key extended can be quite long (the
        // current longest measurement is over 400_000_000 cycles), well past the
        // default 20M-cycle command watchdog budget; extend it.
        drivers.extend_wdt_for_pqc();

        // The certify-key logic is shared with the ECDSA variant; only the DPE
        // profile (and thus identity / signature algorithm) differs.
        CertifyKeyExtendedCmd::certify_key(
            drivers,
            cmd.flags,
            &cmd.certify_key_req,
            CaliptraDpeProfile::Mldsa,
        )
    }
}

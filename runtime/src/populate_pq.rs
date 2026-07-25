/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_pq.rs

Abstract:

    File contains PopulatePqCertCmd mailbox command.

--*/

use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{MailboxRespHeader, PopulatePqCertReq};
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::{FromZeros, IntoBytes};

use crate::Drivers;

pub struct PopulatePqCertCmd;
impl PopulatePqCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = PopulatePqCertReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        let cert_size = cmd.cert_size as usize;
        if cert_size > cmd.cert.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        // PL1 cannot call this mailbox command
        drivers.ensure_pl0()?;

        let chain = ArrayVec::try_from(&cmd.cert[..cert_size])
            .map_err(|_| CaliptraError::RUNTIME_PQ_CERT_POPULATION_FAILED)?;
        drivers.mldsa_cert_chain = chain;

        crate::packet::copy_to_mbox(drivers, MailboxRespHeader::default().as_mut_bytes())
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains PopulateIdev mailbox command.

--*/

use crate::PauserPrivileges;
use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{MailboxResp, PopulateIdevCertReq};
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::{FromZeros, IntoBytes};

use crate::{Drivers, MAX_CERT_CHAIN_SIZE};

pub struct PopulateIDevIdCertCmd;
impl PopulateIDevIdCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut cmd = PopulateIdevCertReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        let cert_size = cmd.cert_size as usize;
        if cert_size > cmd.cert.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        // PL1 cannot call this mailbox command
        if drivers.caller_privilege_level() != PauserPrivileges::PL0 {
            Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL)?
        }

        let mut tmp_chain = ArrayVec::<u8, MAX_CERT_CHAIN_SIZE>::new();
        tmp_chain
            .try_extend_from_slice(&cmd.cert[..cert_size])
            .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
        tmp_chain
            .try_extend_from_slice(drivers.cert_chain.as_slice())
            .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
        drivers.cert_chain = tmp_chain;

        Ok(MailboxResp::default())
    }
}

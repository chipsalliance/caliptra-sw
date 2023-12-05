// Licensed under the Apache-2.0 license

use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{MailboxResp, PopulateIdevCertReq};
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::AsBytes;

use crate::{Drivers, MAX_CERT_CHAIN_SIZE, PL0_PAUSER_FLAG};

pub struct PopulateIDevIdCertCmd;
impl PopulateIDevIdCertCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if cmd_args.len() <= core::mem::size_of::<PopulateIdevCertReq>() {
            let mut cmd = PopulateIdevCertReq::default();
            cmd.as_bytes_mut()[..cmd_args.len()].copy_from_slice(cmd_args);

            let cert_size = cmd.cert_size as usize;
            if cert_size > cmd.cert.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let flags = drivers.persistent_data.get().manifest1.header.flags;
            // PL1 cannot call this mailbox command
            if flags & PL0_PAUSER_FLAG == 0 {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
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
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}

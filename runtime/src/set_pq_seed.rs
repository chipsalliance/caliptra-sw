/*++

Licensed under the Apache-2.0 license.

File Name:

    set_pq_seed.rs

Abstract:

    File contains SET_PQ_SEED mailbox command.

--*/

use crate::{Drivers, PauserPrivileges};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{MailboxResp, SetPqSeedReq};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::{FromZeros, IntoBytes};

pub struct SetPqSeedCmd;

impl SetPqSeedCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        if drivers.caller_privilege_level() != PauserPrivileges::PL0 {
            Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL)?;
        }

        if drivers.persistent_data.get().pqc_mode_enabled() {
            Err(CaliptraError::RUNTIME_SET_PQ_SEED_ALREADY_SET)?;
        }

        let mut cmd = SetPqSeedReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        drivers.persistent_data.get_mut().pq_devid_seed = cmd.seed;
        drivers.persistent_data.get_mut().set_pqc_mode_enabled();

        Ok(MailboxResp::default())
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    fe_programming.rs

Abstract:

    File contains FE_PROG mailbox command.

--*/

use crate::Drivers;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::FeProgReq;
use caliptra_common::uds_fe_programming::UdsFeProgrammingFlow;
use caliptra_drivers::{CaliptraError, CaliptraResult, Lifecycle};
use zerocopy::IntoBytes;

pub struct FeProgrammingCmd;

impl FeProgrammingCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<FeProgReq>() {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        }

        let mut cmd = FeProgReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        // Check if ROM is in manufacturing mode.
        if drivers.soc_ifc.lifecycle() != Lifecycle::Manufacturing {
            Err(CaliptraError::RUNTIME_FE_PROG_ILLEGAL_LIFECYCLE_STATE)?;
        }

        let uds_fe_programmer = UdsFeProgrammingFlow::Fe;

        // Call the common FE programming function
        uds_fe_programmer.program_uds_fe(
            &mut drivers.soc_ifc,
            &mut drivers.trng,
            &drivers.dma,
            Some(cmd.bitflags),
        )?;

        Ok(0)
    }
}

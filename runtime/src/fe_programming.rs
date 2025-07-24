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
use zerocopy::FromBytes;

pub struct FeProgrammingCmd;

impl FeProgrammingCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<usize> {
        let cmd = FeProgReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        // [CAP2][TODO] Check if ROM is in manufacturing mode. Is this to be done for FE?
        if drivers.soc_ifc.lifecycle() != Lifecycle::Manufacturing {
            Err(CaliptraError::RUNTIME_FE_PROG_ILLEGAL_LIFECYCLE_STATE)?;
        }

        let fe_programmer = UdsFeProgrammingFlow::Fe {
            bitmask: cmd.bitflags,
        };

        // Call the common FE programming function
        fe_programmer.program(&mut drivers.soc_ifc, &mut drivers.trng, &drivers.dma)?;

        Ok(0)
    }
}

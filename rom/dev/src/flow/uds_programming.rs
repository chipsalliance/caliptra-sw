/*++

Licensed under the Apache-2.0 license.

File Name:

    uds_programming.rs

Abstract:

    File contains the implementation of UDS programming flow.
--*/

use crate::rom_env::RomEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::cprintln;
use caliptra_common::uds_fe_programming::UdsFeProgrammingFlow;
use caliptra_drivers::{CaliptraError, CaliptraResult, Lifecycle};

/// UDS Programming Flow
pub struct UdsProgrammingFlow {}

impl UdsProgrammingFlow {
    #[inline(never)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn program_uds(env: &mut RomEnv) -> CaliptraResult<()> {
        // Check if UDS programming is requested.
        if !env.soc_ifc.uds_program_req() {
            return Ok(());
        }

        // Check if ROM is running in Subsystem mode.
        if !env.soc_ifc.subsystem_mode() {
            cprintln!("[uds] ROM is not in Active mode.");
            Err(CaliptraError::ROM_UDS_PROG_IN_PASSIVE_MODE)?;
        }

        //  Check if ROM is in manufacturing mode.
        if env.soc_ifc.lifecycle() != Lifecycle::Manufacturing {
            cprintln!("[uds] ROM is not in manufacturing mode.");
            Err(CaliptraError::ROM_UDS_PROG_ILLEGAL_LIFECYCLE_STATE)?;
        }

        let uds_fe_programmer = UdsFeProgrammingFlow::Uds;

        // Call the common UDS programming function
        uds_fe_programmer.program(&mut env.soc_ifc, &mut env.trng, &env.dma)
    }
}

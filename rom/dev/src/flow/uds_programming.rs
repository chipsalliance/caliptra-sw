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
use caliptra_drivers::Lifecycle;
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::AsBytes;

/// UDS Programming Flow
pub struct UdsProgrammingFlow {}

impl UdsProgrammingFlow {
    #[inline(never)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn program_uds(env: &mut RomEnv) -> CaliptraResult<()> {
        cprintln!("[uds] ++");

        // Check if UDS programming is requested.
        if !env.soc_ifc.uds_program_req() {
            return Ok(());
        }

        cprintln!("[uds] ++");

        // Check if ROM is running in Active mode.
        if !env.soc_ifc.active_mode() {
            cprintln!("[uds] ROM is not in Active mode.");
            return Err(CaliptraError::ROM_UDS_PROG_IN_PASSIVE_MODE);
        }

        //  Check if ROM is in manufacturing mode.
        if env.soc_ifc.lifecycle() != Lifecycle::Manufacturing {
            cprintln!("[uds] ROM is not in manufacturing mode.");
            return Err(CaliptraError::ROM_UDS_PROG_ILLEGAL_LIFECYCLE_STATE);
        }

        // Update the UDS programming state.
        env.soc_ifc
            .set_uds_programming_flow_state(true /* in_progress */);

        let result = (|| {
            // Generate a 512-bit random value..
            let mut seed = [0u32; 16];
            let seed1 = env.trng.generate()?;
            let seed2 = env.trng.generate()?;
            seed[..12].copy_from_slice(&seed1.0);
            seed[12..16].copy_from_slice(&seed2.0[0..4]);

            // Write the seed to the UDS_SEED_OFFSET using DMA assist.
            cprintln!("[uds] Writing seed to UDS_SEED_OFFSET");
            env.dma.write_buffer(
                env.soc_ifc.uds_seed_dest_base_addr_low() as usize,
                seed.as_bytes(),
            )?;
            Ok(())
        })();

        // Set the UDS programming result.
        env.soc_ifc.set_uds_programming_flow_status(result.is_ok());

        // Update the UDS programming state.
        env.soc_ifc
            .set_uds_programming_flow_state(false /* in_progress */);

        cprintln!(
            "[uds] UDS programming flow completed with status: {}",
            if result.is_ok() { "SUCCESS" } else { "FAILURE" }
        );

        cprintln!("[uds] --");

        result
    }
}

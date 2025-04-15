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
use caliptra_drivers::{AxiAddr, CaliptraError, CaliptraResult, DmaOtpCtrl, Lifecycle};

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

        cprintln!("[uds] ++");

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

        // Update the UDS programming state.
        cprintln!("[uds] Updating the UDS programming state");
        env.soc_ifc
            .set_uds_programming_flow_state(true /* in_progress */);

        let result = (|| {
            // Generate a 512-bit random value.
            let seed = [0xdeadbeef_u32; 16];
            // let seed1 = env.trng.generate()?;
            // let seed2 = env.trng.generate()?;
            // seed[..12].copy_from_slice(&seed1.0);
            // seed[12..16].copy_from_slice(&seed2.0[0..4]);

            let uds_fuse_row_granularity_64 = env.soc_ifc.uds_fuse_row_granularity_64();
            let fuse_controller_base_addr = env.soc_ifc.fuse_controller_base_addr();
            let mut uds_seed_dest_address = env.soc_ifc.uds_seed_dest_base_addr_low();
            let mut seed_index = 0;

            let otp_ctrl = DmaOtpCtrl::new(AxiAddr::from(fuse_controller_base_addr), &env.dma);
            let _ = otp_ctrl.with_regs_mut(|regs| {
                while seed_index < seed.len() {
                    // Poll the STATUS register until the DAI state returns to idle
                    while !regs.status().read().dai_idle() {}

                    // Write the UDS seed to the DIRECT_ACCESS_WDATA registers
                    let wdata_0 = seed[seed_index];
                    cprintln!(
                        "[uds] Writing the UDS seed to the DIRECT_ACCESS_WDATA_0 register, wdata_0: {:#x}",
                        wdata_0
                    );
                    regs.dai_wdata_rf().direct_access_wdata_0().write(|_| wdata_0);

                    if uds_fuse_row_granularity_64 {
                        if seed_index + 1 >= seed.len() {
                            return Err(CaliptraError::ROM_UDS_PROG_INVALID_SEED_LENGTH);
                        }
                        // 64-bit granularity
                        let wdata_1 = seed[seed_index + 1];
                        cprintln!(
                            "[uds] Writing the UDS seed to the DIRECT_ACCESS_WDATA_1 register, wdata_1: {:#x}",
                            wdata_1
                        );
                        regs.dai_wdata_rf().direct_access_wdata_1().write(|_| wdata_1);
                        seed_index += 2;
                    } else {
                        // 32-bit granularity
                        seed_index += 1;
                    }

                    // Write the UDS Seed destination address to the DIRECT_ACCESS_ADDRESS register
                    cprintln!(
                        "[uds] Writing the UDS Seed programming destination address: {:#x} to the DIRECT_ACCESS_ADDRESS register",
                        uds_seed_dest_address
                    );
                    regs.direct_access_address().write(|w| w.address(uds_seed_dest_address));

                    // Trigger the UDS seed write command
                    cprintln!("[uds] Triggering the UDS seed write command");
                    regs.direct_access_cmd().write(|w| w.wr(true));

                    // Increment the DIRECT_ACCESS_ADDRESS register
                    if uds_fuse_row_granularity_64 {
                        uds_seed_dest_address += 8;
                    } else {
                        uds_seed_dest_address += 4;
                    }
                } // End of UDS seed write loop.

                // Trigger the partition digest operation
                // Poll the STATUS register until the DAI state returns to idle
                while !regs.status().read().dai_idle() {}

                // Write the UDS Seed base address to the DIRECT_ACCESS_ADDRESS register
                cprintln!(
                    "[uds] Triggering the partition digest operation, uds_seed_dest_address: {:#x}",
                    env.soc_ifc.uds_seed_dest_base_addr_low()
                );
                regs.direct_access_address().write(|w| w.address(env.soc_ifc.uds_seed_dest_base_addr_low()));

                // Trigger the digest calculation command
                cprintln!("[uds] Triggering the digest calculation command");
                regs.direct_access_cmd().write(|w| w.digest(true));

                // Poll the STATUS register until the DAI state returns to idle
                while !regs.status().read().dai_idle() {}

                Ok::<(), CaliptraError>(())
            })?;

            Ok(())
        })();

        // Set the UDS programming result.
        cprintln!("[uds] Setting the UDS programming result");
        env.soc_ifc.set_uds_programming_flow_status(result.is_ok());

        // Update the UDS programming state.
        cprintln!("[uds] Updating the UDS programming state");
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

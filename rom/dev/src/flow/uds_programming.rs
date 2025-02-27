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
        cprintln!("[uds] ++");

        // Check if UDS programming is requested.
        if !env.soc_ifc.uds_program_req() {
            return Ok(());
        }

        cprintln!("[uds] ++");

        // Check if ROM is running in Active mode.
        if !env.soc_ifc.active_mode() {
            cprintln!("[uds] ROM is not in Active mode.");
            Err(CaliptraError::ROM_UDS_PROG_IN_PASSIVE_MODE)?;
        }

        //  Check if ROM is in manufacturing mode.
        if env.soc_ifc.lifecycle() != Lifecycle::Manufacturing {
            cprintln!("[uds] ROM is not in manufacturing mode.");
            Err(CaliptraError::ROM_UDS_PROG_ILLEGAL_LIFECYCLE_STATE)?;
        }

        // Update the UDS programming state.
        env.soc_ifc
            .set_uds_programming_flow_state(true /* in_progress */);

        let result = (|| {
            // Generate a 512-bit random value.
            let mut seed = [0u32; 16];
            let seed1 = env.trng.generate()?;
            let seed2 = env.trng.generate()?;
            seed[..12].copy_from_slice(&seed1.0);
            seed[12..16].copy_from_slice(&seed2.0[0..4]);

            let uds_fuse_row_granularity_64: bool = env.soc_ifc.uds_fuse_row_granularity_64();
            let fuse_controller_base_addr = env.soc_ifc.fuse_controller_base_addr();
            let otp_ctrl = DmaOtpCtrl::new(AxiAddr::from(fuse_controller_base_addr), &env.dma);
            let mut uds_seed_dest_address = env.soc_ifc.uds_seed_dest_base_addr_low();
            let mut seed_index = 0;

            while seed_index < seed.len() {
                // Wait for the DAI to be idle before proceeding
                otp_ctrl.with_regs(|regs| {
                    // Poll the STATUS register until the DAI state returns to idle
                    while !regs.status().read().dail_idle() {
                        // [TODO][CAP2] Handle errors.
                    }
                })?;

                // Write the UDS seed data
                if uds_fuse_row_granularity_64 {
                    if seed_index + 1 >= seed.len() {
                        Err(CaliptraError::ROM_UDS_PROG_INVALID_SEED_LENGTH)?;
                    }

                    // 64-bit granularity - write two 32-bit words
                    otp_ctrl.with_regs_mut(|regs| {
                        // Write data to the data registers
                        regs.dai_wdata_rf()
                            .direct_access_wdata_0()
                            .write(|_| seed[seed_index]);
                        regs.dai_wdata_rf()
                            .direct_access_wdata_1()
                            .write(|_| seed[seed_index + 1]);

                        // Set the address
                        regs.direct_access_address()
                            .write(|w| w.address(uds_seed_dest_address));

                        // Trigger the write command
                        regs.direct_access_cmd().write(|w| w.wr(true));
                    })?;

                    seed_index += 2;
                    uds_seed_dest_address += 8;
                } else {
                    // 32-bit granularity - write one 32-bit word
                    otp_ctrl.with_regs_mut(|regs| {
                        // Write data to the data register
                        regs.dai_wdata_rf()
                            .direct_access_wdata_0()
                            .write(|_| seed[seed_index]);

                        // Set the address
                        regs.direct_access_address()
                            .write(|w| w.address(uds_seed_dest_address));

                        // Trigger the write command
                        regs.direct_access_cmd().write(|w| w.wr(true));
                    })?;

                    seed_index += 1;
                    uds_seed_dest_address += 4;
                }
            } // End of UDS seed write loop.

            // Wait for the DAI to be idle before proceeding with digest calculation
            otp_ctrl.with_regs(|regs| {
                // Poll the STATUS register until the DAI state returns to idle
                while !regs.status().read().dail_idle() {
                    // [TODO][CAP2] Handle errors.
                }
            })?;

            // Trigger the partition digest operation
            cprintln!("[uds] Triggering the partition digest operation");
            otp_ctrl.with_regs_mut(|regs| {
                // Set the base address for the digest calculation
                regs.direct_access_address()
                    .write(|w| w.address(env.soc_ifc.uds_seed_dest_base_addr_low()));

                // Trigger the digest calculation command
                regs.direct_access_cmd().write(|w| w.digest(true));
            })?;

            // Wait for the digest calculation to complete
            otp_ctrl.with_regs(|regs| {
                // Poll the STATUS register until the DAI state returns to idle
                while !regs.status().read().dail_idle() {
                    // [TODO][CAP2] Handle errors.
                }
            })?;

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

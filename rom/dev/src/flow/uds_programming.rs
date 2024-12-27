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
use caliptra_drivers::{AxiAddr, CaliptraError, CaliptraResult, Lifecycle};

const STATUS_REG_OFFSET: u64 = 0x10;
const DIRECT_ACCESS_WDATA_0_REG_OFFSET: u64 = 0x44;
const DIRECT_ACCESS_WDATA_1_REG_OFFSET: u64 = 0x48;
const DIRECT_ACCESS_ADDRESS_REG_OFFSET: u64 = 0x40;
const DIRECT_ACCESS_CMD_REG_OFFSET: u64 = 0x3C;
const DAI_IDLE_BIT: u32 = 1 << 18;
const DIRECT_ACCESS_CMD_WRITE: u32 = 0x2;
const DIRECT_ACCESS_CMD_DIGEST: u32 = 0x4;

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
            let status_reg_addr = fuse_controller_base_addr + STATUS_REG_OFFSET;
            let direct_access_wdata_0_reg_addr =
                fuse_controller_base_addr + DIRECT_ACCESS_WDATA_0_REG_OFFSET;
            let direct_access_wdata_1_reg_addr =
                fuse_controller_base_addr + DIRECT_ACCESS_WDATA_1_REG_OFFSET;
            let mut uds_seed_dest_address = env.soc_ifc.uds_seed_dest_base_addr_low();
            let direct_access_address_reg_addr =
                fuse_controller_base_addr + DIRECT_ACCESS_ADDRESS_REG_OFFSET;
            let direct_access_cmd_reg_addr =
                fuse_controller_base_addr + DIRECT_ACCESS_CMD_REG_OFFSET;
            let mut seed_index = 0;

            while seed_index < seed.len() {
                // Poll the STATUS register until the DAI state returns to idle.
                while {
                    let status_value = env.dma.read_dword(AxiAddr::from(status_reg_addr))?;
                    (status_value & DAI_IDLE_BIT) == 0
                } {
                    // [TODO][CAP2] Handle errors.
                }

                // Write the UDS seed to the DIRECT_ACCESS_WDATA_0 register
                // and the DIRECT_ACCESS_WDATA_1 register (for 64-bit granularity).
                let wdata_0 = seed[seed_index];
                env.dma
                    .write_dword(AxiAddr::from(direct_access_wdata_0_reg_addr), wdata_0)?;
                if uds_fuse_row_granularity_64 {
                    if seed_index + 1 >= seed.len() {
                        Err(CaliptraError::ROM_UDS_PROG_INVALID_SEED_LENGTH)?;
                    }
                    // 64-bit granularity
                    let wdata_1 = seed[seed_index + 1];
                    env.dma
                        .write_dword(AxiAddr::from(direct_access_wdata_1_reg_addr), wdata_1)?;
                    seed_index += 2;
                } else {
                    // 32-bit granularity
                    seed_index += 1;
                }

                // Write the lower 32 bits of the UDS Seed programming destination address to the DIRECT_ACCESS_ADDRESS register.
                env.dma.write_dword(
                    AxiAddr::from(direct_access_address_reg_addr),
                    uds_seed_dest_address,
                )?;

                // Trigger the UDS seed write command
                env.dma.write_dword(
                    AxiAddr::from(direct_access_cmd_reg_addr),
                    DIRECT_ACCESS_CMD_WRITE,
                )?;

                // Increment the DIRECT_ACCESS_ADDRESS register
                if uds_fuse_row_granularity_64 {
                    uds_seed_dest_address += 8;
                } else {
                    uds_seed_dest_address += 4;
                }
            } // End of UDS seed write loop.

            // Trigger the partition digest operation
            // Poll the STATUS register until the DAI state returns to idle.
            while {
                let status_value = env.dma.read_dword(AxiAddr::from(status_reg_addr))?;
                (status_value & DAI_IDLE_BIT) == 0
            } {
                // [TODO][CAP2] Handle errors.
            }

            // Write the lower 32 bits of the UDS Seed programming base address to the DIRECT_ACCESS_ADDRESS register.
            cprintln!("[uds] Triggering the partition digest operation");
            env.dma.write_dword(
                AxiAddr::from(direct_access_address_reg_addr),
                env.soc_ifc.uds_seed_dest_base_addr_low(),
            )?;

            // Trigger the digest calculation command
            env.dma.write_dword(
                AxiAddr::from(direct_access_cmd_reg_addr),
                DIRECT_ACCESS_CMD_DIGEST,
            )?;

            // Poll the STATUS register until the DAI state returns to idle
            while {
                let status_value = env.dma.read_dword(AxiAddr::from(status_reg_addr))?;
                (status_value & DAI_IDLE_BIT) == 0
            } {
                // [TODO][CAP2] Handle errors.
            }

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

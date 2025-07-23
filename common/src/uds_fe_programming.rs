/*++

Licensed under the Apache-2.0 license.

File Name:

    uds_fe_programming.rs

Abstract:

    File contains the implementation of UDS/FE programming flow that can be
    used by both ROM and Runtime.

--*/

use crate::cprintln;
use caliptra_drivers::{AxiAddr, CaliptraError, CaliptraResult, Dma, DmaOtpCtrl, SocIfc, Trng};

/// UDS/FE Programming Flow
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UdsFeProgrammingFlow {
    /// UDS (Unique Device Secret) programming mode - 64 bytes
    Uds,
    /// FE (Field Entropy) programming mode - 32 bytes
    Fe,
}

impl UdsFeProgrammingFlow {
    /// Returns true if this is UDS programming mode
    pub fn is_uds(self) -> bool {
        matches!(self, UdsFeProgrammingFlow::Uds)
    }

    /// Returns the seed length in 32-bit words for this mode
    pub fn seed_length(self) -> usize {
        match self {
            UdsFeProgrammingFlow::Uds => 16, // 64 bytes = 16 u32 words
            UdsFeProgrammingFlow::Fe => 8,   // 32 bytes = 8 u32 words
        }
    }

    /// Returns the prefix string for logging
    pub fn prefix(self) -> &'static str {
        match self {
            UdsFeProgrammingFlow::Uds => "uds",
            UdsFeProgrammingFlow::Fe => "fe",
        }
    }

    /// Returns the destination address for programming
    fn get_dest_address(&self, soc_ifc: &SocIfc) -> u32 {
        match self {
            Self::Uds => soc_ifc.uds_seed_dest_base_addr_low(),
            // [CAP2][TODO] This needs to be different for field entropy
            Self::Fe => soc_ifc.uds_seed_dest_base_addr_low(),
        }
    }

    /// Programs either UDS (64 bytes) or FE (32 bytes) based on the enum variant
    ///
    /// # Arguments
    /// * `soc_ifc` - SoC interface for accessing fuse controller and related registers
    /// * `trng` - TRNG for generating random seeds
    /// * `dma` - DMA engine for OTP control
    pub fn program_uds_fe(
        &self,
        soc_ifc: &mut SocIfc,
        trng: &mut Trng,
        dma: &Dma,
    ) -> CaliptraResult<()> {
        cprintln!("[{}] ++", self.prefix());

        // Update the programming state.
        cprintln!("[{}] Updating the programming state", self.prefix());
        if self.is_uds() {
            soc_ifc.set_uds_programming_flow_state(true);
        } else {
            // [CAP2][TODO]: What needs to be done here?
        }

        let result = (|| {
            // Generate a 512-bit random value.
            let seed: [u32; 16] = trng.generate16()?.into();

            // Determine seed length based on the programming mode
            let seed_length = self.seed_length();

            let uds_fuse_row_granularity_64 = soc_ifc.uds_fuse_row_granularity_64();
            let fuse_controller_base_addr = soc_ifc.fuse_controller_base_addr();
            let otp_ctrl = DmaOtpCtrl::new(AxiAddr::from(fuse_controller_base_addr), dma);
            let mut uds_seed_dest_address = self.get_dest_address(soc_ifc);
            let mut seed_index = 0;

            let _ = otp_ctrl.with_regs_mut(|regs| {
                while seed_index < seed_length {
                    // Poll the STATUS register until the DAI state returns to idle
                    while !regs.status().read().dai_idle() {}

                    // Write the seed to the DIRECT_ACCESS_WDATA registers
                    let wdata_0 = seed[seed_index];
                    cprintln!(
                        "[{}] Writing the seed to the DIRECT_ACCESS_WDATA_0 register, wdata_0: {:#x}",
                        self.prefix(),
                        wdata_0
                    );
                    regs.dai_wdata_rf().direct_access_wdata_0().write(|_| wdata_0);

                    if uds_fuse_row_granularity_64 {
                        if seed_index + 1 >= seed_length {
                            return Err(CaliptraError::ROM_UDS_PROG_INVALID_SEED_LENGTH);
                        }
                        // 64-bit granularity
                        let wdata_1 = seed[seed_index + 1];
                        cprintln!(
                            "[{}] Writing the seed to the DIRECT_ACCESS_WDATA_1 register, wdata_1: {:#x}",
                            self.prefix(),
                            wdata_1
                        );
                        regs.dai_wdata_rf().direct_access_wdata_1().write(|_| wdata_1);
                        seed_index += 2;
                    } else {
                        // 32-bit granularity
                        seed_index += 1;
                    }

                    // Write the Seed destination address to the DIRECT_ACCESS_ADDRESS register
                    cprintln!(
                        "[{}] Writing the Seed programming destination address: {:#x} to the DIRECT_ACCESS_ADDRESS register",
                        self.prefix(),
                        uds_seed_dest_address
                    );
                    regs.direct_access_address().write(|w| w.address(uds_seed_dest_address));

                    // Trigger the seed write command
                    cprintln!("[{}] Triggering the seed write command", self.prefix());
                    regs.direct_access_cmd().write(|w| w.wr(true));

                    // Increment the DIRECT_ACCESS_ADDRESS register
                    if uds_fuse_row_granularity_64 {
                        uds_seed_dest_address += 8;
                    } else {
                        uds_seed_dest_address += 4;
                    }
                } // End of seed write loop.

                // Trigger the partition digest operation
                // Poll the STATUS register until the DAI state returns to idle
                while !regs.status().read().dai_idle() {}

                // Write the Seed base address to the DIRECT_ACCESS_ADDRESS register
                cprintln!(
                    "[{}] Triggering the partition digest operation, uds_seed_dest_address: {:#x}",
                    self.prefix(),
                    soc_ifc.uds_seed_dest_base_addr_low()
                );
                regs.direct_access_address().write(|w| w.address(soc_ifc.uds_seed_dest_base_addr_low()));

                // Trigger the digest calculation command
                cprintln!("[{}] Triggering the digest calculation command", self.prefix());
                regs.direct_access_cmd().write(|w| w.digest(true));

                // Poll the STATUS register until the DAI state returns to idle
                while !regs.status().read().dai_idle() {}

                Ok::<(), CaliptraError>(())
            })?;

            Ok(())
        })();

        // Set the programming result.
        cprintln!("[{}] Setting the programming result", self.prefix());
        if self.is_uds() {
            soc_ifc.set_uds_programming_flow_status(result.is_ok());
        } else {
            // [CAP2][TODO]: What needs to be done here?
        }

        // Update the programming state.
        cprintln!("[{}] Updating the programming state", self.prefix());
        if self.is_uds() {
            soc_ifc.set_uds_programming_flow_state(false);
        } else {
            // [CAP2][TODO]: What needs to be done here?
        }

        cprintln!(
            "[{}] Programming flow completed with status: {}",
            self.prefix(),
            if result.is_ok() { "SUCCESS" } else { "FAILURE" }
        );

        cprintln!("[{}] --", self.prefix());

        result
    }
}

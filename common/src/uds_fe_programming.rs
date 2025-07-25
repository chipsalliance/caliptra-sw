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
    /// FE (Field Entropy) programming mode - 8 bytes per partition
    /// Valid partition numbers: 0, 1, 2, 3 (4 total partitions)
    Fe { partition: u32 },
}

const UDS_SEED_SIZE: usize = 64;
const FUSE_CTRL_DIGEST: usize = 8;
const FE_SIZE: usize = 8;
const MAX_FE_PARTITION: u32 = 3;

impl UdsFeProgrammingFlow {
    /// Validates the programming flow parameters
    pub fn validate(self) -> CaliptraResult<()> {
        match self {
            UdsFeProgrammingFlow::Uds => Ok(()),
            UdsFeProgrammingFlow::Fe { partition } => {
                if partition > MAX_FE_PARTITION {
                    Err(CaliptraError::RUNTIME_FE_PROG_INVALID_PARTITION)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Returns true if this is UDS programming mode
    fn is_uds(self) -> bool {
        matches!(self, UdsFeProgrammingFlow::Uds)
    }

    /// Returns the seed length in 32-bit words for this mode
    fn seed_length_words(self) -> usize {
        match self {
            UdsFeProgrammingFlow::Uds => UDS_SEED_SIZE / size_of::<u32>(), // 64 bytes = 16 u32 words
            UdsFeProgrammingFlow::Fe { partition: _ } => FE_SIZE / size_of::<u32>(), // 8 bytes = 2 u32 words
        }
    }

    /// Returns the prefix string for logging
    fn prefix(self) -> &'static str {
        match self {
            UdsFeProgrammingFlow::Uds => "uds",
            UdsFeProgrammingFlow::Fe { partition: _ } => "fe",
        }
    }

    /// Returns the destination address for programming
    ///
    /// Memory Map:
    /// ```
    /// +-------------------------------------+ <- uds_seed_dest_base_addr_low()
    /// |           UDS Region                |
    /// |          (64 bytes)                 |
    /// +-------------------------------------+
    /// ```
    ///
    /// FE Partitions, separate region in fuse controller memory handled by MCU, but at same base as UDS
    ///
    /// ```
    /// +-------------------------------------+ <- uds_seed_dest_base_addr_low()
    /// |        FE Partition 0               |
    /// |         (8 bytes)                   |
    /// +-------------------------------------+ <- base + (0 * 16)
    /// |     FE Partition 0 Digest           |
    /// |         (8 bytes)                   |
    /// +-------------------------------------+ <- base + (0 * 16) + 8
    /// |        FE Partition 1               |
    /// |         (8 bytes)                   |
    /// +-------------------------------------+ <- base + (1 * 16)
    /// |     FE Partition 1 Digest           |
    /// |         (8 bytes)                   |
    /// +-------------------------------------+ <- base + (1 * 16) + 8
    /// |        FE Partition 2               |
    /// |         (8 bytes)                   |
    /// +-------------------------------------+ <- base + (2 * 16)
    /// |     FE Partition 2 Digest           |
    /// |         (8 bytes)                   |
    /// +-------------------------------------+ <- base + (2 * 16) + 8
    /// |            ...                      |
    /// +-------------------------------------+
    /// ```
    fn get_dest_address(&self, soc_ifc: &SocIfc) -> u32 {
        let uds_seed_dest = soc_ifc.uds_seed_dest_base_addr_low();

        match self {
            Self::Uds => uds_seed_dest,
            Self::Fe { partition } => {
                // FE partitions start at the same base address with partition spacing (16 bytes each)
                uds_seed_dest + (partition * (FE_SIZE + FUSE_CTRL_DIGEST) as u32)
            }
        }
    }

    /// Programs either UDS (64 bytes) or FE (32 bytes) based on the enum variant
    ///
    /// # Arguments
    /// * `soc_ifc` - SoC interface for accessing fuse controller and related registers
    /// * `trng` - TRNG for generating random seeds
    /// * `dma` - DMA engine for OTP control
    pub fn program(&self, soc_ifc: &mut SocIfc, trng: &mut Trng, dma: &Dma) -> CaliptraResult<()> {
        // Validate parameters first
        self.validate()?;

        cprintln!("[{}] ++", self.prefix());

        if self.is_uds() {
            // Update the programming state.
            cprintln!("[{}] Updating the programming state", self.prefix());
            soc_ifc.set_uds_programming_flow_state(true);
        }

        let result = (|| {
            // Generate a 512-bit random value.
            let seed: [u32; 16] = trng.generate16()?.into();

            let uds_fuse_row_granularity_64 = soc_ifc.uds_fuse_row_granularity_64();
            let fuse_controller_base_addr = soc_ifc.fuse_controller_base_addr();
            let otp_ctrl = DmaOtpCtrl::new(AxiAddr::from(fuse_controller_base_addr), dma);
            let seed_dest_address = self.get_dest_address(soc_ifc);

            let _ = otp_ctrl.with_regs_mut(|regs| {
                seed[..self.seed_length_words()].chunks(if uds_fuse_row_granularity_64 { 2 } else {1}).enumerate().for_each(
                    |(index, seed)| {
                        let dest = seed_dest_address + (index * seed.len() * size_of::<u32>()) as u32;

                        // Poll the STATUS register until the DAI state returns to idle
                        while !regs.status().read().dai_idle() {}

                        let wdata_0 = seed[0];
                        regs.dai_wdata_rf().direct_access_wdata_0().write(|_| wdata_0);

                        if let Some(&wdata_1) = seed.get(1) {
                            regs.dai_wdata_rf().direct_access_wdata_1().write(|_| wdata_1);
                        }

                        // Write the Seed destination address to the DIRECT_ACCESS_ADDRESS register
                        cprintln!(
                            "[{}] Writing the Seed programming destination address: {:#x} to the DIRECT_ACCESS_ADDRESS register",
                            self.prefix(),
                            dest
                        );
                        regs.direct_access_address().write(|w| w.address(dest));

                        // Trigger the seed write command
                        cprintln!("[{}] Triggering the seed write command", self.prefix());
                        regs.direct_access_cmd().write(|w| w.wr(true));
                    }
                );

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

        if self.is_uds() {
            // Set the programming result.
            cprintln!("[{}] Setting the programming result", self.prefix());

            soc_ifc.set_uds_programming_flow_status(result.is_ok());

            // Update the programming state.
            cprintln!("[{}] Updating the programming state", self.prefix());
            soc_ifc.set_uds_programming_flow_state(false);
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

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
const FE_PARTITION_SIZE: usize = 8;
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
            UdsFeProgrammingFlow::Fe { partition: _ } => FE_PARTITION_SIZE / size_of::<u32>(), // 8 bytes = 2 u32 words
        }
    }

    /// Returns the prefix string for logging
    fn prefix(self) -> &'static str {
        match self {
            UdsFeProgrammingFlow::Uds => "uds",
            UdsFeProgrammingFlow::Fe { partition: _ } => "fe",
        }
    }

    // Returns the destination address for programming
    //
    // Memory Map:
    //
    // +-------------------------------------+ <- uds_seed_dest_base_addr_low()
    // |           UDS Region                |
    // |          (64 bytes)                 |
    // +-------------------------------------+
    //
    // FE Partitions, separate region in fuse controller memory handled by MCU, but at same base as UDS
    //
    // +-------------------------------------+ <- uds_seed_dest_base_addr_low()
    // |        FE Partition 0               |
    // |         (8 bytes)                   |
    // +-------------------------------------+ <- base + (0 * 16)
    // |     FE Partition 0 Digest           |
    // |         (8 bytes)                   |
    // +-------------------------------------+ <- base + (0 * 16) + 8
    // |        FE Partition 1               |
    // |         (8 bytes)                   |
    // +-------------------------------------+ <- base + (1 * 16)
    // |     FE Partition 1 Digest           |
    // |         (8 bytes)                   |
    // +-------------------------------------+ <- base + (1 * 16) + 8
    // |        FE Partition 2               |
    // |         (8 bytes)                   |
    // +-------------------------------------+ <- base + (2 * 16)
    // |     FE Partition 2 Digest           |
    // |         (8 bytes)                   |
    // +-------------------------------------+ <- base + (2 * 16) + 8
    // |            ...                      |
    // +-------------------------------------+
    fn get_dest_address(&self, soc_ifc: &SocIfc) -> u32 {
        let uds_seed_dest = soc_ifc.uds_seed_dest_base_addr_low();

        match self {
            Self::Uds => uds_seed_dest,
            Self::Fe { partition } => {
                // FE partitions start at the same base address with partition spacing (16 bytes each)
                uds_seed_dest + (partition * (FE_PARTITION_SIZE + FUSE_CTRL_DIGEST) as u32) // + 72 BUG!!!
            }
        }
    }

    fn get_fe_digest_address(&self, soc_ifc: &SocIfc) -> CaliptraResult<u32> {
        let uds_seed_dest = soc_ifc.uds_seed_dest_base_addr_low();

        match self {
            Self::Fe { partition } => {
                // FE partition digest address is offset by 8 bytes from partition base
                let digest_addr = uds_seed_dest
                    + (partition * (FE_PARTITION_SIZE + FUSE_CTRL_DIGEST) as u32)
                    + FE_PARTITION_SIZE as u32;
                Ok(digest_addr)
            }
            _ => Err(CaliptraError::RUNTIME_UDS_FE_ZEROIZATION_INTERNAL_ERROR),
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

        let result = {
            // Generate a 512-bit random value.
            let seed: [u32; 16] = trng.generate16()?.into();

            let uds_fuse_row_granularity_64 = soc_ifc.uds_fuse_row_granularity_64();
            let fuse_controller_base_addr = soc_ifc.fuse_controller_base_addr();
            let otp_ctrl = DmaOtpCtrl::new(AxiAddr::from(fuse_controller_base_addr), dma);
            let seed_dest_address = self.get_dest_address(soc_ifc);

            let _ = otp_ctrl.with_regs_mut(|regs| {
                let seed = &seed[..self.seed_length_words()]; // Get random bytes of desired size
                let chunk_size = if uds_fuse_row_granularity_64 { 2 } else { 1 };
                let chunked_seed = seed.chunks(chunk_size);
                for (index, seed_part) in chunked_seed.enumerate() {
                    let dest = seed_dest_address + (index * chunk_size * size_of::<u32>()) as u32;

                    // Poll the STATUS register until the DAI state returns to idle
                    while !regs.status().read().dai_idle() {}

                    let wdata_0 = seed_part[0];
                    regs.dai_wdata_rf().direct_access_wdata_0().write(|_| wdata_0);

                    if let Some(&wdata_1) = seed_part.get(1) {
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

                // Trigger the partition digest operation
                // Poll the STATUS register until the DAI state returns to idle
                while !regs.status().read().dai_idle() {}

                // Write the Seed base address to the DIRECT_ACCESS_ADDRESS register
                cprintln!(
                    "[{}] Triggering the partition digest operation, seed_dest_address: {:#x}",
                    self.prefix(),
                    seed_dest_address
                );
                regs.direct_access_address().write(|w| w.address(seed_dest_address));

                // Trigger the digest calculation command
                cprintln!("[{}] Triggering the digest calculation command", self.prefix());
                regs.direct_access_cmd().write(|w| w.digest(true));

                // Poll the STATUS register until the DAI state returns to idle
                while !regs.status().read().dai_idle() {}

                Ok::<(), CaliptraError>(())
            })?;

            Ok(())
        };

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

    /// Zeroize either UDS (64 bytes) or an FE partition (8 bytes) based on the enum variant
    ///
    /// # Arguments
    /// * `soc_ifc` - SoC interface for accessing fuse controller and related registers
    /// * `dma` - DMA engine for OTP control
    pub fn zeroize_fe(&self, soc_ifc: &mut SocIfc, dma: &Dma) -> CaliptraResult<()> {
        // Validate parameters first
        self.validate()?;

        cprintln!("[{}] ++ Zeroization", self.prefix());

        let result = {
            let uds_fuse_row_granularity_64 = soc_ifc.uds_fuse_row_granularity_64();
            let fuse_controller_base_addr = soc_ifc.fuse_controller_base_addr();
            let otp_ctrl = DmaOtpCtrl::new(AxiAddr::from(fuse_controller_base_addr), dma);

            let partition_base_address = self.get_dest_address(soc_ifc);
            let digest_address = self.get_fe_digest_address(soc_ifc);
            // let zer_address = self.get_zer_address(soc_ifc); // Zeroization marker address // [TODO] What is this address?
            let granularity_step_bytes = if uds_fuse_row_granularity_64 { 8 } else { 4 };

            let _ = otp_ctrl.with_regs_mut(|regs| {
                // Step 1: Clear the Partition Zeroization Flag (64-bit)
                // This step is critical - it masks potential ECC or integrity errors
                // if the process is interrupted by a power failure
                // cprintln!(
                //     "[{}] Step 1: Clearing partition zeroization flag at address: {:#x}",
                //     self.prefix(),
                //     zer_address
                // );

                // while !regs.status().read().dai_idle() {}

                // regs.direct_access_address()
                //     .write(|w| w.address(zer_address));
                // regs.direct_access_cmd().write(|w| w.zer(true));

                // while !regs.status().read().dai_idle() {}

                // // Verify zeroization marker cleared (should be 0xFFFFFFFF)
                // let zer_rdata_0 = regs.dai_rdata_rf().direct_access_rdata_0().read();
                // let zer_rdata_1 = regs.dai_rdata_rf().direct_access_rdata_1().read();

                // if zer_rdata_0 != 0xFFFFFFFF || zer_rdata_1 != 0xFFFFFFFF {
                //     cprintln!(
                //         "[{}] ERROR: Zeroization marker not cleared, rdata: {:#x}_{:#x}",
                //         self.prefix(),
                //         zer_rdata_1,
                //         zer_rdata_0
                //     );
                //     return Err(CaliptraError::RUNTIME_FE_ZEROIZATION_FAILED);
                // }

                // Loop over the partition data words and zeroize them
                for (idx: 0; idx < ) {

                }

                // Step 2: Zeroize all data words in the partition
                cprintln!(
                    "[{}] Step 2: Zeroizing data words from {:#x} to {:#x}",
                    self.prefix(),
                    partition_base_address,
                    digest_address
                );

                let mut addr = partition_base_address;
                while addr < digest_address {
                    while !regs.status().read().dai_idle() {}

                    cprintln!("[{}] Zeroizing data at address: {:#x}", self.prefix(), addr);
                    regs.direct_access_address().write(|w| w.address(addr));
                    regs.direct_access_cmd().write(|w| w.zer(true));

                    while !regs.status().read().dai_idle() {}

                    // Verify zeroization - should return 0xFFFFFFFF for all bits
                    let rdata_0 = regs.dai_rdata_rf().direct_access_rdata_0().read();
                    if rdata_0 != 0xFFFFFFFF {
                        cprintln!(
                            "[{}] ERROR: Data at {:#x} not zeroized, rdata_0: {:#x}",
                            self.prefix(),
                            addr,
                            rdata_0
                        );
                        return Err(CaliptraError::ROM_GLOBAL_ZEROIZATION_FAILED);
                    }

                    if granularity > 32 {
                        let rdata_1 = regs.dai_rdata_rf().direct_access_rdata_1().read();
                        if rdata_1 != 0xFFFFFFFF {
                            cprintln!(
                                "[{}] ERROR: Data at {:#x} not zeroized, rdata_1: {:#x}",
                                self.prefix(),
                                addr,
                                rdata_1
                            );
                            return Err(CaliptraError::ROM_GLOBAL_ZEROIZATION_FAILED);
                        }
                    }

                    addr += granularity_bytes;
                }

                // Step 3: Clear the partition digest (always 64-bit)
                cprintln!(
                    "[{}] Step 3: Clearing partition digest at address: {:#x}",
                    self.prefix(),
                    digest_address
                );

                while !regs.status().read().dai_idle() {}

                regs.direct_access_address()
                    .write(|w| w.address(digest_address));
                regs.direct_access_cmd().write(|w| w.zer(true));

                while !regs.status().read().dai_idle() {}

                // Verify digest cleared
                let digest_rdata_0 = regs.dai_rdata_rf().direct_access_rdata_0().read();
                let digest_rdata_1 = regs.dai_rdata_rf().direct_access_rdata_1().read();

                if digest_rdata_0 != 0xFFFFFFFF || digest_rdata_1 != 0xFFFFFFFF {
                    cprintln!(
                        "[{}] ERROR: Partition digest not cleared, rdata: {:#x}_{:#x}",
                        self.prefix(),
                        digest_rdata_1,
                        digest_rdata_0
                    );
                    return Err(CaliptraError::ROM_GLOBAL_ZEROIZATION_FAILED);
                }

                cprintln!("[{}] Partition successfully zeroized", self.prefix());
                Ok::<(), CaliptraError>(())
            })?;

            Ok(())
        };

        cprintln!(
            "[{}] -- Zeroization completed with status: {}",
            self.prefix(),
            if result.is_ok() { "SUCCESS" } else { "FAILURE" }
        );

        result
    }
}

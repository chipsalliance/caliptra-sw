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

const UDS_SEED_SIZE_BYTES: usize = 64;
const DIGEST_SIZE_BYTES: usize = 8;
const FE_PARTITION_SEED_SIZE_BYTES: usize = 8;
const ZEROIZATION_MARKER_SIZE_BYTES: usize = 8;
const FE_PARTITION_SIZE_BYTES: usize =
    FE_PARTITION_SEED_SIZE_BYTES + DIGEST_SIZE_BYTES + ZEROIZATION_MARKER_SIZE_BYTES;
pub const FE_MAX_PARTITIONS: u32 = 4;
// OTP Direct Access Register Offsets (relative to DIRECT_ACCESS_CMD)
const DIRECT_ACCESS_ADDRESS_OFFSET: u64 = 0x4;
const DIRECT_ACCESS_WDATA_0_OFFSET: u64 = 0x8;
const DIRECT_ACCESS_WDATA_1_OFFSET: u64 = 0xC;
const DIRECT_ACCESS_RDATA_0_OFFSET: u64 = 0x10;
const DIRECT_ACCESS_RDATA_1_OFFSET: u64 = 0x14;

#[derive(Default)]
struct SeedConfig {
    address: u32,
    length_bytes: u32,
}
/// OTP Controller configuration for UDS/FE programming operations
#[derive(Default)]
struct OtpCtrlConfig {
    uds_fuse_row_granularity_64: bool,
    fuse_controller_base_addr: u64,
    seed_config: SeedConfig,
    dai_idle_bit_num: u32,
    direct_access_cmd_reg_addr: u64,
    direct_access_address_reg_addr: u64,
    direct_access_wdata_0_reg_addr: u64,
    direct_access_wdata_1_reg_addr: u64,
    direct_access_rdata_0_reg_addr: u64,
    direct_access_rdata_1_reg_addr: u64,
}

impl UdsFeProgrammingFlow {
    /// Initialize OTP controller configuration from SoC interface
    fn init_otp_config(&self, soc_ifc: &SocIfc) -> OtpCtrlConfig {
        let uds_fuse_row_granularity_64 = soc_ifc.uds_fuse_row_granularity_64();
        let fuse_controller_base_addr = soc_ifc.fuse_controller_base_addr();
        let seed_config = self.get_seed_config(soc_ifc);
        let dai_idle_bit_num = soc_ifc.otp_dai_idle_bit_num();
        let direct_access_cmd_reg_addr =
            fuse_controller_base_addr + soc_ifc.otp_direct_access_cmd_reg_offset() as u64;
        let direct_access_address_reg_addr =
            direct_access_cmd_reg_addr + DIRECT_ACCESS_ADDRESS_OFFSET;
        let direct_access_wdata_0_reg_addr =
            direct_access_cmd_reg_addr + DIRECT_ACCESS_WDATA_0_OFFSET;
        let direct_access_wdata_1_reg_addr =
            direct_access_cmd_reg_addr + DIRECT_ACCESS_WDATA_1_OFFSET;
        let direct_access_rdata_0_reg_addr =
            direct_access_cmd_reg_addr + DIRECT_ACCESS_RDATA_0_OFFSET;
        let direct_access_rdata_1_reg_addr =
            direct_access_cmd_reg_addr + DIRECT_ACCESS_RDATA_1_OFFSET;

        OtpCtrlConfig {
            uds_fuse_row_granularity_64,
            fuse_controller_base_addr,
            seed_config,
            dai_idle_bit_num,
            direct_access_cmd_reg_addr,
            direct_access_address_reg_addr,
            direct_access_wdata_0_reg_addr,
            direct_access_wdata_1_reg_addr,
            direct_access_rdata_0_reg_addr,
            direct_access_rdata_1_reg_addr,
        }
    }

    /// Validates the programming flow parameters
    pub fn validate(self) -> CaliptraResult<()> {
        match self {
            UdsFeProgrammingFlow::Uds => Ok(()),
            UdsFeProgrammingFlow::Fe { partition } => {
                if partition >= FE_MAX_PARTITIONS {
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
            UdsFeProgrammingFlow::Uds => UDS_SEED_SIZE_BYTES / size_of::<u32>(), // 64 bytes = 16 u32 words
            UdsFeProgrammingFlow::Fe { partition: _ } => {
                FE_PARTITION_SEED_SIZE_BYTES / size_of::<u32>()
            } // 8 bytes = 2 u32 words
        }
    }

    /// Returns the prefix string for logging
    fn prefix(self) -> &'static str {
        match self {
            UdsFeProgrammingFlow::Uds => "uds",
            UdsFeProgrammingFlow::Fe { partition: _ } => "fe",
        }
    }

    //
    //         OTP Controller Memory Map
    //
    // +-------------------------------------+ <- uds_seed_dest_base_addr_low()
    // |        UDS Region (64 bytes)        |
    // +-------------------------------------+
    // |        UDS Digest (8 bytes)         |
    // +-------------------------------------+
    // |    Zeroization Marker (8 bytes)     |
    // +-------------------------------------+
    // +-------------------------------------+ <- FE Base = uds_seed_dest_base_addr_low() + UDS Region + UDS Digest + Zeroization Marker
    // |    FE Partition 0  (8 bytes)        |
    // +-------------------------------------+ <- FE Base + 8
    // |   FE Partition 0 Digest (8 bytes)   |
    // +-------------------------------------+ <- FE Base + 16
    // |    Zeroization Marker (8 bytes)     |
    // +-------------------------------------+
    // +-------------------------------------+ <- FE Base + (1 * 24)
    // |    FE Partition 1  (8 bytes)        |
    // +-------------------------------------+ <- FE Base + (1 * 24) + 8
    // |   FE Partition 1 Digest (8 bytes)   |
    // +-------------------------------------+ <- FE Base + (1 * 24) + 16
    // |    Zeroization Marker (8 bytes)     |
    // +-------------------------------------+
    // +-------------------------------------+ <- FE Base + (2 * 24)
    // |    FE Partition 2  (8 bytes)        |
    // +-------------------------------------+ <- FE Base + (2 * 24) + 8
    // |   FE Partition 2 Digest (8 bytes)   |
    // +-------------------------------------+ <- FE Base + (2 * 24) + 16
    // |    Zeroization Marker (8 bytes)     |
    // +-------------------------------------+
    // +-------------------------------------+ <- FE Base + (3 * 24)
    // |    FE Partition 3  (8 bytes)        |
    // +-------------------------------------+ <- FE Base + (3 * 24) + 8
    // |   FE Partition 3 Digest (8 bytes)   |
    // +-------------------------------------+ <- FE Base + (3 * 24) + 16
    // |    Zeroization Marker (8 bytes)     |
    // +-------------------------------------+

    fn get_seed_config(&self, soc_ifc: &SocIfc) -> SeedConfig {
        let uds_seed_dest = soc_ifc.uds_seed_dest_base_addr_low();

        match self {
            Self::Uds => SeedConfig {
                address: uds_seed_dest,
                length_bytes: UDS_SEED_SIZE_BYTES as u32,
            },
            Self::Fe { partition } => SeedConfig {
                address: uds_seed_dest
                    + UDS_SEED_SIZE_BYTES as u32
                    + DIGEST_SIZE_BYTES as u32
                    + ZEROIZATION_MARKER_SIZE_BYTES as u32
                    + (partition * FE_PARTITION_SIZE_BYTES as u32),
                length_bytes: FE_PARTITION_SEED_SIZE_BYTES as u32,
            },
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
            soc_ifc.set_uds_programming_flow_state(true);
        }

        let result = {
            // Generate a 512-bit random value.
            let seed: [u32; 16] = trng.generate16()?.into();
            let config = self.init_otp_config(soc_ifc);
            let otp_ctrl = DmaOtpCtrl::new(AxiAddr::from(config.fuse_controller_base_addr), dma);

            let _ = otp_ctrl.with_regs_mut(|regs| {
                // Helper function to check if DAI is idle using the configurable bit number
                let is_dai_idle = || -> bool {
                    let status: u32 = regs.status().read().into();
                    (status & (1 << config.dai_idle_bit_num)) != 0
                };

                let seed = &seed[..self.seed_length_words()]; // Get random bytes of desired size
                let chunk_size = if config.uds_fuse_row_granularity_64 {
                    2
                } else {
                    1
                };
                let chunked_seed = seed.chunks(chunk_size);
                for (index, seed_part) in chunked_seed.enumerate() {
                    let dest =
                        config.seed_config.address + (index * chunk_size * size_of::<u32>()) as u32;

                    // Poll the STATUS register until the DAI state returns to idle
                    while !is_dai_idle() {}

                    // Write seed data to WDATA registers using DMA
                    let wdata_0 = seed_part[0];
                    dma.write_dword(
                        AxiAddr::from(config.direct_access_wdata_0_reg_addr),
                        wdata_0,
                    );

                    if let Some(&wdata_1) = seed_part.get(1) {
                        dma.write_dword(
                            AxiAddr::from(config.direct_access_wdata_1_reg_addr),
                            wdata_1,
                        );
                    }

                    // Write the Seed destination address to the DIRECT_ACCESS_ADDRESS register
                    dma.write_dword(
                        AxiAddr::from(config.direct_access_address_reg_addr),
                        dest & 0xFFF,
                    );

                    // Trigger the seed write command
                    dma.write_dword(AxiAddr::from(config.direct_access_cmd_reg_addr), 0b10);
                    // bit 1 = 1 for WR
                }

                // Trigger the partition digest operation
                // Poll the STATUS register until the DAI state returns to idle
                while !is_dai_idle() {}

                // Write the Seed base address to the DIRECT_ACCESS_ADDRESS register for digest operation.
                dma.write_dword(
                    AxiAddr::from(config.direct_access_address_reg_addr),
                    config.seed_config.address & 0xFFF,
                );

                // Trigger the digest calculation command
                dma.write_dword(AxiAddr::from(config.direct_access_cmd_reg_addr), 0b100); // bit 2 = 1 for DIGEST

                // Poll the STATUS register until the DAI state returns to idle
                while !is_dai_idle() {}

                Ok::<(), CaliptraError>(())
            })?;

            Ok(())
        };

        if self.is_uds() {
            // Set the programming result.
            soc_ifc.set_uds_programming_flow_status(result.is_ok());

            // Update the programming state.
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
    pub fn zeroize(&self, soc_ifc: &mut SocIfc, dma: &Dma) -> CaliptraResult<()> {
        // Validate parameters first
        self.validate()?;

        cprintln!("[{}] ++ Zeroization", self.prefix());

        const DAI_CMD_ZEROIZE: u32 = 0b1000;

        let config = self.init_otp_config(soc_ifc);
        let otp_ctrl = DmaOtpCtrl::new(AxiAddr::from(config.fuse_controller_base_addr), dma);

        let digest_address = config.seed_config.address + config.seed_config.length_bytes;
        let zeroization_marker_address = digest_address + DIGEST_SIZE_BYTES as u32;
        let granularity_step_bytes = if config.uds_fuse_row_granularity_64 {
            8
        } else {
            4
        };
        let granularity_step_words = granularity_step_bytes / size_of::<u32>();

        let _ = otp_ctrl.with_regs_mut(|regs| {
            // Helper to wait for DAI idle state
            let wait_dai_idle = || loop {
                let status: u32 = regs.status().read().into();
                if (status & (1 << config.dai_idle_bit_num)) != 0 {
                    break;
                }
            };

            // Helper to write address and execute DAI command
            let execute_dai_cmd = |address: u32, cmd: u32| {
                wait_dai_idle();
                dma.write_dword(
                    AxiAddr::from(config.direct_access_address_reg_addr),
                    address & 0xFFF,
                );
                dma.write_dword(AxiAddr::from(config.direct_access_cmd_reg_addr), cmd);
                wait_dai_idle();
            };

            // Helper to verify both rdata registers are 0xFFFFFFFF
            let verify_cleared = |error: CaliptraError| -> CaliptraResult<()> {
                let rdata_0 = dma.read_dword(AxiAddr::from(config.direct_access_rdata_0_reg_addr));
                let rdata_1 = dma.read_dword(AxiAddr::from(config.direct_access_rdata_1_reg_addr));

                if rdata_0 != 0xFFFFFFFF || rdata_1 != 0xFFFFFFFF {
                    Err(error)
                } else {
                    Ok(())
                }
            };

            // Step 1: Clear the Partition Zeroization Marker (64-bit)
            // This step is critical - it masks potential ECC or integrity errors
            // if the process is interrupted by a power failure
            execute_dai_cmd(zeroization_marker_address, DAI_CMD_ZEROIZE);
            verify_cleared(CaliptraError::UDS_FE_ZEROIZATION_MARKER_NOT_CLEARED)?;

            // Step 2: Zeroize all data words in the partition
            let mut addr = config.seed_config.address;
            let mut words_remaining = config.seed_config.length_bytes / 4;

            while words_remaining > 0 {
                execute_dai_cmd(addr, DAI_CMD_ZEROIZE);

                // Verify zeroization - should return 0xFFFFFFFF for all bits
                let rdata_0 = dma.read_dword(AxiAddr::from(config.direct_access_rdata_0_reg_addr));
                if rdata_0 != 0xFFFFFFFF {
                    Err(CaliptraError::UDS_FE_ZEROIZATION_SEED_NOT_CLEARED)?;
                }

                if config.uds_fuse_row_granularity_64 {
                    let rdata_1 =
                        dma.read_dword(AxiAddr::from(config.direct_access_rdata_1_reg_addr));
                    if rdata_1 != 0xFFFFFFFF {
                        Err(CaliptraError::UDS_FE_ZEROIZATION_SEED_NOT_CLEARED)?;
                    }
                }

                addr += granularity_step_bytes as u32;
                words_remaining -= granularity_step_words as u32;
            }

            // Step 3: Clear the partition digest (always 64-bit)
            execute_dai_cmd(digest_address, DAI_CMD_ZEROIZE);
            verify_cleared(CaliptraError::UDS_FE_ZEROIZATION_DIGEST_NOT_CLEARED)?;

            Ok::<(), CaliptraError>(())
        })?;

        cprintln!("[{}] -- Zeroization completed", self.prefix());

        Ok(())
    }
}

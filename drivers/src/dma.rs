/*++

Licensed under the Apache-2.0 license.

File Name:

    dma.rs

Abstract:

    File contains API for DMA Widget operations

--*/

use crate::cprintln;
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::axi_dma::{
    enums::{RdRouteE, WrRouteE},
    AxiDmaReg, RegisterBlock,
};
use caliptra_registers::i3ccsr::RegisterBlock as I3CRegisterBlock;
use core::{cell::Cell, mem::size_of, ops::Add};
use ureg::{Mmio, MmioMut, RealMmioMut};
use zerocopy::IntoBytes;

pub enum DmaReadTarget {
    Mbox(u32),
    AhbFifo,
    AxiWr(AxiAddr, bool),
}

#[derive(Debug, Clone, Copy)]
pub struct AxiAddr {
    pub lo: u32,
    pub hi: u32,
}

impl Add<u32> for AxiAddr {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        AxiAddr::from(u64::from(self) + rhs as u64)
    }
}

impl Add<u64> for AxiAddr {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        AxiAddr::from(u64::from(self) + rhs)
    }
}

impl Add<usize> for AxiAddr {
    type Output = Self;

    fn add(self, rhs: usize) -> Self {
        AxiAddr::from(u64::from(self) + rhs as u64)
    }
}

impl From<u32> for AxiAddr {
    fn from(addr: u32) -> Self {
        Self { lo: addr, hi: 0 }
    }
}

impl From<u64> for AxiAddr {
    fn from(addr: u64) -> Self {
        Self {
            lo: addr as u32,
            hi: (addr >> 32) as u32,
        }
    }
}
impl From<AxiAddr> for u64 {
    fn from(addr: AxiAddr) -> Self {
        (addr.hi as u64) << 32 | (addr.lo as u64)
    }
}

impl Add for AxiAddr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let self_u64: u64 = self.into();
        let rhs_u64: u64 = rhs.into();
        let sum = self_u64 + rhs_u64;
        sum.into()
    }
}

pub struct DmaReadTransaction {
    pub read_addr: AxiAddr,
    pub fixed_addr: bool,
    pub length: u32,
    pub target: DmaReadTarget,
}

pub enum DmaWriteOrigin {
    Mbox(u32),
    AhbFifo,
    AxiRd(AxiAddr),
}

pub struct DmaWriteTransaction {
    pub write_addr: AxiAddr,
    pub fixed_addr: bool,
    pub length: u32,
    pub origin: DmaWriteOrigin,
}

/// Dma Widget
/// Safety: only one instance of the DMA widget should be created.
#[derive(Default)]
pub struct Dma {}

impl Dma {
    /// Safety: This should never be called in a nested manner to avoid
    /// programming conflicts with the underlying DMA registers.
    pub fn with_dma<T>(&self, f: impl FnOnce(RegisterBlock<RealMmioMut>) -> T) -> T {
        // Safety: Caliptra is single-threaded and only one caller to with_dma
        // is allowed at a time, so it is safe to create and consume the
        // zero-sized AxiDmaReg here and create a new one each time.
        // Since the Mmio interface is immutable, we can't generate a
        // around mutable reference to a shared AxiDmaReg without using
        // Cell, which bloats the code.
        let mut dma = unsafe { AxiDmaReg::new() };
        f(dma.regs_mut())
    }

    pub fn flush(&self) {
        self.with_dma(|dma| {
            dma.ctrl().write(|c| c.flush(true));
            // Wait till we're not busy and have no errors
            // TODO this assumes the peripheral does not clear that status0 state
            // in one cycle. Maybe it can be removed if the assumption proves false

            while {
                let status0 = dma.status0().read();
                status0.busy() || status0.error()
            } {}
        })
    }

    pub fn setup_dma_read(&self, read_transaction: DmaReadTransaction, block_size: u32) {
        self.with_dma(|dma| {
            let read_addr = read_transaction.read_addr;
            dma.src_addr_l().write(|_| read_addr.lo);
            dma.src_addr_h().write(|_| read_addr.hi);

            let mut target_addr_lo: u32 = 0;
            let mut target_addr_hi: u32 = 0;
            match read_transaction.target {
                DmaReadTarget::AxiWr(target_addr, _) => {
                    target_addr_lo = target_addr.lo;
                    target_addr_hi = target_addr.hi;
                }
                DmaReadTarget::Mbox(offset) => {
                    target_addr_lo = offset;
                    target_addr_hi = 0;
                }
                _ => {}
            }
            dma.dst_addr_l().write(|_| target_addr_lo);
            dma.dst_addr_h().write(|_| target_addr_hi);

            dma.ctrl().modify(|c| {
                c.rd_route(|_| match read_transaction.target {
                    DmaReadTarget::Mbox(_) => RdRouteE::Mbox,
                    DmaReadTarget::AhbFifo => RdRouteE::AhbFifo,
                    DmaReadTarget::AxiWr(_, _) => RdRouteE::AxiWr,
                })
                .rd_fixed(read_transaction.fixed_addr)
                .wr_route(|_| match read_transaction.target {
                    DmaReadTarget::AxiWr(_, _) => WrRouteE::AxiRd,
                    _ => WrRouteE::Disable,
                })
                .wr_fixed(match read_transaction.target {
                    DmaReadTarget::AxiWr(_, fixed) => fixed,
                    _ => false,
                })
            });

            // Set the number of bytes to read.
            dma.byte_count().write(|_| read_transaction.length);

            // Set the block size.
            dma.block_size().write(|f| f.size(block_size));

            // Start the DMA transaction.
            dma.ctrl().modify(|c| c.go(true));
        })
    }

    fn setup_dma_write(&self, write_transaction: DmaWriteTransaction, block_size: u32) {
        self.with_dma(|dma| {
            let write_addr = write_transaction.write_addr;
            dma.dst_addr_l().write(|_| write_addr.lo);
            dma.dst_addr_h().write(|_| write_addr.hi);

            let mut source_addr_lo: u32 = 0;
            let mut source_addr_hi: u32 = 0;
            match write_transaction.origin {
                DmaWriteOrigin::AxiRd(origin_addr) => {
                    source_addr_lo = origin_addr.lo;
                    source_addr_hi = origin_addr.hi;
                }
                DmaWriteOrigin::Mbox(offset) => {
                    source_addr_lo = offset;
                    source_addr_hi = 0;
                }
                _ => {}
            }
            dma.src_addr_l().write(|_| source_addr_lo);
            dma.src_addr_h().write(|_| source_addr_hi);

            dma.ctrl().modify(|c| {
                c.wr_route(|_| match write_transaction.origin {
                    DmaWriteOrigin::Mbox(_) => WrRouteE::Mbox,
                    DmaWriteOrigin::AhbFifo => WrRouteE::AhbFifo,
                    DmaWriteOrigin::AxiRd(_) => WrRouteE::AxiRd,
                })
                .wr_fixed(write_transaction.fixed_addr)
                .rd_route(|_| match write_transaction.origin {
                    DmaWriteOrigin::AxiRd(_) => RdRouteE::AxiWr,
                    _ => RdRouteE::Disable,
                })
                .rd_fixed(false)
            });

            // Set the number of bytes to write.
            dma.byte_count().write(|_| write_transaction.length);

            // Set the block size.
            dma.block_size().write(|f| f.size(block_size));

            // Start the DMA transaction.
            dma.ctrl().modify(|c| c.go(true));
        })
    }

    /// Wait for the DMA transaction to complete
    ///
    /// This function will block until the DMA transaction is completed successfully.
    fn wait_for_dma_complete(&self) {
        self.with_dma(|dma| while dma.status0().read().busy() {});
    }

    /// Read data from the DMA FIFO
    ///
    /// # Arguments
    ///
    /// * `read_data` - Buffer to store the read data
    ///
    /// # Returns
    ///
    /// * `CaliptraResult<()>` - Success or error code
    fn dma_read_fifo(&self, read_data: &mut [u8]) -> CaliptraResult<()> {
        self.with_dma(|dma| {
            // Only multiple of 4 bytes are allowed
            if read_data.len() % core::mem::size_of::<u32>() != 0 {
                return Err(CaliptraError::DRIVER_DMA_FIFO_INVALID_SIZE);
            }

            // Process all 4-byte chunks
            read_data.chunks_mut(4).for_each(|word| {
                // Wait until the FIFO has data. fifo_depth is in DWORDs.
                while dma.status0().read().fifo_depth() == 0 {}

                let read = &dma.read_data().read().to_le_bytes();
                // check needed so that the compiler doesn't generate a panic
                if read.len() == word.len() {
                    word.copy_from_slice(read);
                }
            });
            Ok(())
        })
    }

    fn dma_write_fifo(&self, write_data: &[u8]) -> CaliptraResult<()> {
        self.with_dma(|dma| {
            if write_data.len() % 4 != 0 {
                Err(CaliptraError::DRIVER_DMA_FIFO_INVALID_SIZE)?;
            }

            // Process all 4-byte chunks
            let max_fifo_depth = dma.cap().read().fifo_max_depth();
            write_data.chunks(4).for_each(|word| {
                // Wait until the FIFO has space. fifo_depth is in DWORDs.
                while max_fifo_depth == dma.status0().read().fifo_depth() {}

                dma.write_data()
                    .write(|_| u32::from_le_bytes(word.try_into().unwrap_or_default()));
            });

            Ok(())
        })
    }

    /// Read a 32-bit word from the specified address
    ///
    /// # Arguments
    ///
    /// * `read_addr` - Address to read from
    ///
    /// # Returns
    ///
    /// * `CaliptraResult<u32>` - Read value or error code
    pub fn read_dword(&self, read_addr: AxiAddr) -> CaliptraResult<u32> {
        let mut read_val: u32 = 0;
        self.read_buffer(read_addr, read_val.as_mut_bytes())?;
        Ok(read_val)
    }

    /// Read an arbitrary length buffer to fifo and read back the fifo into the provided buffer
    ///
    /// # Arguments
    ///
    /// * `read_addr` - Address to read from
    /// * `buffer`  - Target location to read to
    ///
    /// # Returns
    ///
    /// * CaliptraResult<()> - Success or failure
    pub fn read_buffer(&self, read_addr: AxiAddr, buffer: &mut [u8]) -> CaliptraResult<()> {
        self.flush();

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr: false,
            length: buffer.len() as u32,
            target: DmaReadTarget::AhbFifo,
        };

        self.setup_dma_read(read_transaction, 0);
        self.dma_read_fifo(buffer)?;
        self.wait_for_dma_complete();
        Ok(())
    }

    /// Write a 32-bit word to the specified address
    ///
    /// # Arguments
    ///
    /// * `write_addr` - Address to write to
    /// * `write_val` - Value to write
    ///
    /// # Returns
    ///
    /// * `CaliptraResult<()>` - Success or error code
    pub fn write_dword(&self, write_addr: AxiAddr, write_val: u32) -> CaliptraResult<()> {
        self.flush();

        let write_transaction = DmaWriteTransaction {
            write_addr,
            fixed_addr: false,
            length: core::mem::size_of::<u32>() as u32,
            origin: DmaWriteOrigin::AhbFifo,
        };
        self.setup_dma_write(write_transaction, 0);
        self.dma_write_fifo(write_val.as_bytes())?;
        self.wait_for_dma_complete();
        Ok(())
    }

    /// Indicates if payload is available.
    ///
    /// # Returns
    /// true if payload is available, false otherwise
    ///
    pub fn payload_available(&self) -> bool {
        self.with_dma(|dma| dma.status0().read().payload_available())
    }
}

// Implementation of the Mmio and MmioMut traits that uses
// the DMA peripheral to implement the actual reads and writes.
pub struct DmaMmio<'a> {
    base: AxiAddr,
    dma: &'a Dma,
    last_error: Cell<Option<CaliptraError>>,
}

impl<'a> DmaMmio<'a> {
    pub fn new(base: AxiAddr, dma: &'a Dma) -> Self {
        Self {
            base,
            dma,
            last_error: Cell::new(None),
        }
    }

    pub fn check_error<T>(&self, x: T) -> CaliptraResult<T> {
        match self.last_error.take() {
            Some(err) => Err(err),
            None => Ok(x),
        }
    }

    fn set_error(&self, err: Option<CaliptraError>) {
        self.last_error.set(self.last_error.take().or(err));
    }
}

impl<'a> Mmio for &DmaMmio<'a> {
    #[inline(always)]
    unsafe fn read_volatile<T: ureg::Uint>(&self, src: *const T) -> T {
        // we only support 32-bit reads
        if T::TYPE != ureg::UintType::U32 {
            unreachable!();
        }
        let offset = src as usize;
        let a = self.dma.read_dword(self.base + offset);
        self.set_error(a.err());
        // try_into() will always succeed since we only support u32
        a.unwrap_or_default().try_into().unwrap_or_default()
    }
}

impl<'a> MmioMut for &DmaMmio<'a> {
    #[inline(always)]
    unsafe fn write_volatile<T: ureg::Uint>(&self, dst: *mut T, src: T) {
        // we only support 32-bit writes
        if T::TYPE != ureg::UintType::U32 {
            unreachable!();
        }
        // this will always work because we only support u32
        if let Ok(src) = src.try_into() {
            let offset = dst as usize;
            let result = self.dma.write_dword(self.base + offset, src);
            self.set_error(result.err());
        }
    }
}

// Wrapper around the DMA peripheral that provides access to the I3C recovery interface.
pub struct DmaRecovery<'a> {
    base: AxiAddr,
    mci_base: AxiAddr,
    dma: &'a Dma,
}

impl<'a> DmaRecovery<'a> {
    const RECOVERY_REGISTER_OFFSET: usize = 0x100;
    const INDIRECT_FIFO_DATA_OFFSET: u32 = 0x68;
    const RECOVERY_DMA_BLOCK_SIZE_BYTES: u32 = 256;
    const PROT_CAP2_FLASHLESS_BOOT_BIT: u32 = 11;
    const MCU_SRAM_OFFSET: u64 = 0x20_0000;

    const FLASHLESS_STREAMING_BOOT_VALUE: u32 = 0x12;
    const READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE: u32 = 0x3;

    pub const RECOVERY_STATUS_AWAITING_RECOVERY_IMAGE: u32 = 0x1;
    const RECOVERY_STATUS_BOOTING_RECOVERY_IMAGE: u32 = 0x2;
    pub const RECOVERY_STATUS_IMAGE_AUTHENTICATION_ERROR: u32 = 0xD;
    pub const RECOVERY_STATUS_SUCCESSFUL: u32 = 0x3;
    const RECOVERY_STATUS_RUNNING_RECOVERY_IMAGE: u32 = 0x5;

    const DEVICE_RECOVERY_STATUS_PENDING: u32 = 0x4;

    const ACTIVATE_RECOVERY_IMAGE_CMD: u32 = 0xF;

    const RESET_VAL: u32 = 0x1;

    #[inline(always)]
    pub fn new(base: AxiAddr, mci_base: AxiAddr, dma: &'a Dma) -> Self {
        Self {
            base,
            mci_base,
            dma,
        }
    }

    /// Returns a register block that can be used to read
    /// registers from this peripheral, but cannot write.
    #[inline(always)]
    pub fn with_regs<T, F>(&self, f: F) -> CaliptraResult<T>
    where
        F: FnOnce(I3CRegisterBlock<&DmaMmio>) -> T,
    {
        let mmio = DmaMmio::new(self.base, self.dma);
        // SAFETY: we aren't referencing memory directly
        let regs = unsafe {
            I3CRegisterBlock::new_with_mmio(
                // substract the recovery offset since all recovery registers are relative to it
                core::ptr::null_mut::<u32>()
                    .sub(Self::RECOVERY_REGISTER_OFFSET / core::mem::size_of::<u32>()),
                &mmio,
            )
        };
        let t = f(regs);
        mmio.check_error(t)
    }

    /// Return a register block that can be used to read and
    /// write this peripheral's registers.
    #[inline(always)]
    pub fn with_regs_mut<T, F>(&self, f: F) -> CaliptraResult<T>
    where
        F: FnOnce(I3CRegisterBlock<&DmaMmio>) -> T,
    {
        let mmio = DmaMmio::new(self.base, self.dma);
        // SAFETY: we aren't referencing memory directly
        let regs = unsafe {
            I3CRegisterBlock::new_with_mmio(
                // substract the recovery offset since all recovery registers are relative to it
                core::ptr::null_mut::<u32>()
                    .sub(Self::RECOVERY_REGISTER_OFFSET / core::mem::size_of::<u32>()),
                &mmio,
            )
        };
        let t = f(regs);
        mmio.check_error(t)
    }

    fn transfer_payload_to_mbox(
        &self,
        read_addr: AxiAddr,
        payload_len_bytes: u32,
        fixed_addr: bool,
        block_size: u32,
        offset: u32,
    ) -> CaliptraResult<()> {
        self.dma.flush();

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr,
            length: payload_len_bytes,
            target: DmaReadTarget::Mbox(offset),
        };
        self.dma.setup_dma_read(read_transaction, block_size);
        self.dma.wait_for_dma_complete();
        Ok(())
    }

    fn transfer_payload_to_axi(
        &self,
        read_addr: AxiAddr,
        payload_len_bytes: u32,
        write_addr: AxiAddr,
        fixed_addr: bool,
        block_size: u32,
    ) -> CaliptraResult<()> {
        self.dma.flush();

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr,
            length: payload_len_bytes,
            target: DmaReadTarget::AxiWr(write_addr, false),
        };
        self.dma.setup_dma_read(read_transaction, block_size);
        self.dma.wait_for_dma_complete();
        Ok(())
    }

    pub fn transfer_mailbox_to_axi(
        &self,
        payload_len_bytes: u32,
        block_size: u32,
        write_addr: AxiAddr,
        fixed_addr: bool,
        offset: u32,
    ) -> CaliptraResult<()> {
        self.dma.flush();

        let write_transaction = DmaWriteTransaction {
            write_addr,
            fixed_addr,
            length: payload_len_bytes,
            origin: DmaWriteOrigin::Mbox(offset),
        };
        self.dma.setup_dma_write(write_transaction, block_size);
        self.dma.wait_for_dma_complete();
        Ok(())
    }

    // Downloads an image from the recovery interface to the mailbox SRAM.
    pub fn download_image_to_mbox(
        &self,
        fw_image_index: u32,
        caliptra_fw: bool,
    ) -> CaliptraResult<u32> {
        let image_size_bytes = self.request_image(fw_image_index, caliptra_fw)?;
        // Transfer the image from the recovery interface to the mailbox SRAM.
        let addr = self.base + Self::INDIRECT_FIFO_DATA_OFFSET;
        self.transfer_payload_to_mbox(
            addr,
            image_size_bytes,
            true,
            Self::RECOVERY_DMA_BLOCK_SIZE_BYTES,
            0,
        )?;
        self.wait_for_activation()?;
        // Set the RECOVERY_STATUS:Byte0 Bit[3:0] to 0x2 ('Booting recovery image').
        self.set_recovery_status(Self::RECOVERY_STATUS_BOOTING_RECOVERY_IMAGE)?;
        Ok(image_size_bytes)
    }

    pub fn wait_for_activation(&self) -> CaliptraResult<()> {
        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();
            // Set device status to recovery pending to request activation
            recovery
                .device_status_0()
                .modify(|val| val.dev_status(Self::DEVICE_RECOVERY_STATUS_PENDING));

            // Read RECOVERY_CTRL Byte[2] (3rd byte) for 'Activate Recovery Image' (0xF) command.
            while recovery.recovery_ctrl().read().activate_rec_img()
                != Self::ACTIVATE_RECOVERY_IMAGE_CMD
            {}
        })
    }

    // Downloads an image from the recovery interface to the MCU SRAM.
    pub fn download_image_to_mcu(
        &self,
        fw_image_index: u32,
        caliptra_fw: bool,
    ) -> CaliptraResult<u32> {
        let image_size_bytes = self.request_image(fw_image_index, caliptra_fw)?;
        let addr = self.base + Self::INDIRECT_FIFO_DATA_OFFSET;
        cprintln!("[dma-recovery] Uploading image to MCU SRAM");
        self.transfer_payload_to_axi(
            addr,
            image_size_bytes,
            self.mci_base + Self::MCU_SRAM_OFFSET,
            true,
            Self::RECOVERY_DMA_BLOCK_SIZE_BYTES,
        )?;
        self.wait_for_activation()?;
        // Set the RECOVERY_STATUS:Byte0 Bit[3:0] to 0x2 ('Booting recovery image').
        self.set_recovery_status(Self::RECOVERY_STATUS_BOOTING_RECOVERY_IMAGE)?;
        Ok(image_size_bytes)
    }

    // Request the recovery interface load an image.
    pub fn request_image(&self, fw_image_index: u32, caliptra_fw: bool) -> CaliptraResult<u32> {
        cprintln!(
            "[dma-recovery] Requesting recovery image {}",
            fw_image_index
        );

        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();

            // Set PROT_CAP2.AGENT_CAPS Bit11 to 1 ('Flashless boot').
            recovery
                .prot_cap_2()
                .modify(|val| val.agent_caps(Self::PROT_CAP2_FLASHLESS_BOOT_BIT));

            // Set Byte0 Bit[3:0] to 0x1 ('Awaiting recovery image')
            // Set Byte0 Bit[7:4] to recovery image index
            recovery.recovery_status().modify(|recovery_status_val| {
                recovery_status_val
                    .rec_img_index(fw_image_index)
                    .dev_rec_status(Self::RECOVERY_STATUS_AWAITING_RECOVERY_IMAGE)
            });

            if caliptra_fw {
                // the first image is our own firmware, so we needd to set up to receive it
                // Set DEVICE_STATUS:Byte0 to 0x3 ('Recovery mode - ready to accept recovery image').
                // Set DEVICE_STATUS:Byte[2:3] to 0x12 ('Recovery Reason Codes' 0x12 - Flashless/Streaming Boot (FSB)).
                recovery.device_status_0().modify(|val| {
                    val.rec_reason_code(Self::FLASHLESS_STREAMING_BOOT_VALUE)
                        .dev_status(Self::READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE)
                });
            } else {
                // if this is our own firmware, then we must now be running the recovery image,
                // which is necessary to load further images
                // Set DEVICE_STATUS:Byte0 to 0x5 ('Running recovery image').
                recovery
                    .device_status_0()
                    .modify(|val| val.dev_status(Self::RECOVERY_STATUS_RUNNING_RECOVERY_IMAGE));
            }
        })?;

        // Loop on the 'payload_available' signal for the recovery image details to be available.
        while !self.dma.payload_available() {}
        let image_size_bytes = self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();

            // set RESET signal to indirect control to load the nexxt image
            recovery
                .indirect_fifo_ctrl_0()
                .modify(|val| val.reset(Self::RESET_VAL));

            // [TODO][CAP2] we need to program CMS bits, currently they are not available in RDL. Using bytes[4:7] for now for size

            // Read the image size from INDIRECT_FIFO_CTRL0:Byte[2:3] & INDIRECT_FIFO_CTRL1:Byte[0:1]. Image size in DWORDs.
            let image_size_msb = recovery.indirect_fifo_ctrl_0().read().image_size_msb();
            let image_size_lsb = recovery.indirect_fifo_ctrl_1().read().image_size_lsb();

            let image_size_dwords = image_size_msb << 16 | image_size_lsb;
            let image_size_bytes = image_size_dwords * size_of::<u32>() as u32;
            Ok::<u32, CaliptraError>(image_size_bytes)
        })??;

        Ok(image_size_bytes)
    }

    pub fn set_recovery_status(&self, status: u32) -> CaliptraResult<()> {
        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();
            recovery
                .recovery_status()
                .modify(|recovery_status_val| recovery_status_val.dev_rec_status(status));
        })
    }

    // TODO: move to separate MCI struct and use autogenerated registers
    pub fn set_mci_flow_status(&self, status: u32) -> CaliptraResult<()> {
        let mmio = &DmaMmio::new(self.mci_base, self.dma);
        // Safety: 0x24 is the offset for the MCI flow status register
        unsafe { mmio.write_volatile(0x24 as *mut u32, status) };
        mmio.check_error(())
    }
}

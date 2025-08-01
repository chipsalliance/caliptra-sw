/*++

Licensed under the Apache-2.0 license.

File Name:

    dma.rs

Abstract:

    File contains API for DMA Widget operations

--*/

use crate::{cprintln, Array4x12, Array4x16, Sha2_512_384Acc, ShaAccLockState};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::axi_dma::{
    enums::{RdRouteE, WrRouteE},
    AxiDmaReg, RegisterBlock,
};
use caliptra_registers::i3ccsr::RegisterBlock as I3CRegisterBlock;
use caliptra_registers::otp_ctrl::RegisterBlock as FuseCtrlRegisterBlock;
use caliptra_registers::sha512_acc::enums::ShaCmdE;
use caliptra_registers::sha512_acc::RegisterBlock as ShaAccRegisterBlock;
use core::{cell::Cell, mem::size_of, ops::Add};
use ureg::{Mmio, MmioMut, RealMmioMut};

const BLOCK_SIZE: u32 = 256; // Block size for DMA transfers
const MCU_SRAM_OFFSET: u64 = 0xc0_0000;

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
        ((addr.hi as u64) << 32) | (addr.lo as u64)
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

    // This function is used to flush the DMA FIFO and state machine.
    // It does not clear the DMA registers.
    pub fn flush(&self) {
        self.with_dma(|dma| {
            dma.ctrl().write(|c| c.flush(true));

            while {
                let status0 = dma.status0().read();
                status0.busy()
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

            // Set the number of bytes to read.
            dma.byte_count().write(|_| read_transaction.length);

            // Set the block size.
            dma.block_size().write(|f| f.size(block_size));

            dma.ctrl().write(|c| {
                c
                    // AXI read channel is sent where?
                    .rd_route(|_| match read_transaction.target {
                        DmaReadTarget::Mbox(_) => RdRouteE::Mbox,
                        DmaReadTarget::AhbFifo => RdRouteE::AhbFifo,
                        DmaReadTarget::AxiWr(_, _) => RdRouteE::AxiWr,
                    })
                    .rd_fixed(read_transaction.fixed_addr)
                    // AXI write channel comes from where?
                    .wr_route(|_| match read_transaction.target {
                        DmaReadTarget::AxiWr(_, _) => WrRouteE::AxiRd,
                        _ => WrRouteE::Disable,
                    })
                    .wr_fixed(match read_transaction.target {
                        DmaReadTarget::AxiWr(_, fixed) => fixed,
                        _ => false,
                    })
                    .go(true)
            });
        });
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

            // Set the number of bytes to write.
            dma.byte_count().write(|_| write_transaction.length);

            // Set the block size.
            dma.block_size().write(|f| f.size(block_size));

            dma.ctrl().write(|c| {
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
                .go(true)
            });
        })
    }

    /// Wait for the DMA transaction to complete
    ///
    /// This function will block until the DMA transaction is completed successfully.
    /// On a DMA error, this will loop forever.
    fn wait_for_dma_complete(&self) {
        self.with_dma(|dma| while dma.status0().read().busy() {});
    }

    /// Read data from the DMA FIFO
    ///
    /// # Arguments
    ///
    /// * `read_data` - Buffer to store the read data
    ///
    fn dma_read_fifo(&self, read_data: &mut [u32]) {
        self.with_dma(|dma| {
            for word in read_data.iter_mut() {
                // Wait until the FIFO has data. fifo_depth is in DWORDs.
                while dma.status0().read().fifo_depth() == 0 {}

                let read = dma.read_data().read();
                *word = read;
            }
        });
    }

    fn dma_write_fifo(&self, write_data: u32) {
        self.with_dma(|dma| {
            let max_fifo_depth = dma.cap().read().fifo_max_depth();
            while max_fifo_depth == dma.status0().read().fifo_depth() {}

            dma.write_data().write(|_| write_data);
        });
    }

    /// Read a 32-bit word from the specified address
    ///
    /// # Arguments
    ///
    /// * `read_addr` - Address to read from
    ///
    /// # Returns
    ///
    /// * `u32` - Read value
    pub fn read_dword(&self, read_addr: AxiAddr) -> u32 {
        let mut read_val = [0u32; 1];
        self.read_buffer(read_addr, &mut read_val);
        read_val[0]
    }

    /// Read an arbitrary length buffer to fifo and read back the fifo into the provided buffer
    ///
    /// # Arguments
    ///
    /// * `read_addr` - Address to read from
    /// * `buffer`  - Target location to read to
    ///
    pub fn read_buffer(&self, read_addr: AxiAddr, buffer: &mut [u32]) {
        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr: false,
            // Length is in bytes.
            length: buffer.len() as u32 * 4,
            target: DmaReadTarget::AhbFifo,
        };

        self.flush();
        self.setup_dma_read(read_transaction, 0);
        self.dma_read_fifo(buffer);
        self.wait_for_dma_complete();
    }

    /// Write a 32-bit word to the specified address
    ///
    /// # Arguments
    ///
    /// * `write_addr` - Address to write to
    /// * `write_val` - Value to write
    ///
    pub fn write_dword(&self, write_addr: AxiAddr, write_val: u32) {
        let write_transaction = DmaWriteTransaction {
            write_addr,
            fixed_addr: false,
            length: core::mem::size_of::<u32>() as u32,
            origin: DmaWriteOrigin::AhbFifo,
        };
        self.flush();
        self.setup_dma_write(write_transaction, 0);
        self.dma_write_fifo(write_val);
        self.wait_for_dma_complete();
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
}

impl Mmio for &DmaMmio<'_> {
    #[inline(always)]
    unsafe fn read_volatile<T: ureg::Uint>(&self, src: *const T) -> T {
        // we only support 32-bit reads
        if T::TYPE != ureg::UintType::U32 {
            unreachable!();
        }
        let offset = src as usize;
        let a = self.dma.read_dword(self.base + offset);
        // try_into() will always succeed since we only support u32
        a.try_into().unwrap_or_default()
    }
}

impl MmioMut for &DmaMmio<'_> {
    #[inline(always)]
    unsafe fn write_volatile<T: ureg::Uint>(&self, dst: *mut T, src: T) {
        // we only support 32-bit writes
        if T::TYPE != ureg::UintType::U32 {
            unreachable!();
        }
        // this will always work because we only support u32
        if let Ok(src) = src.try_into() {
            let offset = dst as usize;
            self.dma.write_dword(self.base + offset, src);
        }
    }
}

// Wrapper around the DMA peripheral that provides access to the I3C recovery interface.
pub struct DmaRecovery<'a> {
    base: AxiAddr,
    caliptra_base: AxiAddr,
    mci_base: AxiAddr,
    dma: &'a Dma,
}

impl<'a> DmaRecovery<'a> {
    const RECOVERY_REGISTER_OFFSET: usize = 0x100;
    const INDIRECT_FIFO_DATA_OFFSET: u32 = 0x68;
    const PROT_CAP2_DEVICE_ID_SUPPORT: u32 = 0x1; // Bit 0 in agent_caps
    const PROT_CAP2_DEVICE_STATUS_SUPPORT: u32 = 0x10; // Bit 4 in agent_caps
    const PROT_CAP2_PUSH_C_IMAGE_SUPPORT: u32 = 0x80; // Bit 7 in agent_caps
    const PROT_CAP2_FLASHLESS_BOOT_VALUE: u32 = 0x800; // Bit 11 in agent_caps
    const PROT_CAP2_FIFO_CMS_SUPPORT: u32 = 0x1000; // Bit 12 in agent_caps

    const FLASHLESS_STREAMING_BOOT_VALUE: u32 = 0x12;

    pub const RECOVERY_STATUS_AWAITING_RECOVERY_IMAGE: u32 = 0x1;
    const RECOVERY_STATUS_BOOTING_RECOVERY_IMAGE: u32 = 0x2;
    pub const RECOVERY_STATUS_IMAGE_AUTHENTICATION_ERROR: u32 = 0xD;
    pub const RECOVERY_STATUS_SUCCESSFUL: u32 = 0x3;

    pub const DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE: u32 = 0x3;
    const DEVICE_STATUS_PENDING: u32 = 0x4;
    pub const DEVICE_STATUS_RUNNING_RECOVERY_IMAGE: u32 = 0x5;
    pub const DEVICE_STATUS_FATAL_ERROR: u32 = 0xF;

    const ACTIVATE_RECOVERY_IMAGE_CMD: u32 = 0xF;

    const RESET_VAL: u32 = 0x1;
    // offset from the Caliptra base address of the SHA accelerator regs.
    const SHA_ACC_OFFSET: usize = 0x2_1000;

    #[inline(always)]
    pub fn new(base: AxiAddr, caliptra_base: AxiAddr, mci_base: AxiAddr, dma: &'a Dma) -> Self {
        Self {
            base,
            caliptra_base,
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
                // substract the recovery offset since all recovery registers are relative to 0 but need to be relative to 0x100
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
                // substract the recovery offset since all recovery registers are relative to 0 but need to be relative to 0x100
                core::ptr::null_mut::<u32>()
                    .sub(Self::RECOVERY_REGISTER_OFFSET / core::mem::size_of::<u32>()),
                &mmio,
            )
        };
        let t = f(regs);
        mmio.check_error(t)
    }

    fn with_sha_acc<T, F>(&self, f: F) -> CaliptraResult<T>
    where
        F: FnOnce(ShaAccRegisterBlock<&DmaMmio>) -> T,
    {
        let mmio = DmaMmio::new(self.caliptra_base, self.dma);
        // SAFETY: we aren't referencing memory directly
        let regs = unsafe {
            ShaAccRegisterBlock::new_with_mmio(
                // add the accelerator offset since all registers are relative to 0x2100 but need to be relative to 0x0
                core::ptr::null_mut::<u32>()
                    .add(Self::SHA_ACC_OFFSET / core::mem::size_of::<u32>()),
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
        offset: u32,
    ) -> CaliptraResult<()> {
        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr,
            length: payload_len_bytes,
            target: DmaReadTarget::Mbox(offset),
        };
        self.exec_dma_read(read_transaction)?;
        Ok(())
    }

    // Downloads an image from the recovery interface to the mailbox SRAM.
    pub fn download_image_to_mbox(&self, fw_image_index: u32) -> CaliptraResult<u32> {
        let image_size_bytes = self.request_image(fw_image_index)?;
        // Transfer the image from the recovery interface to the mailbox SRAM.
        let addr = self.base + Self::INDIRECT_FIFO_DATA_OFFSET;
        self.transfer_payload_to_mbox(addr, image_size_bytes, true, 0)?;
        cprintln!("[dma-recovery] Waiting for activation");
        self.wait_for_activation()?;
        // Set the RECOVERY_STATUS register 'Device Recovery Status' field to 0x2 ('Booting recovery image').
        self.set_recovery_status(Self::RECOVERY_STATUS_BOOTING_RECOVERY_IMAGE, 0)?;
        Ok(image_size_bytes)
    }

    pub fn wait_for_activation(&self) -> CaliptraResult<()> {
        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();
            // Set device status to 'Recovery Pending (waiting for activation)'.
            recovery
                .device_status_0()
                .modify(|val| val.dev_status(Self::DEVICE_STATUS_PENDING));

            // Read RECOVERY_CTRL register 'Activate Recovery Image' field for 'Activate Recovery Image' (0xF) command.
            while recovery.recovery_ctrl().read().activate_rec_img()
                != Self::ACTIVATE_RECOVERY_IMAGE_CMD
            {}
        })
    }

    // Downloads an image from the recovery interface to the MCU SRAM.
    pub fn download_image_to_mcu(&self, fw_image_index: u32) -> CaliptraResult<u32> {
        let image_size_bytes = self.request_image(fw_image_index)?;
        let addr = self.base + Self::INDIRECT_FIFO_DATA_OFFSET;
        self.transfer_payload_to_axi(
            addr,
            image_size_bytes,
            self.mci_base + MCU_SRAM_OFFSET,
            true,
            false,
        )?;
        self.wait_for_activation()?;
        // Set the RECOVERY_STATUS:Byte0 Bit[3:0] to 0x2 ('Booting recovery image').
        self.set_recovery_status(Self::RECOVERY_STATUS_BOOTING_RECOVERY_IMAGE, 0)?;
        Ok(image_size_bytes)
    }

    /// Load data from MCU SRAM to a provided buffer
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset within MCU SRAM to read from
    /// * `buffer` - Buffer to store the read data
    ///
    pub fn load_from_mcu_to_buffer(&self, offset: u64, buffer: &mut [u32]) -> CaliptraResult<()> {
        let source_addr = self.mci_base + MCU_SRAM_OFFSET + offset;
        self.dma.read_buffer(source_addr, buffer);
        Ok(())
    }

    // Request the recovery interface load an image.
    pub fn request_image(&self, fw_image_index: u32) -> CaliptraResult<u32> {
        cprintln!(
            "[dma-recovery] Requesting recovery image {}",
            fw_image_index
        );

        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();

            // set RESET signal to indirect control to load the next image
            recovery
                .indirect_fifo_ctrl_0()
                .modify(|val| val.reset(Self::RESET_VAL));

            // Set PROT_CAP2.AGENT_CAPS
            // - Bit0  to 1 ('Device ID support')
            // - Bit4  to 1 ('Device Status support')
            // - Bit7  to 1 ('Push C-image support')
            // - Bit11 to 1 ('Flashless boot')
            // - Bit12 to 1 ('FIFO CMS support')
            // Set PROT_CAP2.REC_PROT_VERSION to 0x101 (1.1).
            recovery.prot_cap_2().modify(|val| {
                val.agent_caps(
                    Self::PROT_CAP2_DEVICE_ID_SUPPORT // mandatory
                        | Self::PROT_CAP2_DEVICE_STATUS_SUPPORT // mandatory
                        | Self::PROT_CAP2_FIFO_CMS_SUPPORT
                        | Self::PROT_CAP2_FLASHLESS_BOOT_VALUE
                        | Self::PROT_CAP2_PUSH_C_IMAGE_SUPPORT,
                )
                .rec_prot_version(0x101) // 1.1
            });

            // Set DEVICE_STATUS:Byte0 to 0x3 ('Recovery mode - ready to accept recovery image').
            // Set DEVICE_STATUS:Byte[2:3] to 0x12 ('Recovery Reason Codes' 0x12 - Flashless/Streaming Boot (FSB)).
            cprintln!(
                "[dma-recovery] Set device status {}",
                Self::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE
            );
            recovery.device_status_0().modify(|val| {
                val.rec_reason_code(Self::FLASHLESS_STREAMING_BOOT_VALUE)
                    .dev_status(Self::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE)
            });

            // Set RECOVERY_STATUS register 'Device Recovery Status' field to 0x1 ('Awaiting recovery image')
            // and 'Recovery Image Index' to recovery image index.
            recovery.recovery_status().modify(|recovery_status_val| {
                recovery_status_val
                    .rec_img_index(fw_image_index)
                    .dev_rec_status(Self::RECOVERY_STATUS_AWAITING_RECOVERY_IMAGE)
            });
        })?;

        // Loop on the 'payload_available' signal for the recovery image details to be available.
        while !self.dma.payload_available() {}
        let image_size_bytes = self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();

            // Read the image size from INDIRECT_FIFO_CTRL1 register. Image size is in DWORDs.
            let image_size_dwords = recovery.indirect_fifo_ctrl_1().read();
            let image_size_bytes = image_size_dwords * size_of::<u32>() as u32;
            cprintln!(
                "[dma-recovery] Payload available, {} bytes",
                image_size_bytes
            );
            Ok::<u32, CaliptraError>(image_size_bytes)
        })??;

        Ok(image_size_bytes)
    }

    pub fn set_recovery_status(&self, status: u32, image_idx: u32) -> CaliptraResult<()> {
        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();
            recovery.recovery_status().modify(|recovery_status_val| {
                recovery_status_val
                    .rec_img_index(image_idx)
                    .dev_rec_status(status)
            });
        })
    }

    pub fn set_device_status(&self, status: u32) -> CaliptraResult<()> {
        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();
            recovery
                .device_status_0()
                .modify(|device_status_val| device_status_val.dev_status(status));
        })
    }

    pub fn reset_recovery_ctrl_activate_rec_img(&self) -> CaliptraResult<()> {
        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();
            recovery
                .recovery_ctrl()
                .modify(|recovery_ctrl_val| recovery_ctrl_val.activate_rec_img(Self::RESET_VAL));
        })
    }

    pub fn transfer_payload_to_axi(
        &self,
        read_addr: AxiAddr,
        payload_len_bytes: u32,
        write_addr: AxiAddr,
        read_fixed_addr: bool,
        write_fixed_addr: bool,
    ) -> CaliptraResult<()> {
        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr: read_fixed_addr,
            length: payload_len_bytes,
            target: DmaReadTarget::AxiWr(write_addr, write_fixed_addr),
        };
        self.exec_dma_read(read_transaction)?;
        Ok(())
    }

    // TODO: remove this when the FPGA can do fixed burst transfers
    #[cfg(feature = "fpga_realtime")]
    fn exec_dma_read(&self, read_transaction: DmaReadTransaction) -> CaliptraResult<()> {
        // check if this is an I3C DMA
        let i3c = match read_transaction.read_addr {
            AxiAddr { lo, hi }
                if hi == self.base.hi && lo == self.base.lo + Self::INDIRECT_FIFO_DATA_OFFSET =>
            {
                true
            }
            _ => false,
        };

        for k in (0..read_transaction.length).step_by(BLOCK_SIZE as usize) {
            // TODO: this will fail if the transaction is not a multiple of the block size
            // wait for the FIFO to be full
            if i3c {
                self.with_regs(|r| {
                    while !r
                        .sec_fw_recovery_if()
                        .indirect_fifo_status_0()
                        .read()
                        .full()
                    {}
                })?;
            }
            for j in (0..BLOCK_SIZE).step_by(4) {
                let i = k + j;

                // translate to single dword transfer
                match read_transaction.target {
                    DmaReadTarget::AxiWr(addr, fixed) => {
                        let word = self.dma.read_dword(
                            read_transaction.read_addr
                                + if read_transaction.fixed_addr { 0 } else { i },
                        );
                        self.dma.write_dword(addr + if fixed { 0 } else { i }, word);
                    }
                    DmaReadTarget::Mbox(offset) => {
                        let rd_tx = DmaReadTransaction {
                            read_addr: read_transaction.read_addr
                                + if read_transaction.fixed_addr { 0 } else { i },
                            fixed_addr: false,
                            length: 4,
                            target: DmaReadTarget::Mbox(offset + i as u32),
                        };
                        self.dma.flush();
                        self.dma.setup_dma_read(rd_tx, 0);
                        self.dma.wait_for_dma_complete();
                    }
                    _ => panic!("DMA read target must be AxiWr"),
                };
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "fpga_realtime"))]
    fn exec_dma_read(&self, read_transaction: DmaReadTransaction) -> CaliptraResult<()> {
        self.dma.flush();
        self.dma.setup_dma_read(read_transaction, BLOCK_SIZE);
        self.dma.wait_for_dma_complete();
        Ok(())
    }

    pub fn sha384_mcu_sram(
        &self,
        sha_acc: &'a mut Sha2_512_384Acc,
        base: u32,
        length: u32,
    ) -> CaliptraResult<Array4x12> {
        let source = self.mci_base + MCU_SRAM_OFFSET + AxiAddr::from(base);
        self.sha384_image(sha_acc, source, length)
    }

    pub fn sha512_mcu_sram(
        &self,
        sha_acc: &'a mut Sha2_512_384Acc,
        base: u32,
        length: u32,
    ) -> CaliptraResult<Array4x16> {
        let source = self.mci_base + MCU_SRAM_OFFSET + AxiAddr::from(base);
        self.sha512_image(sha_acc, source, length)
    }

    pub fn sha384_image(
        &self,
        sha_acc: &'a mut Sha2_512_384Acc,
        source: AxiAddr,
        length: u32,
    ) -> CaliptraResult<Array4x12> {
        // This is tricky, because we need to lock and write to several registers over DMA
        // so that the AXI user is set correctly, but we want the guarantees of the
        // Sha2_512_384Acc without making that too generic.

        // Lock the SHA accelerator to ensure that the AXI user is set to the DMA user.
        self.with_sha_acc(|dma_sha| {
            if dma_sha.lock().read().lock() {
                cprintln!(
                    "[dma-image] SHA accelerator lock not acquired by DMA, cannot start operation"
                );
                return Err(CaliptraError::RUNTIME_INTERNAL);
            }

            // we only use the raw SHA accelerator driver to get the digest at the end and unlock when dropped.
            let mut acc_op = sha_acc
                .try_start_operation(ShaAccLockState::AssumedLocked)?
                .ok_or(CaliptraError::RUNTIME_INTERNAL)?;

            dma_sha.mode().write(|w| {
                w.endian_toggle(false) // false means swap endianness to match SHA engine
                    .mode(|_| ShaCmdE::ShaStream384)
            });
            dma_sha.dlen().write(|_| length);
            // Safety: the dma_sha is relative to 0, so we can use it to get the offset of the data in register.
            let write_addr = self.caliptra_base + (dma_sha.datain().ptr as u32 as u64);

            // stream the data in to the SHA accelerator
            cprintln!(
                "[dma-image] SHA384 image digest calculation: source = {:08x}{:08x}, length = {}",
                source.hi,
                source.lo,
                length
            );

            // stream the data in to the SHA accelerator
            self.transfer_payload_to_axi(source, length, write_addr, false, true)?;

            dma_sha.execute().write(|w| w.execute(true));

            let mut digest = Array4x12::default();
            acc_op.stream_wait_for_done_384(&mut digest)?;
            Ok(digest)
        })?
    }

    pub fn sha512_image(
        &self,
        sha_acc: &'a mut Sha2_512_384Acc,
        source: AxiAddr,
        length: u32,
    ) -> CaliptraResult<Array4x16> {
        // This is tricky, because we need to lock and write to several registers over DMA
        // so that the AXI user is set correctly, but we want the guarantees of the
        // Sha2_512_384Acc without making that too generic.

        // Lock the SHA accelerator to ensure that the AXI user is set to the DMA user.
        self.with_sha_acc(|dma_sha| {
            if dma_sha.lock().read().lock() {
                // cprintln!(
                //     "[dma-image] SHA accelerator lock not acquired by DMA, cannot start operation"
                // );
                return Err(CaliptraError::RUNTIME_INTERNAL);
            }

            // we only use the raw SHA accelerator driver to get the digest at the end and unlock when dropped.
            let mut acc_op = sha_acc
                .try_start_operation(ShaAccLockState::AssumedLocked)?
                .ok_or(CaliptraError::RUNTIME_INTERNAL)?;

            dma_sha.mode().write(|w| {
                w.endian_toggle(false) // false means swap endianness to match SHA engine
                    .mode(|_| ShaCmdE::ShaStream512)
            });
            dma_sha.dlen().write(|_| length);
            // Safety: the dma_sha is relative to 0, so we can use it to get the offset of the data in register.
            let write_addr = self.caliptra_base + (dma_sha.datain().ptr as u32 as u64);

            // stream the data in to the SHA accelerator
            // cprintln!(
            //     "[dma-image] SHA512 image digest calculation: source = {:08x}{:08x}, length = {}",
            //     source.hi,
            //     source.lo,
            //     length
            // );

            // stream the data in to the SHA accelerator
            self.transfer_payload_to_axi(source, length, write_addr, false, true)?;

            dma_sha.execute().write(|w| w.execute(true));

            let mut digest = Array4x16::default();
            acc_op.stream_wait_for_done_512(&mut digest)?;
            Ok(digest)
        })?
    }
}

pub struct DmaOtpCtrl<'a> {
    base: AxiAddr,
    dma: &'a Dma,
}

impl<'a> DmaOtpCtrl<'a> {
    #[inline(always)]
    pub fn new(base: AxiAddr, dma: &'a Dma) -> Self {
        Self { base, dma }
    }

    /// Returns a register block that can be used to read
    /// registers from this peripheral, but cannot write.
    #[inline(always)]
    pub fn with_regs<T, F>(&self, f: F) -> CaliptraResult<T>
    where
        F: FnOnce(FuseCtrlRegisterBlock<&DmaMmio>) -> T,
    {
        let mmio = DmaMmio::new(self.base, self.dma);
        // SAFETY: we aren't referencing memory directly
        let regs =
            unsafe { FuseCtrlRegisterBlock::new_with_mmio(core::ptr::null_mut::<u32>(), &mmio) };
        let t = f(regs);
        mmio.check_error(t)
    }

    /// Return a register block that can be used to read and
    /// write this peripheral's registers.
    #[inline(always)]
    pub fn with_regs_mut<T, F>(&self, f: F) -> CaliptraResult<T>
    where
        F: FnOnce(FuseCtrlRegisterBlock<&DmaMmio>) -> T,
    {
        let mmio = DmaMmio::new(self.base, self.dma);
        // SAFETY: we aren't referencing memory directly
        let regs =
            unsafe { FuseCtrlRegisterBlock::new_with_mmio(core::ptr::null_mut::<u32>(), &mmio) };
        let t = f(regs);
        mmio.check_error(t)
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    dma.rs

Abstract:

    File contains API for DMA Widget operations

--*/

use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::axi_dma::{
    enums::{RdRouteE, WrRouteE},
    AxiDmaReg, RegisterBlock,
};
use caliptra_registers::i3ccsr::RegisterBlock as I3CRegisterBlock;
use core::cell::Cell;
use core::ops::Add;
use ureg::{Mmio, MmioMut, RealMmioMut};
use zerocopy::AsBytes;

use crate::cprintln;

pub enum DmaReadTarget {
    Mbox,
    AhbFifo,
    AxiWr(AxiAddr),
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
    Mbox,
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
pub struct Dma {
    dma: Cell<Option<AxiDmaReg>>,
}

impl Dma {
    /// Create a new DMA instance
    ///
    /// # Arguments
    ///
    /// * `dma` - DMA register block
    pub fn new(dma: AxiDmaReg) -> Self {
        Self {
            dma: Cell::new(Some(dma)),
        }
    }

    pub fn with_dma<T>(
        &self,
        f: impl FnOnce(RegisterBlock<RealMmioMut>) -> T,
    ) -> CaliptraResult<T> {
        if let Some(mut dma) = self.dma.take() {
            let result = f(dma.regs_mut());
            self.dma.set(Some(dma));
            Ok(result)
        } else {
            Err(CaliptraError::DRIVER_DMA_INTERNAL) // should never happen
        }
    }

    pub fn flush(&self) -> CaliptraResult<()> {
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

    pub fn set_block_size(&self, block_size: u32) -> CaliptraResult<()> {
        self.with_dma(|dma| dma.block_size().write(|f| f.size(block_size)))
    }

    pub fn setup_dma_read(&self, read_transaction: DmaReadTransaction) -> CaliptraResult<()> {
        self.with_dma(|dma| {
            let read_addr = read_transaction.read_addr;
            dma.src_addr_l().write(|_| read_addr.lo);
            dma.src_addr_h().write(|_| read_addr.hi);

            if let DmaReadTarget::AxiWr(target_addr) = read_transaction.target {
                dma.dst_addr_l().write(|_| target_addr.lo);
                dma.dst_addr_h().write(|_| target_addr.hi);
            }

            dma.ctrl().modify(|c| {
                c.rd_route(|_| match read_transaction.target {
                    DmaReadTarget::Mbox => RdRouteE::Mbox,
                    DmaReadTarget::AhbFifo => RdRouteE::AhbFifo,
                    DmaReadTarget::AxiWr(_) => RdRouteE::AxiWr,
                })
                .rd_fixed(read_transaction.fixed_addr)
                .wr_route(|_| match read_transaction.target {
                    DmaReadTarget::AxiWr(_) => WrRouteE::AxiRd,
                    _ => WrRouteE::Disable,
                })
            });

            dma.byte_count().write(|_| read_transaction.length);
        })
    }

    fn setup_dma_write(&self, write_transaction: DmaWriteTransaction) -> CaliptraResult<()> {
        self.with_dma(|dma| {
            let write_addr = write_transaction.write_addr;
            dma.dst_addr_l().write(|_| write_addr.lo);
            dma.dst_addr_h().write(|_| write_addr.hi);

            if let DmaWriteOrigin::AxiRd(origin_addr) = write_transaction.origin {
                dma.dst_addr_l().write(|_| origin_addr.lo);
                dma.dst_addr_h().write(|_| origin_addr.hi);
            }

            dma.ctrl().modify(|c| {
                c.wr_route(|_| match write_transaction.origin {
                    DmaWriteOrigin::Mbox => WrRouteE::Mbox,
                    DmaWriteOrigin::AhbFifo => WrRouteE::AhbFifo,
                    DmaWriteOrigin::AxiRd(_) => WrRouteE::AxiRd,
                })
                .wr_fixed(write_transaction.fixed_addr)
                .rd_route(|_| match write_transaction.origin {
                    DmaWriteOrigin::AxiRd(_) => RdRouteE::AxiWr,
                    _ => RdRouteE::Disable,
                })
            });

            dma.byte_count().write(|_| write_transaction.length);
        })
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
    pub fn dma_read_fifo(&self, read_data: &mut [u8]) -> CaliptraResult<()> {
        self.with_dma(|dma| {
            let status = dma.status0().read();

            if read_data.len() > status.fifo_depth() as usize {
                return Err(CaliptraError::DRIVER_DMA_FIFO_UNDERRUN);
            }

            // Only multiple of 4 bytes are allowed
            if read_data.len() % core::mem::size_of::<u32>() != 0 {
                return Err(CaliptraError::DRIVER_DMA_FIFO_INVALID_SIZE);
            }

            // Process all 4-byte chunks
            let ptr = dma.read_data().ptr as *mut u8;
            read_data.chunks_mut(4).for_each(|word| {
                // Reg only exports u32 writes but we need finer grained access
                unsafe {
                    ptr.copy_to_nonoverlapping(word.as_mut_ptr(), word.len());
                }
            });
            Ok(())
        })?
    }

    fn dma_write_fifo(&self, write_data: &[u8]) -> CaliptraResult<()> {
        self.with_dma(|dma| {
            let max_fifo_depth = dma.cap().read().fifo_max_depth();
            let current_fifo_depth = dma.status0().read().fifo_depth();

            if write_data.len() as u32 > max_fifo_depth - current_fifo_depth {
                Err(CaliptraError::DRIVER_DMA_FIFO_OVERRUN)?;
            }

            // Process all 4-byte chunks
            if write_data.len() as u32 > max_fifo_depth - current_fifo_depth {
                return Err(CaliptraError::DRIVER_DMA_FIFO_OVERRUN);
            }

            write_data.chunks(4).for_each(|word| {
                let ptr = dma.write_data().ptr as *mut u8;
                // Reg only exports u32 writes but we need finer grained access
                unsafe {
                    ptr.copy_from_nonoverlapping(word.as_ptr(), word.len());
                }
            });
            Ok(())
        })?
    }

    pub fn do_transaction(&self) -> CaliptraResult<()> {
        self.with_dma(|dma| {
            let status0 = dma.status0().read();
            if status0.busy() {
                Err(CaliptraError::DRIVER_DMA_TRANSACTION_ALREADY_BUSY)?;
            }

            if status0.error() {
                Err(CaliptraError::DRIVER_DMA_TRANSACTION_ERROR)?;
            }

            dma.ctrl().modify(|c| c.go(true));

            while dma.status0().read().busy() {
                if dma.status0().read().error() {
                    Err(CaliptraError::DRIVER_DMA_TRANSACTION_ERROR)?;
                }
            }

            Ok(())
        })?
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
        self.read_buffer(read_addr, read_val.as_bytes_mut())?;
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
        self.flush()?;

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr: false,
            length: buffer.len() as u32,
            target: DmaReadTarget::AhbFifo,
        };

        self.setup_dma_read(read_transaction)?;
        self.do_transaction()?;
        self.dma_read_fifo(buffer)?;
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
        self.flush()?;

        let write_transaction = DmaWriteTransaction {
            write_addr,
            fixed_addr: false,
            length: core::mem::size_of::<u32>() as u32,
            origin: DmaWriteOrigin::AhbFifo,
        };
        self.dma_write_fifo(write_val.as_bytes())?;
        self.setup_dma_write(write_transaction)?;
        self.do_transaction()?;
        Ok(())
    }

    /// Transfer payload to mailbox
    ///
    /// The mailbox lock needs to be acquired before this can be called
    ///
    /// # Arguments
    ///
    /// * `read_addr` - Source address to read from
    /// * `payload_len_bytes` - Length of the payload in bytes
    /// * `fixed_addr` - Whether to use a fixed address for reading
    /// * `block_size` - Size of each block transfer
    ///
    /// # Returns
    ///
    /// * `CaliptraResult<()>` - Success or error code
    pub fn transfer_payload_to_mbox(
        &self,
        read_addr: AxiAddr,
        payload_len_bytes: u32,
        fixed_addr: bool,
        block_size: u32,
    ) -> CaliptraResult<()> {
        self.flush()?;

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr,
            length: payload_len_bytes,
            target: DmaReadTarget::Mbox,
        };
        self.setup_dma_read(read_transaction)?;
        self.set_block_size(block_size)?;
        self.do_transaction()?;
        Ok(())
    }

    /// Indicates if payload is available.
    ///
    /// # Returns
    /// true if payload is available, false otherwise
    ///
    pub fn payload_available(&self) -> CaliptraResult<bool> {
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
        T::from_u32(a.unwrap_or_default())
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
    dma: &'a Dma,
}

impl<'a> DmaRecovery<'a> {
    #[inline(always)]
    pub fn new(base: AxiAddr, dma: &'a Dma) -> Self {
        Self { base, dma }
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
                core::ptr::null_mut(), // we don't use this except for offset calculations,
                &mmio,
            )
        };
        let t = f(regs);
        match mmio.last_error.take() {
            Some(err) => Err(err),
            None => Ok(t),
        }
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
                core::ptr::null_mut(), // we don't use this except for offset calculations
                &mmio,
            )
        };
        let t = f(regs);
        match mmio.last_error.take() {
            Some(err) => Err(err),
            None => Ok(t),
        }
    }

    fn transfer_payload_to_mbox(
        &self,
        read_addr: AxiAddr,
        payload_len_bytes: u32,
        fixed_addr: bool,
        block_size: u32,
    ) -> CaliptraResult<()> {
        self.dma.flush()?;

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr,
            length: payload_len_bytes,
            target: DmaReadTarget::Mbox,
        };
        self.dma.setup_dma_read(read_transaction)?;
        self.dma.set_block_size(block_size)?;
        self.dma.do_transaction()?;
        Ok(())
    }

    pub fn transfer_mailbox_to_axi(
        &self,
        payload_len_bytes: u32,
        block_size: u32,
        write_addr: AxiAddr,
        fixed_addr: bool,
    ) -> CaliptraResult<()> {
        self.dma.flush()?;

        let write_transaction = DmaWriteTransaction {
            write_addr,
            fixed_addr,
            length: payload_len_bytes,
            origin: DmaWriteOrigin::Mbox,
        };
        self.dma.setup_dma_write(write_transaction)?;
        self.dma.set_block_size(block_size)?;
        self.dma.do_transaction()?;
        Ok(())
    }

    // Downloads an image from the recovery interface to the mailbox SRAM.
    pub fn download_image_to_mbox(&self, fw_image_index: u32) -> CaliptraResult<u32> {
        const INDIRECT_FIFO_DATA_OFFSET: u32 = 0x68;
        const RECOVERY_DMA_BLOCK_SIZE_BYTES: u32 = 256;

        self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();

            // Set PROT_CAP:Byte11 Bit3 (i.e. DWORD2:Bit27) to 1 ('Flashless boot').
            recovery.prot_cap_0().modify(|val| val | (1 << 27));

            // Set DEVICE_STATUS:Byte0 to 0x3 ('Recovery mode - ready to accept recovery image').
            // Set DEVICE_STATUS:Byte[2:3] to 0x12 ('Recovery Reason Codes' 0x12 = 0 Flashless/Streaming Boot (FSB)).
            recovery
                .device_status_0()
                .modify(|val| (val & 0xFF00FF00) | (0x12 << 16) | 0x03);

            // Set RECOVERY_STATUS:Byte0 Bit[3:0] to 0x1 ('Awaiting recovery image') &
            // Byte0 Bit[7:4] to 0 (Recovery image index).
            // [TODO][CAP2] the spec says this register is read-only, but there is no other way to select an image index?
            recovery.recovery_status().modify(|recovery_status_val| {
                // Set Byte0 Bit[3:0] to 0x1 ('Awaiting recovery image')
                // Set Byte0 Bit[7:4] to recovery image index
                (recovery_status_val & 0xFFFFFF00) | (fw_image_index << 4) | 0x1
            });
        })?;

        // Loop on the 'payload_available' signal for the recovery image details to be available.
        cprintln!("[fwproc] Waiting for payload available signal...");
        while !self.dma.payload_available()? {}
        let image_size_bytes = self.with_regs_mut(|regs_mut| {
            let recovery = regs_mut.sec_fw_recovery_if();

            // [TODO][CAP2] we need to program CMS bits, currently they are not available in RDL. Using bytes[4:7] for now for size

            // Read the image size from INDIRECT_FIFO_CTRL:Byte[2:5]. Image size in DWORDs.
            let indirect_fifo_ctrl_val0 = recovery.indirect_fifo_ctrl_0().read();
            let indirect_fifo_ctrl_val1 = recovery.indirect_fifo_ctrl_1().read();
            let image_size_dwords = ((indirect_fifo_ctrl_val0 >> 16) & 0xFFFF)
                | ((indirect_fifo_ctrl_val1 & 0xFFFF) << 16);

            image_size_dwords * 4
        })?;

        // Transfer the image from the recovery interface to the mailbox SRAM.
        let addr = self.base + INDIRECT_FIFO_DATA_OFFSET;
        self.transfer_payload_to_mbox(addr, image_size_bytes, true, RECOVERY_DMA_BLOCK_SIZE_BYTES)?;
        Ok(image_size_bytes)
    }
}

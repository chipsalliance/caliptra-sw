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
    AxiDmaReg,
};
use core::ops::Add;
use zerocopy::AsBytes;

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
    dma: AxiDmaReg,
}

impl Dma {
    /// Create a new DMA instance
    ///
    /// # Arguments
    ///
    /// * `dma` - DMA register block
    pub fn new(dma: AxiDmaReg) -> Self {
        Self { dma }
    }

    fn flush(&mut self) {
        let dma = self.dma.regs_mut();

        dma.ctrl().write(|c| c.flush(true));

        // Wait till we're not busy and have no errors
        // TODO this assumes the peripheral does not clear that status0 state
        // in one cycle. Maybe it can be removed if the assumption proves false

        while {
            let status0 = dma.status0().read();
            status0.busy() || status0.error()
        } {}
    }

    fn setup_dma_read(&mut self, read_transaction: DmaReadTransaction) {
        let dma = self.dma.regs_mut();

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
    }

    fn setup_dma_write(&mut self, write_transaction: DmaWriteTransaction) {
        let dma = self.dma.regs_mut();

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
    pub fn dma_read_fifo(&mut self, read_data: &mut [u8]) -> CaliptraResult<()> {
        let dma = self.dma.regs_mut();

        let status = dma.status0().read();

        if read_data.len() > status.fifo_depth() as usize {
            return Err(CaliptraError::DRIVER_DMA_FIFO_UNDERRUN);
        }

        read_data.chunks_mut(4).for_each(|word| {
            let ptr = dma.read_data().ptr as *mut u8;
            // Reg only exports u32 writes but we need finer grained access
            unsafe {
                ptr.copy_to_nonoverlapping(word.as_mut_ptr(), word.len());
            }
        });

        Ok(())
    }

    fn dma_write_fifo(&mut self, write_data: &[u8]) -> CaliptraResult<()> {
        let dma = self.dma.regs_mut();

        let max_fifo_depth = dma.cap().read().fifo_max_depth();
        let current_fifo_depth = dma.status0().read().fifo_depth();

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
    }

    fn do_transaction(&mut self) -> CaliptraResult<()> {
        let dma = self.dma.regs_mut();

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
    pub fn read_dword(&mut self, read_addr: AxiAddr) -> CaliptraResult<u32> {
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
    pub fn read_buffer(&mut self, read_addr: AxiAddr, buffer: &mut [u8]) -> CaliptraResult<()> {
        self.flush();

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr: false,
            length: buffer.len() as u32,
            target: DmaReadTarget::AhbFifo,
        };

        self.setup_dma_read(read_transaction);
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
    pub fn write_dword(&mut self, write_addr: AxiAddr, write_val: u32) -> CaliptraResult<()> {
        self.flush();

        let write_transaction = DmaWriteTransaction {
            write_addr,
            fixed_addr: false,
            length: core::mem::size_of::<u32>() as u32,
            origin: DmaWriteOrigin::AhbFifo,
        };
        self.dma_write_fifo(write_val.as_bytes())?;
        self.setup_dma_write(write_transaction);
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
        &mut self,
        read_addr: AxiAddr,
        payload_len_bytes: u32,
        fixed_addr: bool,
        block_size: u32,
    ) -> CaliptraResult<()> {
        self.flush();

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr,
            length: payload_len_bytes,
            target: DmaReadTarget::Mbox,
        };
        self.setup_dma_read(read_transaction);
        self.dma
            .regs_mut()
            .block_size()
            .write(|f| f.size(block_size));
        self.do_transaction()?;
        Ok(())
    }
}

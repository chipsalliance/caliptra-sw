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
use zerocopy::AsBytes;

const PROT_CAP_OFFSET: u32 = 0x0;
const INDIRECT_FIFO_DATA_OFFSET: u32 = PROT_CAP_OFFSET + 0x6C;

pub enum DmaReadTarget {
    Mbox,
    AhbFifo,
    AxiWr(usize),
}

pub struct DmaReadTransaction {
    pub read_addr: usize,
    pub fixed_addr: bool,
    pub length: u32,
    pub target: DmaReadTarget,
}

pub enum DmaWriteOrigin {
    Mbox,
    AhbFifo,
    AxiRd(usize),
}

pub struct DmaWriteTransaction {
    pub write_addr: usize,
    pub fixed_addr: bool,
    pub length: u32,
    pub origin: DmaWriteOrigin,
}

/// Dma Widget
pub struct Dma {
    dma: AxiDmaReg,
}

impl Dma {
    pub fn new(dma: AxiDmaReg) -> Self {
        Self { dma }
    }

    pub fn flush(&mut self) {
        let dma = self.dma.regs_mut();

        dma.ctrl().write(|c| c.flush(true));

        // Wait till we're not busy and have no errors
        while {
            let status0 = dma.status0().read();
            status0.busy() || status0.error()
        } {}
    }

    pub fn setup_dma_read(&mut self, read_transaction: DmaReadTransaction) {
        let dma = self.dma.regs_mut();

        let read_addr: usize = read_transaction.read_addr;
        #[cfg(target_pointer_width = "64")]
        dma.src_addr_h().write(|_| (read_addr >> 32) as u32);
        dma.src_addr_l().write(|_| (read_addr & 0xffff_ffff) as u32);

        if let DmaReadTarget::AxiWr(target_addr) = read_transaction.target {
            #[cfg(target_pointer_width = "64")]
            dma.dst_addr_h().write(|_| (target_addr >> 32) as u32);
            dma.dst_addr_l()
                .write(|_| (target_addr & 0xffff_ffff) as u32);
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

    pub fn dma_write_fifo(&mut self, write_data: &[u8]) -> CaliptraResult<()> {
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

    pub fn setup_dma_write(&mut self, write_transaction: DmaWriteTransaction) {
        let dma = self.dma.regs_mut();

        let write_addr = write_transaction.write_addr;
        #[cfg(target_pointer_width = "64")]
        dma.dst_addr_h().write(|_| (write_addr >> 32) as u32);
        dma.dst_addr_l()
            .write(|_| (write_addr & 0xffff_ffff) as u32);

        if let DmaWriteOrigin::AxiRd(origin_addr) = write_transaction.origin {
            #[cfg(target_pointer_width = "64")]
            dma.dst_addr_h().write(|_| (origin_addr >> 32) as u32);
            dma.dst_addr_l()
                .write(|_| (origin_addr & 0xffff_ffff) as u32);
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

    pub fn do_transaction(&mut self) -> CaliptraResult<()> {
        let dma = self.dma.regs_mut();

        let status0 = dma.status0().read();
        if status0.busy() {
            return Err(CaliptraError::DRIVER_DMA_TRANSACTION_ALREADY_BUSY);
        }

        if status0.error() {
            return Err(CaliptraError::DRIVER_DMA_TRANSACTION_ERROR);
        }

        dma.ctrl().modify(|c| c.go(true));

        while dma.status0().read().busy() {
            if dma.status0().read().error() {
                return Err(CaliptraError::DRIVER_DMA_TRANSACTION_ERROR);
            }
        }

        Ok(())
    }

    pub fn read_dword(&mut self, read_addr: usize) -> CaliptraResult<u32> {
        let mut read_val: u32 = 0;

        self.flush();

        let read_transaction = DmaReadTransaction {
            read_addr,
            fixed_addr: false,
            length: core::mem::size_of::<u32>() as u32,
            target: DmaReadTarget::AhbFifo,
        };

        self.setup_dma_read(read_transaction);
        self.do_transaction()?;
        self.dma_read_fifo(read_val.as_bytes_mut())?;
        Ok(read_val)
    }

    pub fn write_dword(&mut self, write_addr: usize, write_val: u32) -> CaliptraResult<()> {
        self.flush();

        let write_transaction = DmaWriteTransaction {
            write_addr,
            fixed_addr: false,
            length: core::mem::size_of::<u32>() as u32,
            origin: DmaWriteOrigin::AhbFifo,
        };

        self.setup_dma_write(write_transaction);
        self.do_transaction()?;
        self.dma_write_fifo(write_val.as_bytes())?;
        Ok(())
    }

    pub fn transfer_payload_to_mbox(&mut self, payload_len_bytes: u32) -> CaliptraResult<()> {
        self.flush();

        let dma_reg = self.dma.regs_mut();

        // Write  payload length to 'Byte Count' register.
        dma_reg.byte_count().write(|_| payload_len_bytes);

        // Write block size to 'Block Size' register.
        dma_reg.block_size().write(|bs| bs.size(256));

        // Write the source address to SA(L) and SA(H) registers.
        dma_reg.src_addr_l().write(|_| INDIRECT_FIFO_DATA_OFFSET);
        dma_reg.src_addr_h().write(|_| 0);

        // [TODO] Acquire the mailbox lock.

        // Write Control register.
        dma_reg.ctrl().write(|c| c.rd_route(|_| RdRouteE::Mbox).rd_fixed(true).go(true));

        // Loop: Read Status0 register till Busy=0, Error=0
        while dma_reg.status0().read().busy() {
            if dma_reg.status0().read().error() {
                return Err(CaliptraError::DRIVER_DMA_TRANSACTION_ERROR);
            }
        }

        Ok(())
    }
}

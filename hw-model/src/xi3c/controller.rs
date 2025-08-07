// This code was originally translated from the Xilinx I3C C driver:
// https://github.com/Xilinx/embeddedsw/tree/master/XilinxProcessorIPLib/drivers/i3c/src
// Which is:
// Copyright (C) 2024 Advanced Micro Devices, Inc. All Rights Reserved
// SPDX-License-Identifier: MIT

#![allow(dead_code)]

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_structs;
use tock_registers::registers::{ReadOnly, ReadWrite};

pub const MAX_TIMEOUT_US: u32 = 2_000_000;
pub const XI3C_BROADCAST_ADDRESS: u8 = 0x7e;

pub(crate) const XI3C_CCC_BRDCAST_ENEC: u8 = 0x0;
pub(crate) const XI3C_CCC_BRDCAST_DISEC: u8 = 0x1;
pub(crate) const XI3C_CCC_BRDCAST_RSTDAA: u8 = 0x6;
pub(crate) const XI3C_CCC_BRDCAST_ENTDAA: u8 = 0x7;
pub(crate) const XI3C_CCC_SETDASA: u8 = 0x87;

/// BIT 4 - Resp Fifo not empty
pub(crate) const XI3C_SR_RESP_NOT_EMPTY_MASK: u32 = 0x10;
/// BIT 15 - Read FIFO empty
pub(crate) const XI3C_SR_RD_FIFO_NOT_EMPTY_MASK: u32 = 0x8000;

/// BIT 5 - Write Fifo Full
pub(crate) const XI3C_INTR_WR_FIFO_ALMOST_FULL_MASK: u32 = 0x20;
/// BIT 6 - Read Fifo Full
pub(crate) const XI3C_INTR_RD_FULL_MASK: u32 = 0x40;

/// BIT 7 - IBI
pub(crate) const XI3C_INTR_IBI_MASK: u32 = 0x80;
/// BIT 8 - Hot join
pub(crate) const XI3C_INTR_HJ_MASK: u32 = 0x100;

/// BIT 0 - Core Enable
pub(crate) const XI3C_CR_EN_MASK: u32 = 0x1;
/// BIT 3 - IBI Enable
pub(crate) const XI3C_CR_IBI_MASK: u32 = 0x8;
/// BIT 4 - Hot Join Enable
pub(crate) const XI3C_CR_HJ_MASK: u32 = 0x10;

/// BIT 0 - Reset
pub(crate) const XI3C_SOFT_RESET_MASK: u32 = 0x1;
/// BIT 1 to 4 - All fifos reset
pub(crate) const XI3C_ALL_FIFOS_RESET_MASK: u32 = 0x1e;

pub(crate) const XST_DEVICE_IS_STARTED: i32 = 5;
/// There was no data available
pub(crate) const XST_NO_DATA: i32 = 13;
/// Generic receive error
pub(crate) const XST_RECV_ERROR: i32 = 27;
/// Generic transmit error
pub(crate) const XST_SEND_ERROR: i32 = 28;
register_structs! {
    pub XI3c {
        (0x0 => pub version: ReadOnly<u32>), // Version Register
        (0x4 => pub reset: ReadWrite<u32>), // Soft Reset Register
        (0x8 => pub cr: ReadWrite<u32>), // Control Register
        (0xC => pub address: ReadWrite<u32>), // Target Address Register
        (0x10 => pub sr: ReadWrite<u32>), // Status Register
        (0x14 => pub intr_status: ReadWrite<u32>), // Status Event Register
        (0x18 => pub intr_re: ReadWrite<u32>), // Status Event Enable(Rising Edge) Register
        (0x1C => pub intr_fe: ReadWrite<u32>), // Status Event Enable(Falling Edge) Register
        (0x20 => pub cmd_fifo: ReadWrite<u32>), // I3C Command FIFO Register
        (0x24 => pub wr_fifo: ReadWrite<u32>), // I3C Write Data FIFO Register
        (0x28 => pub rd_fifo: ReadWrite<u32>), // I3C Read Data FIFO Register
        (0x2C => pub resp_status_fifo: ReadWrite<u32>), // I3C Response status FIFO Register
        (0x30 => pub fifo_lvl_status: ReadWrite<u32>), // I3C CMD & WR FIFO LVL Register
        (0x34 => pub fifo_lvl_status_1: ReadWrite<u32>), // I3C RESP & RD FIFO LVL Register
        (0x38 => pub scl_high_time: ReadWrite<u32>), // I3C SCL HIGH Register
        (0x3C => pub scl_low_time: ReadWrite<u32>), // I3C SCL LOW  Register
        (0x40 => pub sda_hold_time: ReadWrite<u32>), // I3C SDA HOLD Register
        (0x44 => pub bus_idle: ReadWrite<u32>), // I3C CONTROLLER BUS IDLE Register
        (0x48 => pub tsu_start: ReadWrite<u32>), // I3C START SETUP Register
        (0x4C => pub thd_start: ReadWrite<u32>), // I3C START HOLD Register
        (0x50 => pub tsu_stop: ReadWrite<u32>), // I3C STOP Setup Register
        (0x54 => pub od_scl_high_time: ReadWrite<u32>), // I3C OD SCL HIGH Register
        (0x58 => pub od_scl_low_time: ReadWrite<u32>), // I3C OD SCL LOW  Register
        (0x5C => _reserved),
        (0x60 => pub target_addr_bcr: ReadWrite<u32>), // I3C Target dynamic Address and BCR Register
        (0x64 => @END),
    }
}

pub enum Ccc {
    Byte(u8),
    Data(Vec<u8>),
}

#[derive(Clone)]
pub struct Config {
    pub device_id: u16,
    pub base_address: *mut u32,
    pub input_clock_hz: u32,
    pub rw_fifo_depth: u8,
    pub wr_threshold: u8,
    pub device_count: u8,
    pub ibi_capable: bool,
    pub hj_capable: bool,
    pub entdaa_enable: bool,
    pub known_static_addrs: Vec<u8>, // if entdaa is disabled, we have to know the static addresses to do SETDASA
}

#[derive(Copy, Clone, Default)]
pub struct Command {
    /// I3C command type. 0 = legacy i2c, 1 = SDR, 2+ reserve
    pub cmd_type: u8,
    /// toc (termination on completion).
    /// 0 = next command will be started with Sr
    /// 1 = stop command will be issued after the existing command is completed
    pub no_repeated_start: u8,
    /// pec enable. Per the JEDEC standard, the PEC value will be computed. 0 = disable PEC, 1 = enable PEC.
    pub pec: u8,
    pub target_addr: u8,
    pub rw: u8,
    /// Bytes to Read/Write. This field acts as bytes to read/write (for common command codes (CCC) command, the number of bytes to read or write along with CCC like defining bytes for direct/broadcast CCC or subcommand bytes for broadcast CCC).
    /// Only in SDR/I2C commands.
    /// For other commands, it should be zero. The IP supports 4095 bytes to Read/Write for the SDR/I2C command.
    pub byte_count: u16,
    /// Transaction ID: This field acts as identification tag for I3C commands. The controller returns this tag along with the transaction status
    pub tid: u8,
}
#[derive(Copy, Clone, Default)]
pub struct TargetInfo {
    pub dyna_addr: u8,
    pub id: u64,
    pub bcr: u8,
    pub dcr: u8,
}

pub struct Controller {
    pub config: Config,
    pub ready: bool,
    pub error: u8,
    pub cur_device_count: u8,
    pub status_handler: Option<Box<dyn ErrorHandler>>,
    pub target_info_table: [TargetInfo; 108],
}

pub trait ErrorHandler {
    fn handle_error(&self, error: u32);
}

pub static DYNA_ADDR_LIST: [u8; 108] = [
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5a, 0x5b, 0x5c, 0x5d, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x77,
];

impl Controller {
    pub fn new(base_ptr: *mut u32) -> Self {
        Controller {
            config: Config {
                device_id: 0,
                base_address: base_ptr,
                input_clock_hz: 0,
                rw_fifo_depth: 0,
                wr_threshold: 0,
                device_count: 0,
                ibi_capable: false,
                hj_capable: false,
                entdaa_enable: false,
                known_static_addrs: vec![],
            },
            ready: false,
            error: 0,
            cur_device_count: 0,
            status_handler: None,
            target_info_table: [TargetInfo::default(); 108],
        }
    }

    #[inline(always)]
    pub(crate) const fn regs(&self) -> &XI3c {
        unsafe { &*(self.config.base_address as *const XI3c) }
    }

    pub fn bus_init(&mut self) -> Result<(), i32> {
        let mut cmd: Command = Command {
            cmd_type: 0,
            no_repeated_start: 0,
            pec: 0,
            target_addr: 0,
            rw: 0,
            byte_count: 0,
            tid: 0,
        };
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        // Disable Target Events
        println!("Broadcast CCC DISEC");
        let result = self.send_transfer_cmd(&mut cmd, Ccc::Byte(XI3C_CCC_BRDCAST_DISEC));
        if result.is_ok() {
            println!("Acknowledge received");
        }
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        // Enable Target Events
        println!("Broadcast CCC ENEC");
        let result = self.send_transfer_cmd(&mut cmd, Ccc::Byte(XI3C_CCC_BRDCAST_ENEC));
        if result.is_ok() {
            println!("Acknowledge received");
        }
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        // Reset Dynamic Address assigned to all the I3C Targets
        println!("Broadcast CCC RSTDAA");
        let result = self.send_transfer_cmd(&mut cmd, Ccc::Byte(XI3C_CCC_BRDCAST_RSTDAA));
        if result.is_ok() {
            println!("Acknowledge received");
        }
        Ok(())
    }

    pub fn cfg_initialize(&mut self, config: &Config, effective_addr: usize) -> Result<(), i32> {
        if self.ready {
            return Err(XST_DEVICE_IS_STARTED);
        }
        self.config.device_id = config.device_id;
        // Set the values read from the device config and the base address.
        self.config.base_address = effective_addr as *mut u32;
        self.config.input_clock_hz = config.input_clock_hz;
        self.config.rw_fifo_depth = config.rw_fifo_depth;
        // WrThreshold value in terms of words from design,
        // so convert to bytes.
        self.config.wr_threshold = config.wr_threshold * 4;
        self.config.device_count = config.device_count;
        self.config.ibi_capable = config.ibi_capable;
        self.config.hj_capable = config.hj_capable;
        self.config.entdaa_enable = config.entdaa_enable;
        self.config.known_static_addrs = config.known_static_addrs.clone();
        self.cur_device_count = 0;
        // Indicate the instance is now ready to use, initialized without error
        self.ready = true;
        // Reset the I3C controller to get it into its initial state. It is expected
        // that device configuration will take place after this initialization
        // is done, but before the device is started.
        self.reset();
        self.reset_fifos();
        if self.config.ibi_capable {
            println!("XI3C: enabling IBI");
            self.enable_ibi();
        }
        if self.config.hj_capable {
            self.enable_hotjoin();
        }
        // Enable I3C controller
        self.enable(1);
        self.bus_init()?;
        if self.config.ibi_capable && self.config.device_count != 0 {
            // cheat by enabling IBI everywhere
            for i in 0..128 {
                self.regs().target_addr_bcr.set(0x700 | i);
            }
            if self.config.entdaa_enable {
                self.dyna_addr_assign(&DYNA_ADDR_LIST, self.config.device_count)?;
            } else {
                let static_addrs = self.config.known_static_addrs.clone();
                println!(
                    "XI3C: initializing dynamic addresses with SETDASA (static address: {:x?})",
                    &static_addrs
                );
                let mut cmd: Command = Command {
                    cmd_type: 1,
                    no_repeated_start: 0,
                    pec: 0,
                    target_addr: XI3C_BROADCAST_ADDRESS,
                    rw: 0,
                    byte_count: 1,
                    tid: 2,
                };
                assert!(self.ready);
                println!("XI3C: Broadcast CCC SETDASA");
                self.send_transfer_cmd(&mut cmd, Ccc::Byte(XI3C_CCC_SETDASA))?;
                println!("XI3C: Acknowledged");
                for (i, addr) in static_addrs.iter().enumerate() {
                    self.dyna_addr_assign_static(
                        *addr,
                        DYNA_ADDR_LIST[i],
                        i == DYNA_ADDR_LIST.len() - 1,
                    )?;
                }
            }
            self.config_ibi(self.config.device_count);
        }
        // Enable Hot join raising edge interrupt.
        if self.config.hj_capable {
            self.regs()
                .intr_re
                .set(self.regs().intr_re.get() | XI3C_INTR_HJ_MASK);
        }
        Ok(())
    }

    pub fn fill_cmd_fifo(&mut self, cmd: &Command) {
        let dev_addr = (cmd.target_addr & 0x7f) << 1 | cmd.rw & 0x1;
        let mut transfer_cmd = (cmd.cmd_type & 0xf) as u32;
        transfer_cmd |= ((cmd.no_repeated_start & 0x1) as u32) << 4;
        transfer_cmd |= ((cmd.pec & 0x1) as u32) << 5;
        transfer_cmd |= (dev_addr as u32) << 8;
        transfer_cmd |= ((cmd.byte_count & 0xfff) as u32) << 16;
        transfer_cmd |= ((cmd.tid & 0xf) as u32) << 28;
        self.regs().cmd_fifo.set(transfer_cmd);
    }

    pub fn write_tx_fifo(&mut self, send_buffer: &[u8]) -> usize {
        let data = if send_buffer.len() > 3 {
            u32::from_be_bytes(send_buffer[0..4].try_into().unwrap())
        } else {
            let mut data = 0;
            for (i, x) in send_buffer.iter().enumerate() {
                data |= (*x as u32) << (24 - 8 * i);
            }
            data
        };
        self.regs().wr_fifo.set(data);
        send_buffer.len().min(4)
    }

    pub fn read_rx_fifo(&mut self, recv_byte_count: u16) -> Vec<u8> {
        let data = self.regs().rd_fifo.get();
        if recv_byte_count > 3 {
            data.to_be_bytes().to_vec()
        } else {
            data.to_be_bytes()[0..recv_byte_count as usize].to_vec()
        }
    }

    /// Assign a dynamic address to a single static device using SETDASA
    pub fn dyna_addr_assign_static(
        &mut self,
        static_addr: u8,
        dyn_addr: u8,
        last: bool,
    ) -> Result<(), i32> {
        let mut cmd: Command = Command {
            cmd_type: 1,
            no_repeated_start: if last { 1 } else { 0 }, // controller has a bug where it does not send 7E after CCC if it is a repeated start followed by non-CCC
            pec: 0,
            target_addr: static_addr,
            rw: 0,
            byte_count: 1,
            tid: 3,
        };

        let addr = dyn_addr << 1;
        println!(
            "Controller: Assigning dynamic address with SETDASA private write {:x}",
            addr >> 1
        );
        self.master_send_polled(&mut cmd, &[addr], 1)?;
        println!("Acknowledged");

        self.target_info_table[self.cur_device_count as usize].id = static_addr as u64;
        self.target_info_table[self.cur_device_count as usize].dyna_addr = dyn_addr;
        // TODO: should we get the DCR and BCR from the device?
        self.cur_device_count += 1;
        Ok(())
    }

    /// Assign dynamic addresses to all devices using ENTDAA
    pub fn dyna_addr_assign(&mut self, dyna_addr: &[u8], dev_count: u8) -> Result<(), i32> {
        let mut cmd: Command = Command {
            cmd_type: 0,
            no_repeated_start: 0,
            pec: 0,
            target_addr: 0,
            rw: 0,
            byte_count: 0,
            tid: 0,
        };
        assert!(self.ready);
        cmd.no_repeated_start = 0;
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        println!("XI3C: Broadcast CCC ENTDAA");
        self.send_transfer_cmd(&mut cmd, Ccc::Byte(XI3C_CCC_BRDCAST_ENTDAA))?;
        println!("XI3C: Acknowledged");
        let mut index = 0;
        while index < dev_count as u16 && index < 108 {
            let addr = dyna_addr[index as usize] << 1 | get_odd_parity(dyna_addr[index as usize]);
            self.write_tx_fifo(&[addr]);
            if index + 1 == dev_count as u16 {
                cmd.no_repeated_start = 1;
            } else {
                cmd.no_repeated_start = 0;
            }
            cmd.target_addr = XI3C_BROADCAST_ADDRESS;
            cmd.tid = 0;
            cmd.pec = 0;
            cmd.cmd_type = 1;

            println!("Controller: Assigning dynamic address 0x{:x}", addr >> 1);
            let recv_buffer = match self.master_recv_polled(None, &mut cmd, 9) {
                Ok(recv_buffer) => recv_buffer,
                Err(err) => {
                    println!("No ack received for assigning address");
                    return Err(err);
                }
            };

            println!("cur_device_count = {}", self.cur_device_count);
            self.target_info_table[self.cur_device_count as usize].id = (recv_buffer[0] as u64)
                << 40
                | (recv_buffer[1] as u64) << 32
                | (recv_buffer[2] as u64) << 24
                | (recv_buffer[3] as u64) << 16
                | (recv_buffer[4] as u64) << 8
                | recv_buffer[5] as u64;
            self.target_info_table[self.cur_device_count as usize].bcr = recv_buffer[6];
            println!("Controller received BCR: {:x}", recv_buffer[6]);
            println!("Controller received DCR: {:x}", recv_buffer[7]);
            self.target_info_table[self.cur_device_count as usize].dcr = recv_buffer[7];
            self.target_info_table[self.cur_device_count as usize].dyna_addr =
                dyna_addr[index as usize];
            self.cur_device_count += 1;
            index += 1;
        }
        Ok(())
    }

    pub fn config_ibi(&mut self, dev_count: u8) {
        assert!(self.ready);
        let mut index = 0;
        while index < dev_count && index < 108 {
            self.update_addr_bcr(index as u16);
            index += 1;
        }
    }

    #[inline]
    fn enable(&mut self, enable: u8) {
        assert!(self.ready);
        let mut data = self.regs().cr.get();
        data &= !XI3C_CR_EN_MASK;
        data |= enable as u32;
        self.regs().cr.set(data);
        println!("XI3C: Enable set to {:x}", self.regs().cr.get());
    }

    #[inline]
    fn enable_ibi(&mut self) {
        assert!(self.ready);
        let mut data = self.regs().cr.get();
        data |= XI3C_CR_IBI_MASK;
        self.regs().cr.set(data);
        println!(
            "Control register after enabling IBI: {:x}",
            self.regs().cr.get()
        );
    }

    #[inline]
    fn enable_hotjoin(&mut self) {
        assert!(self.ready);
        let mut data = self.regs().cr.get();
        data |= XI3C_CR_HJ_MASK;
        self.regs().cr.set(data);
    }

    #[inline]
    pub fn update_addr_bcr(&mut self, dev_index: u16) {
        assert!(self.ready);
        let mut addr_bcr = (self.target_info_table[dev_index as usize].dyna_addr & 0x7f) as u32;
        addr_bcr |= (self.target_info_table[dev_index as usize].bcr as u32) << 8;
        println!(
            "Updating BCR (index {}) for device {:x}",
            dev_index, addr_bcr
        );
        self.regs().target_addr_bcr.set(addr_bcr);
    }

    pub fn off(&mut self) {
        let mut data = self.regs().reset.get();
        data |= XI3C_SOFT_RESET_MASK;
        self.regs().reset.set(data);
    }

    #[inline]
    pub fn reset(&mut self) {
        assert!(self.ready);
        let mut data = self.regs().reset.get();
        data |= XI3C_SOFT_RESET_MASK;
        self.regs().reset.set(data);
        std::thread::sleep(Duration::from_micros(50));
        data &= !XI3C_SOFT_RESET_MASK;
        self.regs().reset.set(data);
        std::thread::sleep(Duration::from_micros(10));
    }

    #[inline]
    pub fn reset_fifos(&mut self) {
        assert!(self.ready);
        let mut data = self.regs().reset.get();
        data |= XI3C_ALL_FIFOS_RESET_MASK;
        self.regs().reset.set(data);
        std::thread::sleep(Duration::from_micros(50));
        data &= !XI3C_ALL_FIFOS_RESET_MASK;
        self.regs().reset.set(data);
        std::thread::sleep(Duration::from_micros(10));
    }

    /// Sets I3C Scl clock frequency.
    /// - s_clk_hz is Scl clock to be configured in Hz.
    /// - mode is the mode of operation I2C/I3C.
    pub fn set_s_clk(&mut self, input_clock_hz: u32, s_clk_hz: u32, mode: u8) {
        assert!(s_clk_hz > 0);
        let t_high = input_clock_hz
            .wrapping_add(s_clk_hz)
            .wrapping_sub(1)
            .wrapping_div(s_clk_hz)
            >> 1;
        let t_low = t_high;
        let mut t_hold = t_low.wrapping_mul(4).wrapping_div(10);
        let core_period_ns = 1_000_000_000_u32
            .wrapping_add(input_clock_hz)
            .wrapping_sub(1)
            .wrapping_div(input_clock_hz);
        if (self.regs().version.get() & 0xff00) >> 8 == 0 {
            t_hold = if t_hold < 5 { 5 } else { t_hold };
        } else {
            t_hold = if t_hold < 6 { 6 } else { t_hold };
        }
        self.regs()
            .scl_high_time
            .set(t_high.wrapping_sub(2) & 0x3ffff);
        self.regs()
            .scl_low_time
            .set(t_low.wrapping_sub(2) & 0x3ffff);
        self.regs()
            .sda_hold_time
            .set(t_hold.wrapping_sub(2) & 0x3ffff);
        let tcas_min: u32;
        let mut od_t_high: u32;
        let mut od_t_low: u32;
        if mode == 0 {
            self.regs()
                .od_scl_high_time
                .set(t_high.wrapping_sub(2) & 0x3ffff);
            self.regs()
                .od_scl_low_time
                .set(t_low.wrapping_sub(2) & 0x3ffff);
            tcas_min = 600_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
        } else {
            od_t_low = 500_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
            od_t_high = 41_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
            od_t_low = if t_low < od_t_low { od_t_low } else { t_low };
            od_t_high = if t_high > od_t_high {
                od_t_high
            } else {
                t_high
            };
            self.regs()
                .od_scl_high_time
                .set(od_t_high.wrapping_sub(2) & 0x3ffff);
            self.regs()
                .od_scl_low_time
                .set(od_t_low.wrapping_sub(2) & 0x3ffff);
            tcas_min = 39_u32
                .wrapping_add(core_period_ns)
                .wrapping_sub(1)
                .wrapping_div(core_period_ns);
        }
        let thd_start = if t_high > tcas_min { t_high } else { tcas_min };
        let tsu_start = if t_low > tcas_min { t_low } else { tcas_min };
        let tsu_stop = if t_low > tcas_min { t_low } else { tcas_min };
        self.regs()
            .tsu_start
            .set(tsu_start.wrapping_sub(2) & 0x3ffff);
        self.regs()
            .thd_start
            .set(thd_start.wrapping_sub(2) & 0x3ffff);
        self.regs()
            .tsu_stop
            .set(tsu_stop.wrapping_sub(2) & (0x3ffff + 5));
    }

    fn get_response(&mut self) -> i32 {
        let happened = self.wait_for_event(
            XI3C_SR_RESP_NOT_EMPTY_MASK,
            XI3C_SR_RESP_NOT_EMPTY_MASK,
            MAX_TIMEOUT_US,
        );
        if !happened {
            return 31;
        }
        let response_data = self.regs().resp_status_fifo.get();
        ((response_data & 0x1e0) >> 5) as i32
    }

    pub fn send_transfer_cmd(&mut self, cmd: &mut Command, data: Ccc) -> Result<(), i32> {
        assert!(self.ready);

        match data {
            Ccc::Byte(byte) => {
                cmd.byte_count = 1;
                self.write_tx_fifo(&[byte]);
            }
            Ccc::Data(data) => {
                cmd.byte_count = data.len() as u16;
                self.write_tx_fifo(&data);
            }
        }
        cmd.target_addr = XI3C_BROADCAST_ADDRESS;
        cmd.rw = 0;
        self.fill_cmd_fifo(cmd);
        if self.get_response() != 0 {
            return Err(XST_SEND_ERROR);
        }
        Ok(())
    }

    pub fn master_send(&mut self, cmd: &mut Command, mut msg_ptr: &[u8], byte_count: u16) -> i32 {
        if msg_ptr.is_empty() {
            return 13;
        }
        if byte_count > 4095 {
            return 28;
        }
        msg_ptr = &msg_ptr[..byte_count as usize];
        cmd.byte_count = byte_count;
        cmd.rw = 0;
        let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
        let mut space_index: u16 = 0;
        while space_index < wr_fifo_space && !msg_ptr.is_empty() {
            let size = self.write_tx_fifo(msg_ptr);
            msg_ptr = &msg_ptr[size..];
            space_index += 1;
        }
        if (self.config.wr_threshold as u16) < byte_count {
            self.regs().intr_fe.set(self.regs().intr_fe.get() | 0x20);
        }
        self.regs().intr_re.set(self.regs().intr_re.get() | 0x10);
        self.fill_cmd_fifo(cmd);
        0
    }

    /// This function initiates a polled mode send in master mode.
    ///
    /// It sends data to the FIFO and waits for the slave to pick them up.
    /// If controller fails to send data due arbitration lost or any other error,
    /// will stop transfer status.
    /// - msg_ptr is the pointer to the send buffer.
    /// - byte_count is the number of bytes to be sent.
    pub fn master_send_polled(
        &mut self,
        cmd: &mut Command,
        mut msg_ptr: &[u8],
        byte_count: u16,
    ) -> Result<(), i32> {
        if msg_ptr.is_empty() {
            return Err(XST_NO_DATA);
        }
        if byte_count > 4095 {
            return Err(XST_SEND_ERROR);
        }
        msg_ptr = &msg_ptr[..byte_count as usize];
        cmd.byte_count = byte_count;
        cmd.rw = 0;
        self.fill_cmd_fifo(cmd);
        while !msg_ptr.is_empty() {
            let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
            let mut space_index: u16 = 0;
            while space_index < wr_fifo_space && !msg_ptr.is_empty() {
                let written = self.write_tx_fifo(msg_ptr);
                msg_ptr = &msg_ptr[written..];
                space_index += 1;
            }
        }
        //println!("Waiting for master_send_polled response");
        if self.get_response() != 0 {
            Err(XST_SEND_ERROR)
        } else {
            //println!("master_send_polled OK");
            Ok(())
        }
    }

    pub fn master_recv_polled(
        &mut self,
        running: Option<Arc<AtomicBool>>,
        cmd: &mut Command,
        byte_count: u16,
    ) -> Result<Vec<u8>, i32> {
        self.master_recv(cmd, byte_count)?;
        self.master_recv_finish(running, cmd, byte_count)
    }

    /// Starts a receive from a target, but does not wait on the result (must call .master_recv_finish() separately).
    pub fn master_recv(&mut self, cmd: &mut Command, byte_count: u16) -> Result<(), i32> {
        if byte_count > 4095 {
            return Err(XST_RECV_ERROR);
        }
        cmd.byte_count = byte_count;
        cmd.rw = 1;
        self.fill_cmd_fifo(cmd);
        Ok(())
    }

    /// Receives up to 4 bytes from the read FIFO.
    /// Could return fewer. 0 bytes are returned if no data is available.
    pub fn master_recv_4_bytes(&mut self) -> Vec<u8> {
        let rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        if rx_data_available > 0 {
            self.read_rx_fifo(rx_data_available.min(4))
        } else {
            vec![]
        }
    }

    /// Finishes a receive from a target.
    pub fn master_recv_finish(
        &mut self,
        running: Option<Arc<AtomicBool>>,
        cmd: &Command,
        byte_count: u16,
    ) -> Result<Vec<u8>, i32> {
        let mut recv_byte_count = if cmd.target_addr == XI3C_BROADCAST_ADDRESS {
            (byte_count as i32 - 1) as u16
        } else {
            byte_count
        };
        let mut recv = vec![];
        let running = running.unwrap_or_else(|| Arc::new(AtomicBool::new(true)));
        while running.load(Ordering::Relaxed) && recv_byte_count > 0 {
            let rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
            let mut data_index: u16 = 0;
            while data_index < rx_data_available && recv_byte_count > 0 {
                let new_bytes = self.read_rx_fifo(recv_byte_count);
                recv.extend(&new_bytes);
                recv_byte_count = recv_byte_count.saturating_sub(new_bytes.len() as u16);
                data_index += 1;
            }
        }
        if self.get_response() != 0 {
            Err(XST_RECV_ERROR)
        } else {
            Ok(recv)
        }
    }

    fn ibi_read_rx_fifo(&mut self) -> Vec<u8> {
        let rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        let mut data_index: u16 = 0;
        let mut recv = vec![];
        while data_index < rx_data_available {
            recv.extend(self.read_rx_fifo(4));
            data_index += 1;
        }
        recv
    }

    #[allow(dead_code)]
    pub fn set_status_handler(&mut self, handler: Box<dyn ErrorHandler>) {
        assert!(self.ready);
        self.status_handler = Some(handler);
    }

    pub fn master_interrupt_handler(&mut self) -> Result<(), i32> {
        let mut dyna_addr: [u8; 1] = [0; 1];
        let intr_status_reg = self.regs().intr_status.get();
        self.regs().intr_status.set(intr_status_reg);
        if intr_status_reg & XI3C_INTR_HJ_MASK != 0 {
            if self.cur_device_count as i32 <= 108 {
                dyna_addr[0] = DYNA_ADDR_LIST[self.cur_device_count as usize];
                self.dyna_addr_assign(&dyna_addr, 1)?;
                self.update_addr_bcr((self.cur_device_count as i32 - 1) as u16);
            }
            self.reset_fifos();
        }
        if intr_status_reg & XI3C_INTR_IBI_MASK != 0 {
            while self.regs().sr.get() & XI3C_SR_RD_FIFO_NOT_EMPTY_MASK != 0
                || self.regs().sr.get() & XI3C_SR_RESP_NOT_EMPTY_MASK == 0
            {
                self.ibi_read_rx_fifo();
            }
            self.regs()
                .intr_re
                .set(self.regs().intr_re.get() & !XI3C_INTR_IBI_MASK);
        }
        if intr_status_reg & XI3C_INTR_WR_FIFO_ALMOST_FULL_MASK != 0 {
            // We don't support buffering data locally.
            // let wr_fifo_space = (self.regs().fifo_lvl_status.get() & 0xffff) as u16;
            // let mut space_index: u16 = 0;
            // while (space_index as i32) < wr_fifo_space as i32 && self.send_byte_count as i32 > 0 {
            //     self.write_tx_fifo();
            //     space_index = space_index.wrapping_add(1);
            // }
            // if self.send_byte_count as i32 <= 0 {
            self.regs()
                .intr_fe
                .set(self.regs().intr_fe.get() & !XI3C_INTR_WR_FIFO_ALMOST_FULL_MASK);
            // }
        }
        // No FIFO interrupts.
        // if intr_status_reg & XI3C_INTR_RD_FULL_MASK != 0 {
        //     rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        //     data_index = 0;
        //     while (data_index as i32) < rx_data_available as i32 && self.recv_byte_count as i32 > 0
        //     {
        //         self.read_rx_fifo();
        //         data_index = data_index.wrapping_add(1);
        //     }
        //     if self.recv_byte_count as i32 <= 0 {
        //         self.regs().intr_re.set(self.regs().intr_re.get() & !0x40);
        //     }
        // }
        // if intr_status_reg & XI3C_INTR_RESP_NOT_EMPTY_MASK != 0 {
        //     if self.recv_byte_count as i32 > 0 {
        //         rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
        //         data_index = 0;
        //         while (data_index as i32) < rx_data_available as i32
        //             && self.recv_byte_count as i32 > 0
        //         {
        //             self.read_rx_fifo();
        //             data_index = data_index.wrapping_add(1);
        //         }
        //     }
        //     if self.config.ibi_capable {
        //         self.ibi_read_rx_fifo();
        //     }
        //     let response_data = self.regs().resp_status_fifo.get();
        //     self.error = ((response_data & 0x1e0) >> 5) as u8;
        //     self.regs()
        //         .intr_re
        //         .set(self.regs().intr_re.get() & !(0x10 | 0x40));
        //     self.regs().intr_fe.set(self.regs().intr_fe.get() & !0x20);
        //     if let Some(handler) = self.status_handler.as_ref() {
        //         handler.handle_error(self.error as u32);
        //     }
        // }
        Ok(())
    }

    /// This function receives data during IBI in polled mode.
    ///
    /// It polls the data register for data to come in during IBI.
    /// If controller fails to read data due to any error, it will return an Err with the status.
    pub fn ibi_recv_polled(&mut self) -> Result<Vec<u8>, i32> {
        let mut recv = vec![];
        let mut data_index: u16;
        let mut rx_data_available: u16;
        let happened = self.wait_for_event(
            XI3C_SR_RD_FIFO_NOT_EMPTY_MASK,
            XI3C_SR_RD_FIFO_NOT_EMPTY_MASK,
            MAX_TIMEOUT_US * 10,
        );
        if happened {
            println!("Got an IBI, reading data");
            while self.regs().sr.get() & XI3C_SR_RD_FIFO_NOT_EMPTY_MASK != 0
                || self.regs().sr.get() & XI3C_SR_RESP_NOT_EMPTY_MASK == 0
            {
                rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
                println!("rx_data_available: {}", rx_data_available);
                data_index = 0;
                while data_index < rx_data_available {
                    recv.extend(self.read_rx_fifo(4));
                    data_index += 1;
                }
            }
            rx_data_available = (self.regs().fifo_lvl_status_1.get() & 0xffff) as u16;
            data_index = 0;
            while data_index < rx_data_available {
                recv.extend(self.read_rx_fifo(4));
                data_index += 1;
            }
        }
        if self.get_response() != 0 {
            Err(XST_RECV_ERROR)
        } else {
            Ok(recv)
        }
    }

    /// Wait for a specific event to occur in the status register.
    /// Returns true if the event occurred withing the timeout period.
    pub fn wait_for_event(&mut self, event_mask: u32, event: u32, timeout_us: u32) -> bool {
        let start_time = Instant::now();
        let timeout_duration = Duration::from_micros(timeout_us as u64);

        while start_time.elapsed() < timeout_duration {
            let event_status = self.regs().sr.get() & event_mask;
            if event_status == event {
                return true;
            }
            std::thread::sleep(Duration::from_micros(1));
        }
        false
    }
}

// Computes the parity, inverted.
#[inline]
fn get_odd_parity(addr: u8) -> u8 {
    addr.count_ones() as u8 & 1 ^ 1
}

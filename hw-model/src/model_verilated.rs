// Licensed under the Apache-2.0 license

use crate::bus_logger::{BusLogger, LogFile, NullBus};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_verilated::{AhbTxnType, CaliptraVerilated};
use std::cell::RefCell;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;

use crate::Output;
use std::env;

// TODO: Make this configurable
const SOC_PAUSER: u32 = 0xffff_ffff;

// How many clock cycles before emitting a TRNG nibble
const TRNG_DELAY: u32 = 4;

pub struct VerilatedApbBus<'a> {
    model: &'a mut ModelVerilated,
}
impl<'a> Bus for VerilatedApbBus<'a> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        if addr & 0x3 != 0 {
            return Err(caliptra_emu_bus::BusError::LoadAddrMisaligned);
        }
        let result = Ok(self.model.v.apb_read_u32(SOC_PAUSER, addr));
        self.model
            .log
            .borrow_mut()
            .log_read("SoC", size, addr, result);
        result
    }

    fn write(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        if addr & 0x3 != 0 {
            return Err(caliptra_emu_bus::BusError::StoreAddrMisaligned);
        }
        if size != RvSize::Word {
            return Err(caliptra_emu_bus::BusError::StoreAccessFault);
        }
        self.model.v.apb_write_u32(SOC_PAUSER, addr, val);
        self.model
            .log
            .borrow_mut()
            .log_write("SoC", size, addr, val, Ok(()));
        Ok(())
    }
}

pub struct ModelVerilated {
    v: CaliptraVerilated,

    output: Output,
    trace_enabled: bool,

    trng_nibbles: Box<dyn Iterator<Item = u8>>,
    trng_delay_remaining: u32,

    log: Rc<RefCell<BusLogger<NullBus>>>,
}

impl ModelVerilated {
    pub fn start_tracing(&mut self, path: &str, depth: i32) {
        self.v.start_tracing(path, depth).unwrap();
    }
    pub fn stop_tracing(&mut self) {
        self.v.stop_tracing();
    }
}

fn ahb_txn_size(ty: AhbTxnType) -> RvSize {
    match ty {
        AhbTxnType::ReadU8 | AhbTxnType::WriteU8 => RvSize::Byte,
        AhbTxnType::ReadU16 | AhbTxnType::WriteU16 => RvSize::HalfWord,
        AhbTxnType::ReadU32 | AhbTxnType::WriteU32 => RvSize::Word,
        AhbTxnType::ReadU64 | AhbTxnType::WriteU64 => RvSize::Word,
    }
}

impl crate::HwModel for ModelVerilated {
    type TBus<'a> = VerilatedApbBus<'a>;

    fn new_unbooted(params: crate::InitParams) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
    {
        let output = Output::new(params.log_writer);

        let output_sink = output.sink().clone();

        let generic_load_cb = Box::new(move |v: &CaliptraVerilated, ch: u8| {
            output_sink.set_now(v.total_cycles());
            output_sink.push_uart_char(ch);
        });

        let log = Rc::new(RefCell::new(BusLogger::new(NullBus())));
        let bus_log = log.clone();

        let ahb_cb = Box::new(
            move |_v: &CaliptraVerilated, ty: AhbTxnType, addr: u32, data: u64| {
                if ty.is_write() {
                    bus_log.borrow_mut().log_write(
                        "UC",
                        ahb_txn_size(ty),
                        addr,
                        data as u32,
                        Ok(()),
                    );
                    if ty == AhbTxnType::WriteU64 {
                        bus_log.borrow_mut().log_write(
                            "UC",
                            ahb_txn_size(ty),
                            addr + 4,
                            (data >> 32) as u32,
                            Ok(()),
                        );
                    }
                } else {
                    bus_log
                        .borrow_mut()
                        .log_read("UC", ahb_txn_size(ty), addr, Ok(data as u32));
                    if ty == AhbTxnType::WriteU64 {
                        bus_log.borrow_mut().log_read(
                            "UC",
                            ahb_txn_size(ty),
                            addr + 4,
                            Ok((data >> 32) as u32),
                        );
                    }
                }
            },
        );
        let mut v = CaliptraVerilated::with_callbacks(
            caliptra_verilated::InitArgs {
                security_state: u32::from(params.security_state),
            },
            generic_load_cb,
            ahb_cb,
        );

        v.write_rom_image(params.rom);

        let mut m = ModelVerilated {
            v,
            output,
            trace_enabled: false,

            trng_nibbles: params.trng_nibbles,
            trng_delay_remaining: TRNG_DELAY,

            log,
        };

        m.tracing_hint(true);

        m.v.input.cptra_pwrgood = true;
        m.v.next_cycle_high(1);

        m.v.input.cptra_rst_b = true;
        m.v.next_cycle_high(1);

        while !m.v.output.ready_for_fuses {
            m.v.next_cycle_high(1);
        }
        writeln!(m.output().logger(), "ready_for_fuses is high")?;
        Ok(m)
    }

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        VerilatedApbBus { model: self }
    }

    fn step(&mut self) {
        if self.v.output.etrng_req {
            if self.trng_delay_remaining == 0 {
                if let Some(val) = self.trng_nibbles.next() {
                    self.v.input.itrng_valid = true;
                    self.v.input.itrng_data = val & 0xf;
                }
                self.trng_delay_remaining = TRNG_DELAY;
            } else {
                self.trng_delay_remaining -= 1;
            }
        }
        self.v.next_cycle_high(1);
        self.v.input.itrng_valid = false;
    }

    fn output(&mut self) -> &mut crate::Output {
        self.output.sink().set_now(self.v.total_cycles());
        &mut self.output
    }

    fn ready_for_fw(&self) -> bool {
        self.v.output.ready_for_fw_push
    }

    fn tracing_hint(&mut self, enable: bool) {
        if self.trace_enabled != enable {
            self.trace_enabled = enable;
            if enable {
                if let Ok(trace_path) = env::var("CPTRA_TRACE_PATH") {
                    if trace_path.ends_with(".vcd") {
                        self.v.start_tracing(&trace_path, 99).ok();
                    } else {
                        self.log.borrow_mut().log = match LogFile::open(Path::new(&trace_path)) {
                            Ok(file) => Some(file),
                            Err(e) => {
                                eprintln!("Unable to open file {trace_path:?}: {e}");
                                return;
                            }
                        };
                    }
                }
            } else {
                if self.log.borrow_mut().log.take().is_none() {
                    self.v.stop_tracing();
                }
            }
        }
    }
}

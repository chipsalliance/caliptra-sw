// Licensed under the Apache-2.0 license

use crate::bus_logger::{BusLogger, LogFile, NullBus};
use crate::trace_path_or_env;
use crate::EtrngResponse;
use crate::{HwModel, SocManager, TrngMode};
use caliptra_api_types::Fuses;
use caliptra_emu_bus::Bus;
use caliptra_emu_bus::BusMmio;
use caliptra_emu_bus::Event;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model_types::ErrorInjectionMode;
use caliptra_verilated::{AhbTxnType, CaliptraVerilated};
use std::cell::{Cell, RefCell};
use std::ffi::OsStr;
use std::io::Write;
use std::mpsc;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::Output;

const DEFAULT_AXI_PAUSER: u32 = 0x1;

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
        let result = Ok(self.model.v.apb_read_u32(self.model.soc_axi_pauser, addr));
        self.model
            .log
            .borrow_mut()
            .log_read("SoC", size, addr, result);
        self.model.process_trng();
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
        self.model
            .v
            .apb_write_u32(self.model.soc_axi_pauser, addr, val);
        self.model
            .log
            .borrow_mut()
            .log_write("SoC", size, addr, val, Ok(()));
        self.model.process_trng();
        Ok(())
    }
}

// Like EtrngResponse, but with an absolute time
struct AbsoluteEtrngResponse {
    time: u64,
    data: [u32; 12],
}

pub struct ModelVerilated {
    pub v: CaliptraVerilated,
    fuses: Fuses,

    output: Output,
    trace_enabled: bool,
    trace_path: Option<PathBuf>,

    trng_mode: TrngMode,

    itrng_nibbles: Box<dyn Iterator<Item = u8>>,
    itrng_delay_remaining: u32,

    etrng_responses: Box<dyn Iterator<Item = EtrngResponse>>,
    etrng_response: Option<AbsoluteEtrngResponse>,
    etrng_waiting_for_req_to_clear: bool,

    log: Rc<RefCell<BusLogger<NullBus>>>,

    soc_axi_pauser: u32,
}

impl ModelVerilated {
    pub fn start_tracing(&mut self, path: &str, depth: i32) {
        self.v.start_tracing(path, depth).unwrap();
    }
    pub fn stop_tracing(&mut self) {
        self.v.stop_tracing();
    }

    /// Set all mailbox SRAM cells to value with double-bit ECC errors
    pub fn corrupt_mailbox_ecc_double_bit(&mut self) {
        self.v.corrupt_mailbox_ecc_double_bit();
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
impl SocManager for ModelVerilated {
    type TMmio<'a> = BusMmio<VerilatedApbBus<'a>>;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.apb_bus())
    }

    fn delay(&mut self) {
        self.step();
    }

    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;
}

impl HwModel for ModelVerilated {
    type TBus<'a> = VerilatedApbBus<'a>;

    fn new_unbooted(params: crate::InitParams) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
    {
        let output = Output::new(params.log_writer);

        let output_sink = output.sink().clone();

        let generic_output_wires_changed_cb = {
            let prev_uout = Cell::new(None);
            Box::new(move |v: &CaliptraVerilated, out_wires| {
                if Some(out_wires & 0x1ff) != prev_uout.get() {
                    // bit #8 toggles whenever the Uart driver writes a byte, so
                    // by including it in the comparison we can tell when the
                    // same character has been written a second time
                    if prev_uout.get().is_some() {
                        // Don't print out a character for the initial state
                        output_sink.set_now(v.total_cycles());
                        output_sink.push_uart_char((out_wires & 0xff) as u8);
                    }
                    prev_uout.set(Some(out_wires & 0x1ff));
                }
            })
        };

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
        let compiled_trng_mode = if cfg!(feature = "itrng") {
            TrngMode::Internal
        } else {
            TrngMode::External
        };
        let desired_trng_mode = TrngMode::resolve(params.trng_mode);
        if desired_trng_mode != compiled_trng_mode {
            let msg_suffix = match desired_trng_mode {
                TrngMode::Internal => "try compiling with --features itrng",
                TrngMode::External => "try compiling without --features itrng",
            };
            return Err(format!(
                "HwModel InitParams asked for trng_mode={desired_trng_mode:?}, \
                    but verilog was compiled with trng_mode={compiled_trng_mode:?}; {msg_suffix}"
            )
            .into());
        }
        let mut v = CaliptraVerilated::with_callbacks(
            caliptra_verilated::InitArgs {
                security_state: u32::from(params.security_state),
                cptra_obf_key: params.cptra_obf_key,
            },
            generic_output_wires_changed_cb,
            ahb_cb,
        );

        v.write_rom_image(params.rom);

        let mut m = ModelVerilated {
            v,
            fuses: params.fuses,
            output,
            trace_enabled: false,
            trace_path: trace_path_or_env(params.trace_path),

            trng_mode: desired_trng_mode,

            itrng_nibbles: params.itrng_nibbles,
            itrng_delay_remaining: TRNG_DELAY,

            etrng_responses: params.etrng_responses,
            etrng_response: None,
            etrng_waiting_for_req_to_clear: false,

            log,

            soc_axi_pauser: DEFAULT_AXI_PAUSER,
        };

        m.tracing_hint(true);

        if params.random_sram_puf {
            m.v.init_random_puf_state(&mut rand::thread_rng());
        }

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

    fn type_name(&self) -> &'static str {
        "ModelVerilated"
    }

    fn trng_mode(&self) -> TrngMode {
        self.trng_mode
    }

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        VerilatedApbBus { model: self }
    }

    fn step(&mut self) {
        self.process_trng_start();
        self.v.next_cycle_high(1);
        self.process_trng_end();
    }

    fn output(&mut self) -> &mut crate::Output {
        self.output.sink().set_now(self.v.total_cycles());
        &mut self.output
    }

    fn warm_reset(&mut self) {
        // Toggle reset pin
        self.v.input.cptra_rst_b = false;
        self.v.next_cycle_high(1);

        self.v.input.cptra_rst_b = true;
        self.v.next_cycle_high(1);

        // Wait for ready_for_fuses
        while !self.v.output.ready_for_fuses {
            self.v.next_cycle_high(1);
        }
    }

    fn cold_reset(&mut self) {
        // Toggle reset pin
        self.v.input.cptra_rst_b = false;
        self.v.next_cycle_high(1);

        // Toggle pwrgood pin
        self.v.input.cptra_pwrgood = false;
        self.v.next_cycle_high(1);

        self.v.input.cptra_pwrgood = true;
        self.v.next_cycle_high(1);

        self.v.input.cptra_rst_b = true;
        self.v.next_cycle_high(1);

        // Wait for ready_for_fuses
        while !self.v.output.ready_for_fuses {
            self.v.next_cycle_high(1);
        }
    }

    fn ready_for_mb_processing(&self) -> bool {
        self.v.output.ready_for_mb_processing_push
    }

    fn tracing_hint(&mut self, enable: bool) {
        if self.trace_enabled != enable {
            self.trace_enabled = enable;
            if enable {
                if let Some(trace_path) = &self.trace_path {
                    if trace_path.extension() == Some(OsStr::new("vcd")) {
                        self.v.start_tracing(trace_path.to_str().unwrap(), 99).ok();
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

    fn ecc_error_injection(&mut self, mode: ErrorInjectionMode) {
        match mode {
            ErrorInjectionMode::None => {
                self.v.input.sram_error_injection_mode = 0x0;
            }
            ErrorInjectionMode::IccmDoubleBitEcc => {
                self.v.input.sram_error_injection_mode = 0x2;
            }
            ErrorInjectionMode::DccmDoubleBitEcc => {
                self.v.input.sram_error_injection_mode = 0x8;
            }
        }
    }

    fn set_axi_user(&mut self, pauser: u32) {
        self.soc_axi_pauser = pauser;
    }
}
impl ModelVerilated {
    fn process_trng(&mut self) {
        if self.process_trng_start() {
            self.v.next_cycle_high(1);
            self.process_trng_end();
        }
    }
    fn process_trng_start(&mut self) -> bool {
        match self.trng_mode {
            TrngMode::Internal => self.process_itrng_start(),
            TrngMode::External => self.process_etrng_start(),
        }
    }

    fn process_trng_end(&mut self) {
        match self.trng_mode {
            TrngMode::Internal => self.process_itrng_end(),
            TrngMode::External => {}
        }
    }

    // Returns true if process_trng_end must be called after a clock cycle
    fn process_etrng_start(&mut self) -> bool {
        if self.etrng_waiting_for_req_to_clear && !self.v.output.etrng_req {
            self.etrng_waiting_for_req_to_clear = false;
        }
        if self.v.output.etrng_req && !self.etrng_waiting_for_req_to_clear {
            if self.etrng_response.is_none() {
                if let Some(response) = self.etrng_responses.next() {
                    self.etrng_response = Some(AbsoluteEtrngResponse {
                        time: self.v.total_cycles() + u64::from(response.delay),
                        data: response.data,
                    });
                }
            }
            if let Some(etrng_response) = &mut self.etrng_response {
                if self.v.total_cycles().wrapping_sub(etrng_response.time) < 0x8000_0000_0000_0000 {
                    self.etrng_waiting_for_req_to_clear = true;
                    let etrng_response = self.etrng_response.take().unwrap();
                    self.soc_ifc_trng()
                        .cptra_trng_data()
                        .write(&etrng_response.data);
                    self.soc_ifc_trng()
                        .cptra_trng_status()
                        .write(|w| w.data_wr_done(true));
                }
            }
        }
        false
    }
    // Returns true if process_trng_end must be called after a clock cycle
    fn process_itrng_start(&mut self) -> bool {
        if self.v.output.etrng_req {
            if self.itrng_delay_remaining == 0 {
                if let Some(val) = self.itrng_nibbles.next() {
                    self.v.input.itrng_valid = true;
                    self.v.input.itrng_data = val & 0xf;
                }
                self.itrng_delay_remaining = TRNG_DELAY;
            } else {
                self.itrng_delay_remaining -= 1;
            }
            self.v.input.itrng_valid
        } else {
            false
        }
    }
    fn process_itrng_end(&mut self) {
        if self.v.input.itrng_valid {
            self.v.input.itrng_valid = false;
        }
    }

    fn put_firmware_in_rri(&mut self, firmware: &[u8]) -> Result<(), ModelError> {
        todo!()
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        todo!()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        todo!()
    }

    fn write_payload_to_ss_staging_area(&mut self, payload: &[u8]) -> Result<u64, ModelError> {
        todo!()
    }

    fn read_payload_from_ss_staging_area(&mut self, _len: usize) -> Result<Vec<u8>, ModelError> {
        todo!()
    }

    fn fuses(&self) -> &Fuses {
        &self.fuses
    }

    fn set_fuses(&mut self, fuses: Fuses) {
        self.fuses = fuses;
    }
}

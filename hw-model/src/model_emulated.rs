// Licensed under the Apache-2.0 license

use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::Hasher;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;

use caliptra_api::soc_mgr::SocManager;
use caliptra_api_types::Fuses;
use caliptra_emu_bus::Clock;
use caliptra_emu_bus::Device;
use caliptra_emu_bus::Event;
use caliptra_emu_bus::EventData;
use caliptra_emu_bus::{Bus, BusMmio};
#[cfg(feature = "coverage")]
use caliptra_emu_cpu::CoverageBitmaps;
use caliptra_emu_cpu::{Cpu, CpuArgs, InstrTracer, Pic};
use caliptra_emu_periph::dma::axi_root_bus::AxiRootBus;
use caliptra_emu_periph::dma::recovery::RecoveryControl;
use caliptra_emu_periph::ActionCb;
use caliptra_emu_periph::MailboxExternal;
use caliptra_emu_periph::Mci;
use caliptra_emu_periph::ReadyForFwCb;
use caliptra_emu_periph::{
    CaliptraRootBus, CaliptraRootBusArgs, MailboxRequester, SocToCaliptraBus, TbServicesCb,
};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model_types::ErrorInjectionMode;
use caliptra_image_types::IMAGE_MANIFEST_BYTE_SIZE;
use caliptra_registers::i3ccsr::regs::DeviceStatus0ReadVal;
use tock_registers::interfaces::{ReadWriteable, Readable};

use crate::bus_logger::BusLogger;
use crate::bus_logger::LogFile;
use crate::trace_path_or_env;
use crate::HwModel;
use crate::InitParams;
use crate::ModelError;
use crate::Output;
use crate::TrngMode;

pub struct EmulatedApbBus<'a> {
    model: &'a mut ModelEmulated,
}

impl Bus for EmulatedApbBus<'_> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        let result = self.model.soc_to_caliptra_bus.read(size, addr);
        self.model.cpu.bus.log_read("SoC", size, addr, result);
        result
    }
    fn write(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        let result = self.model.soc_to_caliptra_bus.write(size, addr, val);
        self.model.cpu.bus.log_write("SoC", size, addr, val, result);
        result
    }
}

/// Emulated model
pub struct ModelEmulated {
    cpu: Cpu<BusLogger<CaliptraRootBus>>,
    soc_to_caliptra_bus: SocToCaliptraBus,
    output: Output,
    trace_fn: Option<Box<InstrTracer<'static>>>,
    ready_for_fw: Rc<Cell<bool>>,
    cpu_enabled: Rc<Cell<bool>>,
    trace_path: Option<PathBuf>,
    fuses: Fuses,

    // Keep this even when not including the coverage feature to keep the
    // interface consistent
    _rom_image_tag: u64,
    iccm_image_tag: Option<u64>,
    trng_mode: TrngMode,

    events_to_caliptra: mpsc::Sender<Event>,
    events_from_caliptra: mpsc::Receiver<Event>,
    collected_events_from_caliptra: Vec<Event>,

    pub mci: Mci,
}

#[cfg(feature = "coverage")]
impl Drop for ModelEmulated {
    fn drop(&mut self) {
        let cov_path =
            std::env::var(caliptra_coverage::CPTRA_COVERAGE_PATH).unwrap_or_else(|_| "".into());
        if cov_path.is_empty() {
            return;
        }

        let CoverageBitmaps { rom, iccm } = self.code_coverage_bitmap();
        let _ = caliptra_coverage::dump_emu_coverage_to_file(
            cov_path.as_str(),
            self._rom_image_tag,
            rom,
        );

        if let Some(iccm_image_tag) = self.iccm_image_tag {
            let _ = caliptra_coverage::dump_emu_coverage_to_file(
                cov_path.as_str(),
                iccm_image_tag,
                iccm,
            );
        }
    }
}

#[cfg(feature = "coverage")]
impl ModelEmulated {
    pub fn code_coverage_bitmap(&self) -> CoverageBitmaps {
        self.cpu.code_coverage.code_coverage_bitmap()
    }
}

fn hash_slice(slice: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    std::hash::Hash::hash_slice(slice, &mut hasher);
    hasher.finish()
}

impl SocManager for ModelEmulated {
    type TMmio<'a> = BusMmio<EmulatedApbBus<'a>>;

    fn delay(&mut self) {
        self.step();
    }

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.apb_bus())
    }

    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;
}

impl HwModel for ModelEmulated {
    type TBus<'a> = EmulatedApbBus<'a>;

    fn new_unbooted(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let timer = clock.timer();

        let args = CpuArgs::default();

        let ready_for_fw = Rc::new(Cell::new(false));
        let ready_for_fw_clone = ready_for_fw.clone();

        let cpu_enabled = Rc::new(Cell::new(false));
        let cpu_enabled_cloned = cpu_enabled.clone();

        let output = Output::new(params.log_writer);

        let output_sink = output.sink().clone();

        let bus_args = CaliptraRootBusArgs {
            rom: params.rom.into(),
            tb_services_cb: TbServicesCb::new(move |ch| {
                output_sink.set_now(timer.now());
                output_sink.push_uart_char(ch);
            }),
            ready_for_fw_cb: ReadyForFwCb::new(move |_| {
                ready_for_fw_clone.set(true);
            }),
            bootfsm_go_cb: ActionCb::new(move || {
                cpu_enabled_cloned.set(true);
            }),
            security_state: params.security_state,
            dbg_manuf_service_req: params.dbg_manuf_service,
            subsystem_mode: params.subsystem_mode,
            ocp_lock_en: params.ocp_lock_en,
            prod_dbg_unlock_keypairs: params.prod_dbg_unlock_keypairs,
            debug_intent: params.debug_intent,
            cptra_obf_key: params.cptra_obf_key,

            itrng_nibbles: Some(params.itrng_nibbles),
            etrng_responses: params.etrng_responses,
            test_sram: params.test_sram,
            clock: clock.clone(),
            pic: pic.clone(),
            ..CaliptraRootBusArgs::default()
        };
        let mut root_bus = CaliptraRootBus::new(bus_args);

        let trng_mode = TrngMode::resolve(params.trng_mode);
        let hw_config = {
            let mut hw_config = 0;
            if matches!(trng_mode, TrngMode::Internal) {
                hw_config |= 1;
            }
            if params.subsystem_mode {
                hw_config |= 1 << 5
            }
            if params.ocp_lock_en {
                hw_config |= 1 << 6
            }
            hw_config
        };
        root_bus.soc_reg.set_hw_config(hw_config.into());

        let input_wires = (!params.uds_fuse_row_granularity_64 as u32) << 31;
        root_bus.soc_reg.set_generic_input_wires(&[input_wires, 0]);

        let ss_strap_generic_reg_0 = params.otp_dai_idle_bit_offset << 16;
        let ss_strap_generic_reg_1 = params.otp_direct_access_cmd_reg_offset;
        root_bus
            .soc_reg
            .set_strap_generic(&[ss_strap_generic_reg_0, ss_strap_generic_reg_1, 0, 0]);

        {
            let mut iccm_ram = root_bus.iccm.ram().borrow_mut();
            let Some(iccm_dest) = iccm_ram.data_mut().get_mut(0..params.iccm.len()) else {
                return Err(ModelError::ProvidedIccmTooLarge.into());
            };
            iccm_dest.copy_from_slice(params.iccm);

            let Some(dccm_dest) = root_bus.dccm.data_mut().get_mut(0..params.dccm.len()) else {
                return Err(ModelError::ProvidedDccmTooLarge.into());
            };
            dccm_dest.copy_from_slice(params.dccm);
        }
        let soc_to_caliptra_bus = root_bus.soc_to_caliptra_bus(params.soc_user);
        let (events_to_caliptra, events_from_caliptra, cpu) = {
            let mut cpu = Cpu::new(BusLogger::new(root_bus), clock, pic, args);
            if let Some(stack_info) = params.stack_info {
                cpu.with_stack_info(stack_info);
            }
            let (events_to_caliptra, events_from_caliptra) = cpu.register_events();
            (events_to_caliptra, events_from_caliptra, cpu)
        };

        let mut hasher = DefaultHasher::new();
        std::hash::Hash::hash_slice(params.rom, &mut hasher);
        let image_tag = hasher.finish();
        let mci_regs = cpu.bus.bus.mci_external_regs();

        let mut m = ModelEmulated {
            output,
            cpu,
            soc_to_caliptra_bus,
            trace_fn: None,
            ready_for_fw,
            cpu_enabled,
            trace_path: trace_path_or_env(params.trace_path),
            fuses: params.fuses,
            _rom_image_tag: image_tag,
            iccm_image_tag: None,
            trng_mode,
            events_to_caliptra,
            events_from_caliptra,
            collected_events_from_caliptra: vec![],
            mci: mci_regs,
        };
        // Turn tracing on if the trace path was set
        m.tracing_hint(true);

        Ok(m)
    }

    fn type_name(&self) -> &'static str {
        "ModelEmulated"
    }

    fn trng_mode(&self) -> TrngMode {
        self.trng_mode
    }

    fn ready_for_fw(&self) -> bool {
        self.ready_for_fw.get()
    }
    fn apb_bus(&mut self) -> Self::TBus<'_> {
        EmulatedApbBus { model: self }
    }

    fn step(&mut self) {
        if self.cpu_enabled.get() {
            self.cpu.step(self.trace_fn.as_deref_mut());
        }

        // do the bare minimum for the recovery flow: activating the recovery image
        const DEVICE_STATUS_PENDING: u32 = 0x4;
        const ACTIVATE_RECOVERY_IMAGE_CMD: u32 = 0xF;
        if DeviceStatus0ReadVal::from(self.cpu.bus.bus.dma.axi.recovery.device_status_0.reg.get())
            .dev_status()
            == DEVICE_STATUS_PENDING
        {
            self.cpu
                .bus
                .bus
                .dma
                .axi
                .recovery
                .recovery_ctrl
                .reg
                .modify(RecoveryControl::ACTIVATE_RECOVERY_IMAGE.val(ACTIVATE_RECOVERY_IMAGE_CMD));
        }

        for event in self.events_from_caliptra.try_iter() {
            self.collected_events_from_caliptra.push(event.clone());
            // brute force respond to AXI DMA MCU SRAM read
            if let (Device::MCU, EventData::MemoryRead { start_addr, len }) =
                (event.dest, event.event)
            {
                let addr = start_addr as usize;
                let mcu_sram_data = self.cpu.bus.bus.dma.axi.mcu_sram.data_mut();
                let Some(dest) = mcu_sram_data.get_mut(addr..addr + len as usize) else {
                    continue;
                };
                self.events_to_caliptra
                    .send(Event {
                        src: Device::MCU,
                        dest: Device::CaliptraCore,
                        event: EventData::MemoryReadResponse {
                            start_addr,
                            data: dest.to_vec(),
                        },
                    })
                    .unwrap();
            }
        }
    }

    fn output(&mut self) -> &mut Output {
        // In case the caller wants to log something, make sure the log has the
        // correct time.env::
        self.output.sink().set_now(self.cpu.clock.now());
        &mut self.output
    }

    fn cover_fw_image(&mut self, fw_image: &[u8]) {
        let iccm_image = &fw_image[IMAGE_MANIFEST_BYTE_SIZE..];
        self.iccm_image_tag = Some(hash_slice(iccm_image));
    }
    fn tracing_hint(&mut self, enable: bool) {
        if enable == self.trace_fn.is_some() {
            // No change
            return;
        }
        self.trace_fn = None;
        self.cpu.bus.log = None;
        let Some(trace_path) = &self.trace_path else {
            return;
        };

        let mut log = match LogFile::open(trace_path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Unable to open file {trace_path:?}: {e}");
                return;
            }
        };
        self.cpu.bus.log = Some(log.clone());
        self.trace_fn = Some(Box::new(move |pc, _instr| {
            writeln!(log, "pc=0x{pc:x}").unwrap();
        }))
    }

    fn ecc_error_injection(&mut self, mode: ErrorInjectionMode) {
        match mode {
            ErrorInjectionMode::None => {
                self.cpu.bus.bus.iccm.ram().borrow_mut().error_injection = 0;
                self.cpu.bus.bus.dccm.error_injection = 0;
            }
            ErrorInjectionMode::IccmDoubleBitEcc => {
                self.cpu.bus.bus.iccm.ram().borrow_mut().error_injection = 2;
            }
            ErrorInjectionMode::DccmDoubleBitEcc => {
                self.cpu.bus.bus.dccm.error_injection = 8;
            }
        }
    }

    fn set_axi_user(&mut self, axi_user: u32) {
        self.soc_to_caliptra_bus.mailbox = MailboxExternal {
            soc_user: MailboxRequester::from(axi_user),
            regs: self.soc_to_caliptra_bus.mailbox.regs.clone(),
        };
    }

    fn warm_reset(&mut self) {
        self.cpu.warm_reset();
        self.step();
    }

    // [TODO][CAP2] Should it be statically provisioned?
    fn put_firmware_in_rri(
        &mut self,
        firmware: &[u8],
        soc_manifest: Option<&[u8]>,
        mcu_firmware: Option<&[u8]>,
    ) -> Result<(), ModelError> {
        self.cpu.bus.bus.dma.axi.recovery.cms_data = vec![firmware.to_vec()];
        if let Some(soc_manifest) = soc_manifest {
            self.cpu
                .bus
                .bus
                .dma
                .axi
                .recovery
                .cms_data
                .push(soc_manifest.to_vec());
            if let Some(mcu_fw) = mcu_firmware {
                self.cpu
                    .bus
                    .bus
                    .dma
                    .axi
                    .recovery
                    .cms_data
                    .push(mcu_fw.to_vec());
            }
        }
        Ok(())
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        self.collected_events_from_caliptra.drain(..).collect()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        self.events_to_caliptra.clone()
    }

    fn write_payload_to_ss_staging_area(&mut self, payload: &[u8]) -> Result<u64, ModelError> {
        if !self.subsystem_mode() {
            return Err(ModelError::SubsystemSramError);
        }

        let payload_len = payload.len();
        self.cpu
            .bus
            .bus
            .dma
            .axi
            .mcu_sram
            .data_mut()
            .get_mut(..payload_len)
            .ok_or(ModelError::SubsystemSramError)?
            .copy_from_slice(payload);
        Ok(AxiRootBus::mcu_sram_offset())
    }

    fn read_payload_from_ss_staging_area(&mut self, len: usize) -> Result<Vec<u8>, ModelError> {
        if !self.subsystem_mode() {
            return Err(ModelError::SubsystemSramError);
        }

        let data = self
            .cpu
            .bus
            .bus
            .dma
            .axi
            .mcu_sram
            .data()
            .get(..len)
            .ok_or(ModelError::SubsystemSramError)?;
        Ok(data.to_vec())
    }

    fn fuses(&self) -> &Fuses {
        &self.fuses
    }

    fn set_fuses(&mut self, fuses: Fuses) {
        self.fuses = fuses;
    }
}

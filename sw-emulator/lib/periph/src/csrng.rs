// Licensed under the Apache-2.0 license

use crate::entropy_combiner::CombinerLink;
use caliptra_emu_bus::{Bus, BusError, Clock, ReadOnlyRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_registers::entropy_src::regs::{
    AdaptpHiThresholdReadVal, AdaptpLoThresholdReadVal, ConfReadVal, HealthTestWindowsReadVal,
    RepcntThresholdReadVal, RepcntsThresholdReadVal,
};
use sha3::{Digest, Sha3_384};
use std::{cell::RefCell, mem, rc::Rc};
use tock_registers::interfaces::Readable;

mod health_test;
use health_test::HealthTester;

mod ctr_drbg;
use ctr_drbg::{Block, CtrDrbg, Instantiate, Seed, SEED_LEN_BYTES};

use crate::helpers::bytes_from_words_be;

type Word = u32;

const BITS_PER_NIBBLE: usize = 4;
const WORD_SIZE_BYTES: usize = mem::size_of::<Word>();

#[derive(Clone, Default)]
pub(crate) struct SecondaryEntropySource(Option<Rc<RefCell<Csrng>>>);

impl SecondaryEntropySource {
    pub(crate) fn new(nibbles: Box<dyn Iterator<Item = u8>>, clock: Rc<Clock>) -> Self {
        let mut source = Csrng::new(nibbles);
        source.dual_clock = Some(clock);
        Self(Some(Rc::new(RefCell::new(source))))
    }
}

impl Bus for SecondaryEntropySource {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.0
            .as_ref()
            .ok_or(BusError::LoadAccessFault)?
            .borrow_mut()
            .read(size, 0x1000 + addr)
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.0
            .as_ref()
            .ok_or(BusError::StoreAccessFault)?
            .borrow_mut()
            .write(size, 0x1000 + addr, val)
    }

    fn warm_reset(&mut self) {
        if let Some(source) = &self.0 {
            source.borrow_mut().reset_source_config();
        }
    }
}

#[derive(Bus)]
#[warm_reset_fn(warm_reset)]
pub struct Csrng {
    // CSRNG registers
    #[register(offset = 0x14, write_fn = ctrl_write)]
    ctrl: u32,

    #[register(offset = 0x18, write_fn = cmd_req_write)]
    cmd_req: WriteOnlyRegister<u32>,

    #[register(offset = 0x1C, write_fn = reseed_interval_write)]
    reseed_interval: u32,

    // SW app instance counter (NumApps=3, instance 2 is what the driver reads).
    #[register(offset = 0x28, read_fn = reseed_counter_read)]
    reseed_counter_2: ReadOnlyRegister<u32>,

    #[register(offset = 0x2c, read_fn = read_command_status)]
    sw_cmd_sts: ReadOnlyRegister<u32>,

    #[register(offset = 0x30, read_fn = genbits_vld_read)]
    genbits_vld: ReadOnlyRegister<u32>,

    #[register(offset = 0x34, read_fn = genbits_read)]
    genbits: ReadOnlyRegister<u32>,

    // MAIN_SM_STATE is Idle except while waiting for a dual entropy seed.
    #[register(offset = 0x5c, read_fn = read_csrng_state)]
    main_sm_state_csrng: ReadOnlyRegister<u32>,

    #[register(offset = 0x54)]
    err_code: ReadOnlyRegister<u32>,

    // Entropy Source registers
    // ME_REGWEN: Module enable register write enable (W0C - write-0-clear)
    // When cleared (false), MODULE_ENABLE becomes read-only
    #[register(offset = 0x1010, write_fn = me_regwen_write)]
    me_regwen: u32,

    // SW_REGUPD: Software update enable (W0C - write-0-clear)
    // When cleared (false), configuration registers become read-only
    #[register(offset = 0x1014, write_fn = sw_regupd_write)]
    sw_regupd: u32,

    #[register(offset = 0x1020, write_fn = module_enable_write)]
    module_enable: u32,

    #[register(offset = 0x1024, write_fn = conf_write)]
    conf: u32,

    // ES_TYPE (conditioning bypass) is stored but not modeled.
    #[register(offset = 0x1028, write_fn = entropy_control_write)]
    entropy_control: u32,

    #[register(offset = 0x1030, write_fn = health_test_windows_write)]
    health_test_windows: u32,

    #[register(offset = 0x1038, write_fn = repcnt_threshold_write)]
    repcnt_threshold: u32,

    #[register(offset = 0x103c, write_fn = repcnts_threshold_write)]
    repcnts_threshold: u32,

    #[register(offset = 0x1040, write_fn = adaptp_hi_threshold_write)]
    adaptp_hi_threshold: u32,

    #[register(offset = 0x1044, write_fn = adaptp_lo_threshold_write)]
    adaptp_lo_threshold: u32,

    #[register(offset = 0x1048, write_fn = adaptps_threshold_write)]
    adaptps_threshold: u32,

    #[register(offset = 0x1090)]
    alert_threshold: u32, // TODO: implement this

    #[register(offset = 0x1094, read_fn = alert_summary_fail_counts_read)]
    alert_summary_fail_counts: ReadOnlyRegister<u32>,

    #[register(offset = 0x1098, read_fn = alert_fail_counts_read)]
    alert_fail_counts: ReadOnlyRegister<u32>,

    #[register(offset = 0x10d0, read_fn = main_sm_state_read)]
    main_sm_state: ReadOnlyRegister<u32>,

    cmd_req_state: CmdReqState,
    seed: Vec<u32>,
    update: Vec<u32>,
    ctr_drbg: CtrDrbg,
    words: Words,
    health_tester: HealthTester,
    /// Tracks whether the first instantiate has completed (boot is done).
    /// Only after boot is complete should continuous health testing consume entropy,
    /// to avoid interfering with seed conditioning that requires specific entropy amounts.
    boot_instantiate_complete: bool,
    secondary: SecondaryEntropySource,
    dual_clock: Option<Rc<Clock>>,
    combiner: Option<Rc<CombinerLink>>,
    zeroize_epoch: u64,
    last_sample: u64,
    samples: Vec<u8>,
    window_start_failures: u32,
    consecutive_failures: u32,
    startup_ready: bool,
    ready_seed: Option<Seed>,
    pending_dual: Option<bool>, // true = reseed, false = instantiate
    latched: [Option<(Seed, bool)>; 2],
    output_fips: bool,
}

impl Csrng {
    pub fn new(itrng_nibbles: Box<dyn Iterator<Item = u8>>) -> Self {
        Self {
            // These reset values come from register definitions
            ctrl: 0x999,
            cmd_req: WriteOnlyRegister::new(0),
            reseed_interval: 0xffffffff,
            reseed_counter_2: ReadOnlyRegister::new(0),
            sw_cmd_sts: ReadOnlyRegister::new(0b110), // cmd_rdy=1, cmd_ack=1, cmd_sts=0
            genbits_vld: ReadOnlyRegister::new(0b01),
            genbits: ReadOnlyRegister::new(0),
            main_sm_state_csrng: ReadOnlyRegister::new(0x4e), // MainSmIdle (csrng_pkg.sv)
            err_code: ReadOnlyRegister::new(0),
            me_regwen: 1, // Reset value: enabled (writable)
            sw_regupd: 1, // Reset value: enabled (writable)
            module_enable: 0x9,
            conf: 0x999999,
            entropy_control: 0x99,
            health_test_windows: 0x1800200,
            repcnt_threshold: 0xffff,
            repcnts_threshold: 0xffff,
            adaptp_hi_threshold: 0xffff,
            adaptp_lo_threshold: 0,
            adaptps_threshold: 0xffff,
            alert_threshold: 0xfffd0002,
            alert_summary_fail_counts: ReadOnlyRegister::new(0),
            alert_fail_counts: ReadOnlyRegister::new(0),
            main_sm_state: ReadOnlyRegister::new(0x2c), // StartupHTStart, entropy_src_main_sm_pkg.sv

            cmd_req_state: CmdReqState::NewCommand,
            seed: vec![],
            update: vec![],
            ctr_drbg: CtrDrbg::new(),
            words: Words::default(),
            health_tester: HealthTester::new(itrng_nibbles),
            boot_instantiate_complete: false,
            secondary: SecondaryEntropySource::default(),
            dual_clock: None,
            combiner: None,
            zeroize_epoch: 0,
            last_sample: 0,
            samples: Vec::new(),
            window_start_failures: 0,
            consecutive_failures: 0,
            startup_ready: false,
            ready_seed: None,
            pending_dual: None,
            latched: [None; 2],
            output_fips: false,
        }
    }

    pub(crate) fn enable_dual(
        &mut self,
        secondary: SecondaryEntropySource,
        clock: Rc<Clock>,
        combiner: Rc<CombinerLink>,
    ) {
        self.secondary = secondary;
        self.dual_clock = Some(clock);
        self.combiner = Some(combiner);
    }

    fn read_csrng_state(&mut self, _: RvSize) -> Result<RvData, BusError> {
        self.progress_dual_request();
        Ok(match self.pending_dual {
            Some(false) => 0xc1, // MainSmInstantPrep
            Some(true) => 0xdd,  // MainSmReseedPrep
            None => 0x4e,        // MainSmIdle
        })
    }

    fn read_command_status(&mut self, _: RvSize) -> Result<RvData, BusError> {
        self.progress_dual_request();
        Ok(self.sw_cmd_sts.reg.get())
    }

    fn cmd_req_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // Since the CMD_REQ register can be used to initiate new commands or
        // supply words to an existing command, we need to track which "state"
        // we're in for this register and branch accordingly.
        self.progress_dual_request();
        if self.pending_dual.is_some() {
            return Ok(());
        }
        match self.cmd_req_state {
            CmdReqState::NewCommand => self.process_new_cmd(data),

            CmdReqState::SeedWords { num_words } => {
                self.seed.push(data);
                if self.seed.len() == num_words {
                    self.ctr_drbg.instantiate(Instantiate::Words(&self.seed));
                    self.seed.clear();
                    self.cmd_req_state = CmdReqState::NewCommand;
                }
            }

            CmdReqState::ReseedWords { num_words } => {
                self.seed.push(data);
                if self.seed.len() == num_words {
                    self.ctr_drbg.reseed(Instantiate::Words(&self.seed));
                    self.seed.clear();
                    self.cmd_req_state = CmdReqState::NewCommand;
                }
            }

            CmdReqState::UpdateWords { num_words } => {
                self.update.push(data);
                if self.update.len() == num_words {
                    let seed32: [u32; SEED_LEN_BYTES / 4] =
                        self.update.as_slice().try_into().unwrap();
                    let seed = bytes_from_words_be(&seed32);
                    self.ctr_drbg.update(seed);
                    self.update.clear();
                    self.cmd_req_state = CmdReqState::NewCommand;
                }
            }
        }
        Ok(())
    }

    /// CTRL write handler. Disabling CSRNG clears the DRBG instance and any
    /// partially received command, as in the RTL.
    fn ctrl_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        const ENABLE_MASK: u32 = 0xf;
        if data & ENABLE_MASK != MultiBitBool::True as u32 {
            self.ctr_drbg = CtrDrbg::new();
            self.ctr_drbg.set_reseed_interval(self.reseed_interval);
            self.words = Words::default();
            self.cmd_req_state = CmdReqState::NewCommand;
            self.seed.clear();
            self.update.clear();
            self.output_fips = false;
        }
        self.ctrl = data;
        Ok(())
    }

    fn reseed_interval_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        if self.sw_regupd == 0 {
            return Ok(());
        }
        self.reseed_interval = data;

        self.ctr_drbg.set_reseed_interval(data);
        Ok(())
    }

    /// Read handler for RESEED_COUNTER_2 (SW app instance; NumApps=3).
    fn reseed_counter_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        Ok(self.ctr_drbg.reseed_counter())
    }

    fn genbits_vld_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        if self.words.is_empty() {
            // Check if the CTR_DRBG has any bits for us.
            if let Some(block) = self.ctr_drbg.pop_block() {
                self.words = Words::new(block);
                Ok(1 | (u32::from(self.output_fips) << 1))
            } else {
                Ok(0b00)
            }
        } else {
            Ok(1 | (u32::from(self.output_fips) << 1))
        }
    }

    fn genbits_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        Ok(self.words.next().unwrap_or(0xCAFE_F00D))
    }

    /// ME_REGWEN write handler - W0C (write-0-clear) behavior.
    /// When cleared to 0, MODULE_ENABLE becomes read-only.
    fn me_regwen_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // W0C: writing 0 clears the bit, writing 1 has no effect
        // Once cleared, cannot be set back to 1 (until reset)
        if data & 1 == 0 {
            self.me_regwen = 0;
        }
        Ok(())
    }

    /// SW_REGUPD write handler - W0C (write-0-clear) behavior.
    /// When cleared to 0, configuration registers become read-only.
    fn sw_regupd_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // W0C: writing 0 clears the bit, writing 1 has no effect
        // Once cleared, cannot be set back to 1 (until reset)
        if data & 1 == 0 {
            self.sw_regupd = 0;
        }
        Ok(())
    }

    fn module_enable_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // If ME_REGWEN is cleared, MODULE_ENABLE is read-only
        if self.me_regwen == 0 {
            return Ok(()); // Silently ignore writes when locked
        }
        if let Some(clock) = &self.dual_clock {
            if self.module_enable != data {
                self.last_sample = clock.now();
                self.health_tester.clear_progress();
                self.samples.clear();
                self.window_start_failures = 0;
                self.consecutive_failures = 0;
                self.ready_seed = None;
                self.startup_ready = false;
                self.module_enable = data;
            }
            return Ok(());
        }
        self.module_enable = data;

        if data == MultiBitBool::False as u32 {
            return Ok(());
        }

        if ConfReadVal::from(self.conf).fips_enable() == MultiBitBool::False as u32 {
            unimplemented!("emulation of non-FIPS mode");
        }

        assert!(
            self.health_tester.test_startup_windows(),
            "iTRNG iterator ended during startup"
        );

        Ok(())
    }

    fn conf_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // CONF is protected by SW_REGUPD - if cleared, CONF is read-only
        if self.sw_regupd == 0 {
            return Ok(()); // Silently ignore writes when locked
        }
        self.conf = data;

        let conf = ConfReadVal::from(self.conf);
        let threshold_scope = conf.threshold_scope() == MultiBitBool::True as u32;
        self.health_tester
            .adaptp
            .set_threshold_scope(threshold_scope);

        // Single-bit (single-lane) mode: entropy_src samples only the RNG lane
        // selected by RNG_BIT_SEL and runs the health tests on that one bit.
        let rng_bit_enable = conf.rng_bit_enable() == MultiBitBool::True as u32;
        let rng_bit_sel = conf.rng_bit_sel() as usize;
        self.health_tester
            .set_rng_bit_mode(rng_bit_enable, rng_bit_sel);

        Ok(())
    }

    fn entropy_control_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        if self.sw_regupd != 0 {
            self.entropy_control = data & 0xff;
        }
        Ok(())
    }

    /// HEALTH_TEST_WINDOWS write handler.
    /// Sets the FIPS health-test window size in samples per RNG lane.
    /// Protected by SW_REGUPD just like the other configuration registers.
    fn health_test_windows_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        if self.sw_regupd == 0 {
            return Ok(());
        }
        self.health_test_windows = data;

        let fips_window = HealthTestWindowsReadVal::from(data).fips_window() as usize;
        self.health_tester.set_window_size_samples(fips_window);
        Ok(())
    }

    fn repcnt_threshold_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        if self.sw_regupd != 0 {
            self.repcnt_threshold = data & 0xffff;
            self.health_tester
                .repcnt
                .set_threshold(RepcntThresholdReadVal::from(data));
        }
        Ok(())
    }

    fn repcnts_threshold_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        if self.sw_regupd != 0 {
            self.repcnts_threshold = data & 0xffff;
            self.health_tester
                .repcnts
                .set_threshold(RepcntsThresholdReadVal::from(data));
        }
        Ok(())
    }

    fn adaptp_hi_threshold_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        if self.sw_regupd != 0 {
            self.adaptp_hi_threshold = data & 0xffff;
            self.health_tester
                .adaptp
                .set_hi_threshold(AdaptpHiThresholdReadVal::from(data));
        }
        Ok(())
    }

    fn adaptp_lo_threshold_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        if self.sw_regupd != 0 {
            self.adaptp_lo_threshold = data & 0xffff;
            self.health_tester
                .adaptp
                .set_lo_threshold(AdaptpLoThresholdReadVal::from(data));
        }
        Ok(())
    }

    fn adaptps_threshold_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        if self.sw_regupd != 0 {
            self.adaptps_threshold = data & 0xffff;
            self.health_tester.symbol_adaptive_threshold = self.adaptps_threshold;
        }
        Ok(())
    }

    fn alert_summary_fail_counts_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        let failures = self.health_tester.failures();
        self.alert_summary_fail_counts = ReadOnlyRegister::new(failures);
        Ok(failures)
    }

    fn alert_fail_counts_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        // Don't have a `AlertFailCountsWriteVal` from caliptra_ureg, so let's pack counts manually.
        // Bit positions from entropy_src register definitions:
        // - repcnt_fail_count: bits [3:0]
        // - repcnts_fail_count: bits [7:4]
        // - adaptp_hi_fail_count: bits [11:8]
        // - adaptp_lo_fail_count: bits [15:12]
        let repcnt = self.health_tester.repcnt.failures().min(0xf) & 0xf;
        let repcnts = self.health_tester.repcnts.failures().min(0xf) & 0xf;
        let adapt_hi = self.health_tester.adaptp.hi_failures().min(0xf) & 0xf;
        let adapt_lo = self.health_tester.adaptp.lo_failures().min(0xf) & 0xf;
        let adaptps = self.health_tester.symbol_adaptive_failures.min(0xf);
        let fail_counts =
            (adaptps << 16) | (adapt_lo << 12) | (adapt_hi << 8) | (repcnts << 4) | repcnt;

        self.alert_fail_counts = ReadOnlyRegister::new(fail_counts);
        Ok(fail_counts)
    }

    fn main_sm_state_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        // https://opentitan.org/earlgrey_1.0.0/book/hw/ip/entropy_src/doc/theory_of_operation.html#main-state-machine-diagram
        // https://github.com/chipsalliance/caliptra-rtl/blob/main/src/entropy_src/rtl/entropy_src_main_sm_pkg.sv
        // https://github.com/chipsalliance/caliptra-rtl/blob/main/src/entropy_src/rtl/entropy_src_core.sv
        //
        // From entropy_src_core.sv (lines 2185-2191):
        //   assign alert_threshold = reg2hw.alert_threshold.alert_threshold.q;
        //   assign any_fail_count_q >= alert_threshold -> alert_threshold_fail
        //
        // The state machine only transitions to AlertHang when alert_threshold_fail is true,
        // meaning the total failure count must meet or exceed the configured alert threshold.
        const ALERT_HANG: u32 = 0x1fb;
        const CONT_HT_RUNNING: u32 = 0x1a2;

        // In real hardware, entropy_src continuously pulls entropy from the TRNG and runs
        // health tests. The state machine state reflects the ongoing health test results.
        // To simulate this behavior, we consume a health test window worth of entropy
        // when the state is read, running it through the health testers.
        if self.dual_clock.is_some() {
            self.progress_source();
        } else {
            self.simulate_continuous_health_testing();
        }

        // Extract alert_threshold from the alert_threshold register (bits [15:0])
        let alert_threshold = self.alert_threshold & 0xffff;
        let failures = if self.dual_clock.is_some() {
            self.consecutive_failures
        } else {
            self.health_tester.failures()
        };

        let state = if failures >= alert_threshold {
            ALERT_HANG
        } else if self.dual_clock.is_some() && !self.startup_ready {
            0x2c // StartupHTStart: not enough input to finish startup.
        } else {
            CONT_HT_RUNNING
        };

        self.main_sm_state = ReadOnlyRegister::new(state);
        Ok(state)
    }

    /// Simulate the continuous health testing that happens in real hardware.
    /// In the RTL, entropy_src continuously pulls entropy from the TRNG and runs health tests.
    /// We simulate this by consuming a health test window worth of entropy when state is queried.
    ///
    /// This is only done AFTER boot/instantiate is complete to avoid consuming entropy that's
    /// needed for seed conditioning in tests with limited entropy.
    fn simulate_continuous_health_testing(&mut self) {
        // Only run continuous testing if:
        // 1. The module is enabled
        // 2. Boot/instantiate has completed (so we don't consume entropy needed for seed conditioning)
        if self.module_enable != MultiBitBool::True as u32 {
            return;
        }
        if !self.boot_instantiate_complete {
            return;
        }

        let num_nibbles = self.health_tester.nibbles_per_window();

        // Consume a window's worth of entropy through the health testers
        for _ in 0..num_nibbles {
            if let Some(nibble) = self.health_tester.next() {
                // The nibble was already fed through health testers in HealthTester::next()
                let _ = nibble;
            } else {
                // No more entropy available
                break;
            }
        }
    }

    fn reset_source_config(&mut self) {
        let mut health = std::mem::replace(
            &mut self.health_tester,
            HealthTester::new(Box::new(std::iter::empty())),
        );
        health.reset();
        let clock = self.dual_clock.clone();
        let secondary = self.secondary.clone();
        let combiner = self.combiner.clone();
        *self = Self::new(Box::new(std::iter::empty()));
        self.health_tester = health;
        self.dual_clock = clock;
        self.secondary = secondary;
        self.combiner = combiner;
    }

    fn warm_reset(&mut self) {
        // CSRNG and entropy_src are in the non-core reset domain.
        self.reset_source_config();
    }

    fn progress_source(&mut self) {
        let now = self.dual_clock.as_ref().unwrap().now();
        let elapsed = now.saturating_sub(self.last_sample);
        self.last_sample = now;
        if self.module_enable != MultiBitBool::True as u32 || self.ready_seed.is_some() {
            return;
        }
        let window = self.health_tester.nibbles_per_window();
        let needed = window * if self.startup_ready { 1 } else { 2 };
        for _ in 0..elapsed {
            if self.consecutive_failures >= self.alert_threshold & 0xffff {
                break;
            }
            let Some(symbol) = self.health_tester.sample() else {
                continue;
            };
            self.samples.push(symbol);
            if self.samples.len().is_multiple_of(window) {
                let failures = self.health_tester.failures();
                let failed = failures != self.window_start_failures;
                self.window_start_failures = failures;
                if failed {
                    self.consecutive_failures += 1;
                    self.samples.clear();
                    continue;
                }
                self.consecutive_failures = 0;
            }
            if self.samples.len() == needed {
                // Pack symbols least-significant first, matching the conditioner input.
                let bits = self.health_tester.bits_per_symbol();
                let mut bytes = vec![0; (needed * bits).div_ceil(8)];
                for (i, symbol) in self.samples.drain(..).enumerate() {
                    bytes[i * bits / 8] |= symbol << (i * bits % 8);
                }
                self.ready_seed = Some(Sha3_384::digest(bytes).into());
                self.startup_ready = true;
                break;
            }
        }
    }

    fn take_source_seed(&mut self) -> Option<(Seed, bool)> {
        self.progress_source();
        self.ready_seed
            .take()
            .map(|seed| (seed, ConfReadVal::from(self.conf).fips_flag() == 6))
    }

    fn progress_dual_request(&mut self) {
        let (Some(reseed), Some(link)) = (self.pending_dual, self.combiner.clone()) else {
            return;
        };
        if self.zeroize_epoch != link.zeroize_epoch.get() {
            // RTL clears in-flight seed storage, but retains the request while waiting.
            self.zeroize_epoch = link.zeroize_epoch.get();
            self.latched = [None; 2];
        }
        if link.has_error() {
            return;
        }
        if self.latched[0].is_none() {
            self.latched[0] = self.take_source_seed();
        }
        if self.latched[1].is_none() {
            self.latched[1] = self
                .secondary
                .0
                .as_ref()
                .unwrap()
                .borrow_mut()
                .take_source_seed();
        }
        let [Some((es0, fips0)), Some((es1, fips1))] = self.latched else {
            return;
        };
        let mut hash = Sha3_384::new();
        hash.update(es0);
        hash.update(es1);
        let mut seed: Seed = hash.finalize().into();
        seed.reverse(); // CSRNG model expects big-endian seed bytes.
        self.output_fips = link.output_fips(fips0, fips1);
        if reseed {
            self.ctr_drbg.reseed(Instantiate::Bytes(&seed));
        } else {
            self.ctr_drbg.instantiate(Instantiate::Bytes(&seed));
        }
        self.latched = [None; 2];
        self.pending_dual = None;
        self.sw_cmd_sts = ReadOnlyRegister::new(0b110);
    }

    fn request_dual_seed(&mut self, reseed: bool) {
        self.zeroize_epoch = self.combiner.as_ref().unwrap().zeroize_epoch.get();
        self.pending_dual = Some(reseed);
        self.sw_cmd_sts = ReadOnlyRegister::new(0b010);
        self.progress_dual_request();
    }

    fn process_new_cmd(&mut self, data: RvData) {
        const INSTANTIATE: u32 = 1;
        const RESEED: u32 = 2;
        const GENERATE: u32 = 3;
        const UPDATE: u32 = 4;
        const UNINSTANTIATE: u32 = 5;

        let acmd = data & 0xf;
        let clen = (data >> 4) & 0xf;
        let flag0 = (data >> 8) & 0xf;
        let glen = (data >> 12) & 0x1fff;

        match acmd {
            INSTANTIATE => {
                const FALSE: u32 = MultiBitBool::False as u32;
                const TRUE: u32 = MultiBitBool::True as u32;

                // https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#command-description
                match [flag0, clen] {
                    [FALSE, 0] => {
                        // Seed from entropy_src.
                        if self.combiner.is_some() {
                            self.request_dual_seed(false);
                            return;
                        }
                        let seed = self
                            .get_conditioned_seed()
                            .expect("iTRNG iterator ended while conditioning");
                        self.ctr_drbg.instantiate(Instantiate::Bytes(&seed));
                        // Mark boot as complete - continuous health testing can now run
                        self.boot_instantiate_complete = true;
                    }

                    [FALSE, _] => unimplemented!("seed: entropy_src XOR constant"),

                    [TRUE, 0] => {
                        self.output_fips = false;
                        // Zero seed.
                        self.ctr_drbg.instantiate(Instantiate::default());
                    }

                    [TRUE, _] => {
                        self.output_fips = false;
                        self.cmd_req_state = CmdReqState::SeedWords {
                            num_words: clen as usize,
                        };
                    }

                    _ => unreachable!("invalid INSTANTIATE state: flag0={flag0}, clen={clen}"),
                }
            }

            RESEED => {
                const FALSE: u32 = MultiBitBool::False as u32;
                const TRUE: u32 = MultiBitBool::True as u32;

                // Mirror INSTANTIATE flag handling for RESEED.
                match [flag0, clen] {
                    [FALSE, 0] => {
                        if self.combiner.is_some() {
                            self.request_dual_seed(true);
                            return;
                        }
                        let seed = self
                            .get_conditioned_seed()
                            .expect("iTRNG iterator ended while reseeding");
                        self.ctr_drbg.reseed(Instantiate::Bytes(&seed));
                    }

                    [FALSE, _] => unimplemented!("reseed: entropy_src XOR constant"),

                    [TRUE, 0] => {
                        self.ctr_drbg.reseed(Instantiate::default());
                    }

                    [TRUE, _] => {
                        self.cmd_req_state = CmdReqState::ReseedWords {
                            num_words: clen as usize,
                        };
                    }

                    _ => unreachable!("invalid RESEED state: flag0={flag0}, clen={clen}"),
                }
            }

            GENERATE => {
                self.ctr_drbg.generate(glen as usize);
            }

            UNINSTANTIATE => {
                self.output_fips = false;
                self.ctr_drbg.uninstantiate();
            }

            UPDATE => {
                self.cmd_req_state = CmdReqState::UpdateWords {
                    num_words: SEED_LEN_BYTES / 4,
                };
            }

            _ => {
                unimplemented!("CSRNG cmd: {acmd}");
            }
        }
    }

    fn get_conditioned_seed(&mut self) -> Option<Seed> {
        // Replicate the logic in caliptra-rtl/src/entropy_src/rtl/entropy_src_core.sv.
        const NUM_TEST_WINDOWS: usize = 2;
        const BITS_PER_BLOCK: usize = 8 * mem::size_of::<u64>();

        let window_size_bits = self.health_tester.window_size_bits();
        let num_blocks = NUM_TEST_WINDOWS * window_size_bits / BITS_PER_BLOCK;
        let bits_per_symbol = self.health_tester.bits_per_symbol();

        let mut hasher = Sha3_384::new();

        for _ in 0..num_blocks {
            // Update the hasher in 64-bit packed entropy blocks.
            let mut packed_entropy = 0u64;
            for i in 0..BITS_PER_BLOCK / bits_per_symbol {
                let symbol = self.health_tester.next()?;
                packed_entropy |= u64::from(symbol) << (i * bits_per_symbol);
            }
            hasher.update(packed_entropy.to_le_bytes());
        }

        let mut digest = hasher.finalize();
        digest.as_mut_slice().reverse();
        Some(digest.into())
    }
}

#[derive(Default)]
struct Words {
    block: Block,
    cursor: usize,
}

impl Words {
    pub fn new(block: Block) -> Self {
        Self {
            block,
            cursor: block.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Iterator for Words {
    type Item = Word;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == 0 {
            None
        } else {
            // We have to return, in reverse order, the words within this block.
            // Reverse order because of https://opentitan.org/book/hw/ip/csrng/doc/programmers_guide.html#endianness-and-known-answer-tests
            let start = self.cursor - WORD_SIZE_BYTES;
            let end = self.cursor;

            let word = &self.block[start..end];
            let word = word.try_into().expect("byte slice to 4-byte array");
            let word = u32::from_be_bytes(word);

            self.cursor = start;
            Some(word)
        }
    }
}

impl ExactSizeIterator for Words {
    fn len(&self) -> usize {
        self.cursor / WORD_SIZE_BYTES
    }
}

enum CmdReqState {
    NewCommand,
    SeedWords { num_words: usize },
    ReseedWords { num_words: usize },
    UpdateWords { num_words: usize },
}

#[repr(u32)]
enum MultiBitBool {
    False = 9,
    True = 6,
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_registers::entropy_src::regs::{AlertFailCountsReadVal, ConfWriteVal};

    const OFFSET_CONF: caliptra_emu_types::RvAddr = 0x1024;
    const OFFSET_MODULE_ENABLE: caliptra_emu_types::RvAddr = 0x1020;

    fn make_itrng_nibbles() -> Box<dyn Iterator<Item = u8>> {
        Box::new(std::iter::repeat_with(|| 0xAu8))
    }

    #[test]
    fn test_entropy_health_register_offsets_and_failure_fields() {
        let mut csrng = Csrng::new(make_itrng_nibbles());
        for (offset, value) in [(0x1030, 8), (0x1038, 2), (0x103c, 3)] {
            csrng.write(RvSize::Word, offset, value).unwrap();
        }
        csrng.write(RvSize::Word, OFFSET_CONF, 0x999996).unwrap();
        csrng
            .write(
                RvSize::Word,
                OFFSET_MODULE_ENABLE,
                MultiBitBool::True as u32,
            )
            .unwrap();

        let failures = AlertFailCountsReadVal::from(csrng.read(RvSize::Word, 0x1098).unwrap());
        assert_eq!(failures.repcnt_fail_count(), 15);
        assert_eq!(failures.repcnts_fail_count(), 14);
        assert_eq!(failures.adaptp_hi_fail_count(), 0);
        assert_eq!(failures.adaptp_lo_fail_count(), 0);
        assert_eq!(failures.markov_lo_fail_count(), 0);
        assert_eq!(csrng.read(RvSize::Word, 0x1094).unwrap(), 74);
        assert_eq!(csrng.read(RvSize::Word, 0x10d0).unwrap(), 0x1fb);
    }

    #[test]
    fn test_single_bit_seed_uses_selected_lane_and_configured_sample_count() {
        let mut csrng = Csrng::new(Box::new(std::iter::repeat_n(0b1011, 128)));
        let conf = ConfWriteVal::from(0x999999)
            .fips_enable(MultiBitBool::True as u32)
            .rng_bit_enable(MultiBitBool::True as u32)
            .rng_bit_sel(2);
        csrng
            .write(RvSize::Word, OFFSET_CONF, u32::from(conf))
            .unwrap();
        csrng.write(RvSize::Word, 0x1030, 64).unwrap();
        csrng
            .write(
                RvSize::Word,
                OFFSET_MODULE_ENABLE,
                MultiBitBool::True as u32,
            )
            .unwrap();

        let mut expected = Sha3_384::digest([0u8; 16]);
        expected.reverse();
        assert_eq!(
            csrng.get_conditioned_seed().unwrap().as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn test_warm_reset_sets_module_enable_to_false() {
        let mut csrng = Csrng::new(make_itrng_nibbles());

        // Verify initial state: module_enable should be 0x9 (MultiBitBool::False)
        let initial = csrng.read(RvSize::Word, OFFSET_MODULE_ENABLE).unwrap();
        assert_eq!(initial, MultiBitBool::False as u32);

        // Configure FIPS mode (fips_enable in bits [3:0] = 6 for TRUE)
        // Use the default conf value but with fips_enable set to TRUE
        let conf_with_fips = 0x999996; // Replace low nibble 9 with 6
        csrng
            .write(RvSize::Word, OFFSET_CONF, conf_with_fips)
            .unwrap();

        // Enable the module by writing MultiBitBool::True
        csrng
            .write(
                RvSize::Word,
                OFFSET_MODULE_ENABLE,
                MultiBitBool::True as u32,
            )
            .unwrap();

        // Verify module is enabled
        let enabled = csrng.read(RvSize::Word, OFFSET_MODULE_ENABLE).unwrap();
        assert_eq!(enabled, MultiBitBool::True as u32);

        // Perform warm reset
        csrng.warm_reset();

        // After warm reset, module_enable should be back to 0x9 (MultiBitBool::False)
        let after_reset = csrng.read(RvSize::Word, OFFSET_MODULE_ENABLE).unwrap();
        assert_eq!(
            after_reset,
            MultiBitBool::False as u32,
            "After warm reset, module_enable should be MultiBitBool::False (0x9)"
        );
    }
}

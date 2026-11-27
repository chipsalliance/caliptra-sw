// Licensed under the Apache-2.0 license

use crate::csrng::Seed;
use crate::helpers::MultiBitBool;
use caliptra_emu_bus::{Bus, BusError, Clock, ReadOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_registers::entropy_src::regs::{
    AdaptpHiThresholdReadVal, AdaptpLoThresholdReadVal, ConfReadVal, HealthTestWindowsReadVal,
    RepcntThresholdReadVal, RepcntsThresholdReadVal,
};
use sha3::{Digest, Sha3_384};
use std::{cell::RefCell, mem, rc::Rc};

mod health_test;
use health_test::HealthTester;

const BITS_PER_NIBBLE: usize = 4;
const MODULE_ENABLE: RvAddr = 0x20;
const MAIN_SM_STATE: RvAddr = 0xd0;

pub(crate) type SharedEntropySrc = Rc<RefCell<EntropySrc>>;

/// The ES1 slot faults when the second source isn't wired up.
#[derive(Default)]
pub(crate) struct OptionalEntropySrc(pub(crate) Option<SharedEntropySrc>);

impl Bus for OptionalEntropySrc {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.0
            .as_ref()
            .ok_or(BusError::LoadAccessFault)?
            .borrow_mut()
            .read(size, addr)
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.0
            .as_ref()
            .ok_or(BusError::StoreAccessFault)?
            .borrow_mut()
            .write(size, addr, val)
    }

    fn warm_reset(&mut self) {
        if let Some(source) = &self.0 {
            source.borrow_mut().warm_reset();
        }
    }
}

/// Raw conditioner output, in the byte order fed to the entropy combiner.
#[derive(Clone, Copy)]
pub(crate) struct ConditionedSeed {
    pub(crate) bytes: Seed,
    pub(crate) fips: bool,
}

impl ConditionedSeed {
    pub(crate) fn into_csrng_bytes(self) -> Seed {
        let mut bytes = self.bytes;
        bytes.reverse();
        bytes
    }
}

enum SamplingMode {
    /// Preserve legacy single-source consumption: test two windows on enable,
    /// reuse those samples for the first seed, and only run continuous health
    /// tests on state reads after CSRNG instantiates. Clocked sampling would
    /// change the nibble order seen by deterministic DRBG tests.
    Synchronous,
    /// In dual-source mode each source can accumulate or stall independently
    /// while CSRNG waits for both inputs to the combiner.
    Clocked(Rc<Clock>),
}

pub(crate) struct EntropySrc {
    nibbles: Box<dyn Iterator<Item = u8>>,
    sampling: SamplingMode,
    state: EntropySrcState,
}

#[derive(Default)]
struct ClockedProgress {
    last_sample_cycle: u64,
    conditioning_symbols: Vec<u8>,
    previous_window_failures: u32,
    consecutive_failed_windows: u32,
    startup_complete: bool,
    conditioned_seed: Option<Seed>,
}

#[derive(Bus)]
struct EntropySrcState {
    // ME_REGWEN: Module enable register write enable (W0C - write-0-clear)
    // When cleared (false), MODULE_ENABLE becomes read-only
    #[register(offset = 0x10, write_fn = me_regwen_write)]
    me_regwen: u32,

    // SW_REGUPD: Software update enable (W0C - write-0-clear)
    // When cleared (false), configuration registers become read-only
    #[register(offset = 0x14, write_fn = sw_regupd_write)]
    sw_regupd: u32,

    #[register(offset = 0x20)]
    module_enable: u32,

    #[register(offset = 0x24, write_fn = conf_write)]
    conf: u32,

    // ES_TYPE (conditioning bypass) is stored but not modeled.
    #[register(offset = 0x28, write_fn = entropy_control_write)]
    entropy_control: u32,

    #[register(offset = 0x30, write_fn = health_test_windows_write)]
    health_test_windows: u32,

    #[register(offset = 0x38, write_fn = repcnt_threshold_write)]
    repcnt_threshold: u32,

    #[register(offset = 0x3c, write_fn = repcnts_threshold_write)]
    repcnts_threshold: u32,

    #[register(offset = 0x40, write_fn = adaptp_hi_threshold_write)]
    adaptp_hi_threshold: u32,

    #[register(offset = 0x44, write_fn = adaptp_lo_threshold_write)]
    adaptp_lo_threshold: u32,

    #[register(offset = 0x48, write_fn = adaptps_threshold_write)]
    adaptps_threshold: u32,

    #[register(offset = 0x90)]
    alert_threshold: u32, // TODO: implement this

    #[register(offset = 0x94, read_fn = alert_summary_fail_counts_read)]
    alert_summary_fail_counts: ReadOnlyRegister<u32>,

    #[register(offset = 0x98, read_fn = alert_fail_counts_read)]
    alert_fail_counts: ReadOnlyRegister<u32>,

    health_tester: HealthTester,
    boot_instantiate_complete: bool,
    clocked: ClockedProgress,
}

impl Default for EntropySrcState {
    fn default() -> Self {
        Self {
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
            health_tester: HealthTester::new(),
            boot_instantiate_complete: false,
            clocked: ClockedProgress::default(),
        }
    }
}

impl EntropySrcState {
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
}

impl Bus for EntropySrc {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match addr {
            MAIN_SM_STATE => Ok(self.main_sm_state_read()),
            _ => self.state.read(size, addr),
        }
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            MODULE_ENABLE => self.module_enable_write(val),
            _ => self.state.write(size, addr, val),
        }
    }

    fn warm_reset(&mut self) {
        // Reset configuration and health tests, not the input iterator or clock.
        self.state = EntropySrcState::default();
    }
}

impl EntropySrc {
    pub(crate) fn new(nibbles: Box<dyn Iterator<Item = u8>>) -> Self {
        Self {
            nibbles,
            sampling: SamplingMode::Synchronous,
            state: EntropySrcState::default(),
        }
    }

    pub(crate) fn use_clocked_sampling(&mut self, clock: Rc<Clock>) {
        self.sampling = SamplingMode::Clocked(clock);
    }

    pub(crate) fn configuration_locked(&self) -> bool {
        self.state.sw_regupd == 0
    }

    pub(crate) fn complete_boot_instantiate(&mut self) {
        self.state.boot_instantiate_complete = true;
    }

    fn module_enable_write(&mut self, data: RvData) -> Result<(), BusError> {
        // If ME_REGWEN is cleared, MODULE_ENABLE is read-only.
        if self.state.me_regwen == 0 {
            return Ok(());
        }
        match &self.sampling {
            SamplingMode::Clocked(clock) => {
                if self.state.module_enable != data {
                    self.state.clocked = ClockedProgress {
                        last_sample_cycle: clock.now(),
                        ..Default::default()
                    };
                    self.state.health_tester.clear_progress();
                    self.state.module_enable = data;
                }
            }
            SamplingMode::Synchronous => {
                self.state.module_enable = data;
                if data != MultiBitBool::False as u32 {
                    if ConfReadVal::from(self.state.conf).fips_enable()
                        == MultiBitBool::False as u32
                    {
                        unimplemented!("emulation of non-FIPS mode");
                    }
                    assert!(
                        self.state
                            .health_tester
                            .test_startup_windows(self.nibbles.as_mut()),
                        "iTRNG iterator ended during startup"
                    );
                }
            }
        }
        Ok(())
    }

    fn main_sm_state_read(&mut self) -> RvData {
        // The RTL transitions to AlertHang when the failure count reaches the
        // configured alert threshold (entropy_src_core.sv).
        const ALERT_HANG: u32 = 0x1fb;
        const STARTUP_HT_START: u32 = 0x2c;
        const CONT_HT_RUNNING: u32 = 0x1a2;

        let (failures, startup_complete) = match &self.sampling {
            SamplingMode::Synchronous => {
                self.simulate_continuous_health_testing();
                (self.state.health_tester.failures(), true)
            }
            SamplingMode::Clocked(clock) => {
                self.progress_clocked(clock.now());
                (
                    self.state.clocked.consecutive_failed_windows,
                    self.state.clocked.startup_complete,
                )
            }
        };

        let alert_threshold = self.state.alert_threshold & 0xffff;
        if failures >= alert_threshold {
            ALERT_HANG
        } else if !startup_complete {
            STARTUP_HT_START
        } else {
            CONT_HT_RUNNING
        }
    }

    /// The legacy path models continuous health testing by consuming one test
    /// window per state read, but only after the boot instantiate has used its seed.
    fn simulate_continuous_health_testing(&mut self) {
        if self.state.module_enable != MultiBitBool::True as u32
            || !self.state.boot_instantiate_complete
        {
            return;
        }
        for _ in 0..self.state.health_tester.nibbles_per_window() {
            if self
                .state
                .health_tester
                .next(self.nibbles.as_mut())
                .is_none()
            {
                break;
            }
        }
    }

    pub(crate) fn take_seed(&mut self) -> Option<ConditionedSeed> {
        match &self.sampling {
            SamplingMode::Synchronous => Some(ConditionedSeed {
                bytes: self.condition_synchronously()?,
                fips: false,
            }),
            SamplingMode::Clocked(clock) => {
                self.progress_clocked(clock.now());
                Some(ConditionedSeed {
                    bytes: self.state.clocked.conditioned_seed.take()?,
                    fips: ConfReadVal::from(self.state.conf).fips_flag()
                        == MultiBitBool::True as u32,
                })
            }
        }
    }

    fn progress_clocked(&mut self, now: u64) {
        let progress = &mut self.state.clocked;
        let elapsed = now.saturating_sub(progress.last_sample_cycle);
        progress.last_sample_cycle = now;
        if self.state.module_enable != MultiBitBool::True as u32
            || progress.conditioned_seed.is_some()
        {
            return;
        }
        let window = self.state.health_tester.nibbles_per_window();
        let needed = window * if progress.startup_complete { 1 } else { 2 };
        for _ in 0..elapsed {
            if progress.consecutive_failed_windows >= self.state.alert_threshold & 0xffff {
                break;
            }
            let Some(symbol) = self.state.health_tester.sample(self.nibbles.as_mut()) else {
                continue;
            };
            progress.conditioning_symbols.push(symbol);
            if progress.conditioning_symbols.len().is_multiple_of(window) {
                let failures = self.state.health_tester.failures();
                let failed = failures != progress.previous_window_failures;
                progress.previous_window_failures = failures;
                if failed {
                    progress.consecutive_failed_windows += 1;
                    progress.conditioning_symbols.clear();
                    continue;
                }
                progress.consecutive_failed_windows = 0;
            }
            if progress.conditioning_symbols.len() == needed {
                // Pack symbols least-significant first, matching the conditioner input.
                let bits = self.state.health_tester.bits_per_symbol();
                let mut bytes = vec![0; (needed * bits).div_ceil(8)];
                for (i, symbol) in progress.conditioning_symbols.drain(..).enumerate() {
                    bytes[i * bits / 8] |= symbol << (i * bits % 8);
                }
                progress.conditioned_seed = Some(Sha3_384::digest(bytes).into());
                progress.startup_complete = true;
                break;
            }
        }
    }

    fn condition_synchronously(&mut self) -> Option<Seed> {
        // Replicate the logic in caliptra-rtl/src/entropy_src/rtl/entropy_src_core.sv.
        const NUM_TEST_WINDOWS: usize = 2;
        const BITS_PER_BLOCK: usize = 8 * mem::size_of::<u64>();

        let window_size_bits = self.state.health_tester.window_size_bits();
        let num_blocks = NUM_TEST_WINDOWS * window_size_bits / BITS_PER_BLOCK;
        let bits_per_symbol = self.state.health_tester.bits_per_symbol();

        let mut hasher = Sha3_384::new();

        for _ in 0..num_blocks {
            // Update the hasher in 64-bit packed entropy blocks.
            let mut packed_entropy = 0u64;
            for i in 0..BITS_PER_BLOCK / bits_per_symbol {
                let symbol = self.state.health_tester.next(self.nibbles.as_mut())?;
                packed_entropy |= u64::from(symbol) << (i * bits_per_symbol);
            }
            hasher.update(packed_entropy.to_le_bytes());
        }

        Some(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_registers::entropy_src::regs::{AlertFailCountsReadVal, ConfWriteVal};

    const OFFSET_CONF: caliptra_emu_types::RvAddr = 0x24;

    fn make_itrng_nibbles() -> Box<dyn Iterator<Item = u8>> {
        Box::new(std::iter::repeat_with(|| 0xAu8))
    }

    #[test]
    fn test_entropy_health_register_offsets_and_failure_fields() {
        let mut source = EntropySrc::new(make_itrng_nibbles());
        for (offset, value) in [(0x30, 8), (0x38, 2), (0x3c, 3)] {
            source.write(RvSize::Word, offset, value).unwrap();
        }
        source.write(RvSize::Word, OFFSET_CONF, 0x999996).unwrap();
        source
            .write(RvSize::Word, MODULE_ENABLE, MultiBitBool::True as u32)
            .unwrap();

        let failures = AlertFailCountsReadVal::from(source.read(RvSize::Word, 0x98).unwrap());
        assert_eq!(failures.repcnt_fail_count(), 15);
        assert_eq!(failures.repcnts_fail_count(), 14);
        assert_eq!(failures.adaptp_hi_fail_count(), 0);
        assert_eq!(failures.adaptp_lo_fail_count(), 0);
        assert_eq!(failures.markov_lo_fail_count(), 0);
        assert_eq!(source.read(RvSize::Word, 0x94).unwrap(), 74);
        assert_eq!(source.read(RvSize::Word, 0xd0).unwrap(), 0x1fb);
    }

    #[test]
    fn test_single_bit_seed_uses_selected_lane_and_configured_sample_count() {
        let mut source = EntropySrc::new(Box::new(std::iter::repeat_n(0b1011, 128)));
        let conf = ConfWriteVal::from(0x999999)
            .fips_enable(MultiBitBool::True as u32)
            .rng_bit_enable(MultiBitBool::True as u32)
            .rng_bit_sel(2);
        source
            .write(RvSize::Word, OFFSET_CONF, u32::from(conf))
            .unwrap();
        source.write(RvSize::Word, 0x30, 64).unwrap();
        source
            .write(RvSize::Word, MODULE_ENABLE, MultiBitBool::True as u32)
            .unwrap();

        let mut expected = Sha3_384::digest([0u8; 16]);
        expected.reverse();
        assert_eq!(
            source.take_seed().unwrap().into_csrng_bytes().as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn test_warm_reset_sets_module_enable_to_false() {
        let mut source = EntropySrc::new(make_itrng_nibbles());

        // Verify initial state: module_enable should be 0x9 (MultiBitBool::False)
        let initial = source.read(RvSize::Word, MODULE_ENABLE).unwrap();
        assert_eq!(initial, MultiBitBool::False as u32);

        // Configure FIPS mode (fips_enable in bits [3:0] = 6 for TRUE)
        // Use the default conf value but with fips_enable set to TRUE
        let conf_with_fips = 0x999996; // Replace low nibble 9 with 6
        source
            .write(RvSize::Word, OFFSET_CONF, conf_with_fips)
            .unwrap();

        // Enable the module by writing MultiBitBool::True
        source
            .write(RvSize::Word, MODULE_ENABLE, MultiBitBool::True as u32)
            .unwrap();

        // Verify module is enabled
        let enabled = source.read(RvSize::Word, MODULE_ENABLE).unwrap();
        assert_eq!(enabled, MultiBitBool::True as u32);

        // Perform warm reset
        source.warm_reset();

        // After warm reset, module_enable should be back to 0x9 (MultiBitBool::False)
        let after_reset = source.read(RvSize::Word, MODULE_ENABLE).unwrap();
        assert_eq!(
            after_reset,
            MultiBitBool::False as u32,
            "After warm reset, module_enable should be MultiBitBool::False (0x9)"
        );
    }
}

/*++

Licensed under the Apache-2.0 license.

Inspired by OpenTitan's driver interface functions for the entropy_src and
CSRNG peripherals:
https://opentitan.org/book/sw/device/lib/dif/dif_entropy_src_h.html
https://opentitan.org/book/sw/device/lib/dif/dif_csrng_h.html

An overview of the entropy_src and CSRNG peripherals can be found at:
https://opentitan.org/earlgrey_1.0.0/book/hw/ip/entropy_src/index.html
https://opentitan.org/book/hw/ip/csrng/index.html

File Name:

    csrng.rs

Abstract:

    Software interface to the Cryptographically Secure Random Number Generator
    (CSRNG) peripheral.

--*/
use crate::persistent::{EntropyConfiguration, EntropyConfigurationExtension};
use crate::soc_ifc::reset_reason;
use crate::{wait, CaliptraError, CaliptraResult, PersistentDataAccessor, ResetReason};
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::{self, regs::AlertFailCountsReadVal, EntropySrcReg};
use caliptra_registers::soc_ifc::{self, SocIfcReg};

// https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#command-description
pub const MAX_SEED_WORDS: usize = 12;
const WORDS_PER_BLOCK: usize = 4;
const ES_ALERT_HANG: u32 = 0x1fb;
// ROM defaults used when a CPTRA_iTRNG_ENTROPY_CONFIG field is zero. See
// the "Entropy Source Configuration Registers" section of the ROM README.
const DEFAULT_ALERT_THRESHOLD: u32 = 2;
const DEFAULT_HEALTH_TEST_WINDOW: u32 = 1024;
// Assumes a min-entropy of 1 per sample (NIST SP 800-90B 4.4.1, alpha = 2^-40).
const DEFAULT_REPCNT_THRESHOLD: u32 = 41;
// Reset values of the entropy_src thresholds; these never fail.
const UNUSED_HI_THRESHOLD: u32 = 0xffff;
const UNUSED_LO_THRESHOLD: u32 = 0;

/// Health-test configuration of one entropy source, as cached in ROM
/// persistent data.
#[derive(Clone)]
struct SourceConfig {
    cfg: EntropyConfiguration,
    ext: EntropyConfigurationExtension,
}

/// A unique handle to the underlying CSRNG peripheral.
pub struct Csrng {
    csrng: CsrngReg,
    entropy_src: EntropySrcReg,
}

impl Csrng {
    /// Returns a handle to the CSRNG in TRNG mode.
    ///
    /// The CSRNG will gather seed material from the entropy_src peripheral.
    ///
    /// # Safety
    ///
    /// No other handles to the CSRNG should exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal seed command fails.
    pub fn new(
        csrng: CsrngReg,
        entropy_src: EntropySrcReg,
        soc_ifc: &SocIfcReg,
        persistent_data: PersistentDataAccessor,
    ) -> CaliptraResult<Self> {
        Self::with_seed(
            csrng,
            entropy_src,
            soc_ifc,
            Seed::EntropySrc,
            persistent_data,
        )
    }

    /// # Safety
    ///
    /// The caller MUST ensure that the CSRNG peripheral is in a state where new
    /// entropy is accessible via the generate command.
    pub unsafe fn assume_initialized(csrng: CsrngReg, entropy_src: EntropySrcReg) -> Self {
        Self { csrng, entropy_src }
    }

    /// Returns a handle to the CSRNG configured to use the provided [`Seed`].
    ///
    /// # Safety
    ///
    /// No other handles to the CSRNG should exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal seed command fails.
    pub fn with_seed(
        csrng: CsrngReg,
        entropy_src: EntropySrcReg,
        soc_ifc: &SocIfcReg,
        seed: Seed,
        mut persistent_data: PersistentDataAccessor,
    ) -> CaliptraResult<Self> {
        let mut result = Self { csrng, entropy_src };
        result.configure_entropy_sources(soc_ifc, &mut persistent_data)?;
        let c = result.csrng.regs_mut();

        if c.ctrl().read().enable() == MULTIBIT_FALSE {
            c.ctrl().write(|w| {
                w.enable(MULTIBIT_TRUE)
                    .sw_app_enable(MULTIBIT_TRUE)
                    .read_int_state(MULTIBIT_TRUE)
            });
        }

        result.send_command(Command::Uninstantiate)?;
        result.send_command(Command::Instantiate(seed))?;

        Ok(result)
    }

    /// Program and enable entropy_src unless an earlier stage already did.
    fn configure_entropy_sources(
        &mut self,
        soc_ifc: &SocIfcReg,
        persistent: &mut PersistentDataAccessor,
    ) -> CaliptraResult<()> {
        let e = self.entropy_src.regs();
        if e.module_enable().read().module_enable() == MULTIBIT_TRUE {
            return Ok(());
        }
        let r = soc_ifc.regs();
        let config = entropy_configuration(&r, persistent);
        let lock = r.cptra_security_state().read().debug_locked();
        program_entropy_source(self.entropy_src.regs_mut(), &config, lock);
        self.enable_entropy_source();
        check_for_alert_state(self.entropy_src.regs())
    }

    /// Return 4 randomly generated [`u32`]s as a tuple.
    ///
    /// The return type is a tuple of 4 `u32`s which fits entirely in registers
    /// on RV32, guaranteeing no hidden out-pointer and no `memcpy` on the
    /// return path regardless of optimization level. Safe to call before CFI
    /// counters are initialized.
    pub fn generate4(&mut self) -> CaliptraResult<(u32, u32, u32, u32)> {
        let token = self.manage_entropy_src_and_reseed()?;
        self.do_generate4(token)
    }

    fn do_generate4(&mut self, _token: GenerateToken) -> CaliptraResult<(u32, u32, u32, u32)> {
        self.send_command(Command::Generate {
            num_128_bit_blocks: 1,
        })?;
        wait::until(|| self.csrng.regs().genbits_vld().read().genbits_vld());
        let w0 = self.csrng.regs().genbits().read();
        let w1 = self.csrng.regs().genbits().read();
        let w2 = self.csrng.regs().genbits().read();
        let w3 = self.csrng.regs().genbits().read();
        self.wait_for_csrng_idle(CaliptraError::DRIVER_CSRNG_GENERATE)?;
        Ok((w0, w1, w2, w3))
    }

    /// Return 12 randomly generated [`u32`]s.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal generate command fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let mut csrng = ...;
    ///
    /// let random_words: [u32; 12] = csrng.generate()?;
    ///
    /// for word in random_words {
    ///     // Do something with `word`.
    /// }
    /// ```
    pub fn generate12(&mut self) -> CaliptraResult<[u32; 12]> {
        let token = self.manage_entropy_src_and_reseed()?;
        let result = self.do_generate::<12>(token, 12 / WORDS_PER_BLOCK)?;
        #[cfg(feature = "fips-test-hooks")]
        let result = unsafe {
            crate::FipsTestHook::corrupt_data_if_hook_set(
                crate::FipsTestHook::CSRNG_CORRUPT_OUTPUT,
                &result,
            )
        };
        Ok(result)
    }

    /// Number of Generate calls before the reseed interval at which entropy_src
    /// is pre-enabled, so it is ready by the time the reseed is needed.
    /// Covers the ~2 ms entropy_src startup at typical generate cadence.
    pub const ENTROPY_SRC_PRE_ENABLE_HEADROOM: u32 = 5;

    /// Disable entropy_src.
    ///
    /// Must be called only after any in-flight Reseed has consumed its seed
    /// from the esfinal FIFO; disabling mid-Reseed clears that FIFO and hangs
    /// the CSRNG in `MainSmReseedPrep`. Pair with `wait_for_csrng_idle`.
    pub(crate) fn disable_entropy_source(&mut self) {
        self.entropy_src
            .regs_mut()
            .module_enable()
            .write(|w| w.module_enable(MULTIBIT_FALSE));
    }

    pub(crate) fn enable_entropy_source(&mut self) {
        self.entropy_src
            .regs_mut()
            .module_enable()
            .write(|w| w.module_enable(MULTIBIT_TRUE));
    }

    /// Called before every Generate command. Keeps entropy_src disabled except
    /// during a short window around each reseed:
    ///
    /// Phase 1 — pre-enable (`counter >= interval - HEADROOM`): enable
    /// entropy_src in the background so its startup health checks overlap with
    /// the next few Generates.
    ///
    /// Phase 2 — reseed (`counter >= interval`): reseed from entropy_src,
    /// then disable it again. The Generate runs with entropy_src off.
    fn manage_entropy_src_and_reseed(&mut self) -> CaliptraResult<GenerateToken> {
        let interval = self.csrng.regs().reseed_interval().read();
        let counter = self.csrng.regs().reseed_counter_2().read();
        if counter >= interval {
            self.ensure_entropy_src_enabled(&Seed::EntropySrc)?;
            self.reseed(Seed::EntropySrc)?;
            self.disable_entropy_source();
            return Ok(GenerateToken(()));
        }

        let pre_enable_threshold = interval.saturating_sub(Self::ENTROPY_SRC_PRE_ENABLE_HEADROOM);
        if counter >= pre_enable_threshold {
            self.enable_entropy_source();
        }

        Ok(GenerateToken(()))
    }

    fn do_generate<const N: usize>(
        &mut self,
        _token: GenerateToken,
        num_128_bit_blocks: usize,
    ) -> CaliptraResult<[u32; N]> {
        self.send_command(Command::Generate { num_128_bit_blocks })?;

        let mut result = [0u32; N];
        for block in result.chunks_mut(WORDS_PER_BLOCK) {
            wait::until(|| self.csrng.regs().genbits_vld().read().genbits_vld());
            for word in block.iter_mut() {
                *word = self.csrng.regs().genbits().read();
            }
        }
        self.wait_for_csrng_idle(CaliptraError::DRIVER_CSRNG_GENERATE)?;
        Ok(result)
    }

    /// Return 16 randomly generated [`u32`]s (512 bits = four 128-bit GENBITS
    /// blocks) from a single Generate command.
    ///
    /// This is distinct from invoking [`Self::generate12`] / [`Self::generate4`]
    /// multiple times because each `Generate` command performs its own internal
    /// Update step on completion (NIST SP 800-90A). The CTR_DRBG-AES-256 NIST
    /// CAVP known-answer vectors specify `ReturnedBitsLen = 512`, so the KAT
    /// must request all 512 bits from one Generate.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal generate command fails.
    pub fn generate16(&mut self) -> CaliptraResult<[u32; 16]> {
        let token = self.manage_entropy_src_and_reseed()?;
        let result = self.do_generate::<16>(token, 16 / WORDS_PER_BLOCK)?;
        #[cfg(feature = "fips-test-hooks")]
        let result = unsafe {
            crate::FipsTestHook::corrupt_data_if_hook_set(
                crate::FipsTestHook::CSRNG_CORRUPT_OUTPUT,
                &result,
            )
        };
        Ok(result)
    }

    /// Reseed the DRBG with the given seed. Returns only after the CSRNG has
    /// fully processed the Reseed.
    pub fn reseed(&mut self, seed: Seed) -> CaliptraResult<()> {
        self.ensure_entropy_src_enabled(&seed)?;
        // FIPS test hook: inject a reseed failure for testing on platforms
        // where the real TRNG cannot produce bad entropy (e.g. FPGA itrng).
        // No-op unless `fips-test-hooks` is enabled and the host arms
        // `CSRNG_RESEED_FAILURE` in `cptra_dbg_manuf_service_reg`.
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::CSRNG_RESEED_FAILURE)?;
        }
        self.send_command(Command::Reseed(seed))
    }

    /// Tear down the current DRBG instance and create a new one with the
    /// given seed.
    ///
    /// This requires that the CSRNG and ENTROPY_SRC peripherals have already
    /// been enabled and configured by a prior call to [`Self::new`] /
    /// [`Self::with_seed`]. It is used by the CTR_DRBG known-answer test to
    /// briefly swap the live DRBG into deterministic mode (`flag0=true`) for
    /// validation against a NIST CAVP vector and then restore an
    /// entropy-sourced instance before returning to production use.
    ///
    /// # Errors
    ///
    /// Returns an error if either the internal `Uninstantiate` or
    /// `Instantiate` command fails.
    pub fn reinstantiate(&mut self, seed: Seed) -> CaliptraResult<()> {
        self.ensure_entropy_src_enabled(&seed)?;
        self.send_command(Command::Uninstantiate)?;
        self.send_command(Command::Instantiate(seed))
    }

    /// Enables entropy_src and waits for it to be ready if the seed source is
    /// `EntropySrc` and the module is currently disabled. No-op for
    /// `Seed::Constant` since entropy_src is not needed in that case.
    fn ensure_entropy_src_enabled(&mut self, seed: &Seed) -> CaliptraResult<()> {
        if matches!(seed, Seed::EntropySrc) {
            if self
                .entropy_src
                .regs()
                .module_enable()
                .read()
                .module_enable()
                != MULTIBIT_TRUE
            {
                self.enable_entropy_source();
            }
            check_for_alert_state(self.entropy_src.regs())?;
        }
        Ok(())
    }

    pub fn update(&mut self, additional_data: &[u32]) -> CaliptraResult<()> {
        // if we are given too much data, do multiple updates
        for data in additional_data.chunks(MAX_SEED_WORDS) {
            self.send_command(Command::Update(data))?;
        }
        Ok(())
    }

    /// Returns the number of failing health checks.
    pub fn health_fail_counts(&self) -> HealthFailCounts {
        let e = self.entropy_src.regs();

        HealthFailCounts {
            total: e.alert_summary_fail_counts().read().any_fail_count(),
            specific: e.alert_fail_counts().read(),
        }
    }

    pub fn uninstantiate(mut self) {
        let _ = self.send_command(Command::Uninstantiate);
    }

    pub fn zeroize(&mut self) -> CaliptraResult<()> {
        self.send_command(Command::Uninstantiate)
    }

    /// Leave no DRBG or entropy state behind for the next boot stage.
    ///
    /// Uninstantiates the DRBG, disables the entropy source (dropping any
    /// queued seeds), and disables then re-enables CSRNG while it is idle.
    /// The next stage instantiates a fresh DRBG through [`Csrng::new`].
    pub fn clear_for_handoff(&mut self) -> CaliptraResult<()> {
        self.send_command(Command::Uninstantiate)?;
        self.disable_entropy_source();
        let c = self.csrng.regs_mut();
        let ctrl = u32::from(c.ctrl().read());
        c.ctrl().modify(|w| w.enable(MULTIBIT_FALSE));
        c.ctrl().write(|_| ctrl.into());
        Ok(())
    }

    /// Wait for the CSRNG command interface to be ready to accept a word.
    fn wait_for_cmd_rdy(&self, err: CaliptraError) -> CaliptraResult<()> {
        loop {
            let reg = self.csrng.regs().sw_cmd_sts().read();

            // Order matters. Check for errors first.
            if reg.cmd_sts() != 0 || u32::from(self.csrng.regs().err_code().read()) != 0 {
                // TODO: Somehow convey additional error information found in
                // the ERR_CODE register.
                return Err(err);
            }

            if reg.cmd_rdy() {
                return Ok(());
            }
        }
    }

    /// Wait for the CSRNG command to be acknowledged and the main SM to return
    /// to Idle.
    fn wait_for_csrng_idle(&self, err: CaliptraError) -> CaliptraResult<()> {
        const MAIN_SM_IDLE: u32 = 0x4e;
        loop {
            let reg = self.csrng.regs().sw_cmd_sts().read();
            if reg.cmd_sts() != 0 || u32::from(self.csrng.regs().err_code().read()) != 0 {
                return Err(err);
            }
            let csrng_state = self.csrng.regs().main_sm_state().read().main_sm_state();
            if reg.cmd_rdy() && reg.cmd_ack() && csrng_state == MAIN_SM_IDLE {
                return Ok(());
            }
            let es_state = self
                .entropy_src
                .regs()
                .main_sm_state()
                .read()
                .main_sm_state();
            if es_state == ES_ALERT_HANG {
                return check_for_alert_state(self.entropy_src.regs());
            }
        }
    }

    fn send_command(&mut self, command: Command) -> CaliptraResult<()> {
        // https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#general-command-format
        let acmd: u32;
        let clen: usize;
        let flag0: MultiBitBool;
        let glen: usize;
        let extra_words: &[u32];
        let err: CaliptraError;

        match command {
            Command::Instantiate(ref seed) | Command::Reseed(ref seed) => {
                acmd = if matches!(command, Command::Instantiate(_)) {
                    err = CaliptraError::DRIVER_CSRNG_INSTANTIATE;
                    1
                } else {
                    err = CaliptraError::DRIVER_CSRNG_RESEED;
                    2
                };

                match seed {
                    Seed::EntropySrc => {
                        clen = 0;
                        flag0 = MultiBitBool::False;
                        extra_words = &[];
                    }

                    Seed::Constant(constant) => {
                        clen = constant.len().min(MAX_SEED_WORDS);
                        flag0 = MultiBitBool::True;
                        extra_words = &constant[..clen];
                    }
                }

                glen = 0;
            }

            Command::Generate { num_128_bit_blocks } => {
                acmd = 3;
                clen = 0;
                flag0 = MultiBitBool::False;
                glen = num_128_bit_blocks;
                extra_words = &[];
                err = CaliptraError::DRIVER_CSRNG_GENERATE;
            }

            Command::Update(words) => {
                acmd = 4;
                clen = words.len().min(MAX_SEED_WORDS);
                flag0 = MultiBitBool::True;
                glen = 0;
                extra_words = &words[..clen];
                err = CaliptraError::DRIVER_CSRNG_UPDATE;
            }

            Command::Uninstantiate => {
                acmd = 5;
                clen = 0;
                flag0 = MultiBitBool::False;
                glen = 0;
                extra_words = &[];
                err = CaliptraError::DRIVER_CSRNG_UNINSTANTIATE;
            }
        }

        // Write mandatory 32-bit command header.
        self.wait_for_cmd_rdy(err)?;
        self.csrng.regs_mut().cmd_req().write(|w| {
            w.acmd(acmd)
                .clen(clen as u32)
                .flag0(flag0 as u32)
                .glen(glen as u32)
        });

        // Write optional extra words.
        for &word in extra_words {
            self.wait_for_cmd_rdy(err)?;
            self.csrng.regs_mut().cmd_req().write(|_| word.into());
        }

        if matches!(command, Command::Generate { .. }) {
            // Generate commands are only acknowledged after GENBITS are read.
            self.wait_for_cmd_rdy(err)
        } else {
            self.wait_for_csrng_idle(err)
        }
    }
}

fn check_for_alert_state(
    entropy_src: entropy_src::RegisterBlock<caliptra_ureg::RealMmio>,
) -> CaliptraResult<()> {
    // https://opentitan.org/earlgrey_1.0.0/book/hw/ip/entropy_src/doc/theory_of_operation.html#main-state-machine-diagram
    // https://github.com/chipsalliance/caliptra-rtl/blob/main/src/entropy_src/rtl/entropy_src_main_sm_pkg.sv
    while !poll_entropy_source(&entropy_src)? {}
    Ok(())
}

fn poll_entropy_source(
    entropy_src: &entropy_src::RegisterBlock<caliptra_ureg::RealMmio<'_>>,
) -> CaliptraResult<bool> {
    const CONT_HT_RUNNING: u32 = 0x1a2;
    const BOOT_PHASE_DONE: u32 = 0x8e;
    match entropy_src.main_sm_state().read().main_sm_state() {
        ES_ALERT_HANG => {
            let counts = entropy_src.alert_fail_counts().read();
            if counts.repcnt_fail_count() > 0 || counts.repcnts_fail_count() > 0 {
                Err(CaliptraError::DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED)
            } else if counts.adaptp_lo_fail_count() > 0
                || counts.adaptp_hi_fail_count() > 0
                || counts.adaptps_fail_count() > 0
            {
                Err(CaliptraError::DRIVER_CSRNG_ADAPTP_HEALTH_CHECK_FAILED)
            } else {
                Err(CaliptraError::DRIVER_CSRNG_OTHER_HEALTH_CHECK_FAILED)
            }
        }
        CONT_HT_RUNNING | BOOT_PHASE_DONE => Ok(true),
        _ => Ok(false),
    }
}

/// Variants that describe seed inputs to the CSRNG.
pub enum Seed<'a> {
    /// Use a non-deterministic seed.
    EntropySrc,

    /// Use a deterministic seed. The number of seed words should be at least
    /// one and no more than twelve.
    Constant(&'a [u32]),
}

/// Proof token that `manage_entropy_src_and_reseed` has been called.
struct GenerateToken(());

enum Command<'a> {
    Instantiate(Seed<'a>),
    Reseed(Seed<'a>),
    Generate { num_128_bit_blocks: usize },
    Update(&'a [u32]),
    Uninstantiate,
}

#[repr(u32)]
enum MultiBitBool {
    False = 9,
    True = 6,
}

const MULTIBIT_FALSE: u32 = MultiBitBool::False as u32;
const MULTIBIT_TRUE: u32 = MultiBitBool::True as u32;

/// Contains counts of failing health checks.
///
/// This struct is returned by the [`health_fail_counts`] function on [`Csrng`].
///
/// [`health_fail_counts`]: Csrng::health_fail_counts
pub struct HealthFailCounts {
    /// The total number of failing health check alerts.
    pub total: u32,

    /// The counts of specific failing health checks.
    pub specific: AlertFailCountsReadVal,
}

/// Return the entropy source configuration.
///
/// On cold reset this reads CPTRA_iTRNG_ENTROPY_CONFIG_{0,1,2} and caches the
/// result in ROM persistent data; later resets reuse the cache.
fn entropy_configuration(
    soc_ifc: &soc_ifc::RegisterBlock<caliptra_ureg::RealMmio>,
    persistent: &mut PersistentDataAccessor,
) -> SourceConfig {
    let rom = &mut persistent.get_mut().rom;
    let cold_reset = matches!(reset_reason(), ResetReason::ColdReset);
    if !cold_reset && rom.entropy_cfg.configured != 0 {
        let ext = if rom.supports_entropy_cfg_extension() {
            rom.entropy_cfg_extension
        } else {
            EntropyConfigurationExtension::default()
        };
        return SourceConfig {
            cfg: rom.entropy_cfg.clone(),
            ext,
        };
    }

    let config = source_config(
        soc_ifc.cptra_i_trng_entropy_config_0().read(),
        soc_ifc.cptra_i_trng_entropy_config_1().read(),
        soc_ifc.cptra_i_trng_entropy_config_2().read(),
    );
    rom.entropy_cfg = config.cfg.clone();
    rom.entropy_cfg_extension = config.ext;
    config
}

/// Decode one source's CPTRA_iTRNG_ENTROPY_CONFIG_{0,1,2}. A zero field
/// selects the ROM default.
fn source_config(
    cfg0: soc_ifc::regs::EntropyConfig0ReadVal,
    cfg1: soc_ifc::regs::EntropyConfig1ReadVal,
    cfg2: soc_ifc::regs::EntropyConfig2ReadVal,
) -> SourceConfig {
    let or_default = |value, default| if value == 0 { default } else { value };
    // FIPS_WINDOW is in samples: one bit of the selected lane in single-bit
    // mode, one 4-bit symbol in multi-channel mode.
    let window = or_default(cfg2.fips_window_size(), DEFAULT_HEALTH_TEST_WINDOW);
    let single_bit = cfg2.single_bit_mode();

    // Adaptive Proportion cutoffs, 75% and 25% of the window by default.
    // RTL fails when the count reaches the high threshold (>=) or falls to the
    // low threshold (<=), so the SoC programs the NIST cutoff C directly.
    let default_hi = 3 * (window / 4);
    let default_lo = window / 4;
    let hi = or_default(cfg0.high_threshold(), default_hi);
    let (hi, lo) = if single_bit {
        let lo = or_default(cfg0.low_threshold(), default_lo);
        if lo < hi {
            (hi, lo)
        } else {
            (default_hi, default_lo)
        }
    } else {
        // ADAPTPS has no low cutoff; CONFIG_0.low_threshold is unused.
        (hi, UNUSED_LO_THRESHOLD)
    };

    let mut ext = EntropyConfigurationExtension::default();
    ext.set_rng_bit_enable(single_bit);
    ext.set_rng_bit_sel(if single_bit { cfg2.rng_bit_sel() } else { 0 });
    ext.set_bypass(cfg2.bypass_mode());

    SourceConfig {
        cfg: EntropyConfiguration {
            configured: 1,
            alert_threshold: or_default(cfg1.alert_threshold(), DEFAULT_ALERT_THRESHOLD),
            health_test_window: window,
            repcnt_threshold: or_default(cfg1.repetition_count(), DEFAULT_REPCNT_THRESHOLD),
            adaptp_hi_threshold: hi,
            adaptp_lo_threshold: lo,
        },
        ext,
    }
}

/// Program one entropy_src instance while it is disabled and unlocked.
///
/// Single-bit mode uses the per-lane tests (REPCNT, ADAPTP_HI/LO); multi-channel
/// mode uses the symbol tests (REPCNTS, ADAPTPS). The other set stays at its
/// never-failing reset value.
fn program_entropy_source(
    e: entropy_src::RegisterBlock<caliptra_ureg::RealMmioMut>,
    source: &SourceConfig,
    lock: bool,
) {
    if e.module_enable().read().module_enable() == MULTIBIT_TRUE
        || !e.sw_regupd().read().sw_regupd()
    {
        return;
    }
    let (cfg, ext) = (&source.cfg, source.ext);
    e.alert_threshold().write(|w| {
        w.alert_threshold(cfg.alert_threshold)
            .alert_threshold_inv(!cfg.alert_threshold & 0xffff)
    });
    e.health_test_windows()
        .write(|w| w.fips_window(cfg.health_test_window));

    let (repcnt, adaptp_hi, adaptp_lo, repcnts, adaptps) = if ext.rng_bit_enable() {
        (
            cfg.repcnt_threshold,
            cfg.adaptp_hi_threshold,
            cfg.adaptp_lo_threshold,
            UNUSED_HI_THRESHOLD,
            UNUSED_HI_THRESHOLD,
        )
    } else {
        (
            UNUSED_HI_THRESHOLD,
            UNUSED_HI_THRESHOLD,
            UNUSED_LO_THRESHOLD,
            cfg.repcnt_threshold,
            cfg.adaptp_hi_threshold,
        )
    };
    e.repcnt_threshold().write(|w| w.repcnt_threshold(repcnt));
    e.adaptp_hi_threshold()
        .write(|w| w.adaptp_hi_threshold(adaptp_hi));
    e.adaptp_lo_threshold()
        .write(|w| w.adaptp_lo_threshold(adaptp_lo));
    e.repcnts_threshold()
        .write(|w| w.repcnts_threshold(repcnts));
    e.adaptps_threshold()
        .write(|w| w.adaptps_threshold(adaptps));

    e.conf().write(|w| {
        // Conditioning is enabled, but SoC-supplied thresholds are not an
        // approved qualification profile, so FIPS_FLAG stays false.
        w.fips_enable(MULTIBIT_TRUE)
            .fips_flag(MULTIBIT_FALSE)
            .entropy_data_reg_enable(MULTIBIT_FALSE)
            // Score lanes individually rather than summed.
            .threshold_scope(MULTIBIT_FALSE)
            .rng_bit_enable(if ext.rng_bit_enable() {
                MULTIBIT_TRUE
            } else {
                MULTIBIT_FALSE
            })
            .rng_bit_sel(ext.rng_bit_sel())
    });
    // The SoC may request bypass so entropy can be characterized without
    // conditioning.
    if ext.bypass() {
        e.entropy_control().modify(|w| w.es_type(MULTIBIT_TRUE));
    }
    // Production: ROM programs once and locks the configuration. Debug-unlocked
    // parts stay writable for characterization. MODULE_ENABLE stays writable
    // so firmware can power the source down between reseeds.
    if lock {
        e.sw_regupd().modify(|w| w.sw_regupd(false));
    }
}

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
// The #[inline(never)] annotations keep the firmware images within budget.
use crate::persistent::{EntropyConfiguration, EntropyConfigurationExtension};
use crate::soc_ifc::reset_reason;
use crate::{CaliptraError, CaliptraResult, PersistentDataAccessor, ResetReason};
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_combiner::{self, EntropyCombinerReg};
use caliptra_registers::entropy_src::{
    self, regs::AlertFailCountsReadVal, EntropySrc1Reg, EntropySrcReg,
};
use caliptra_registers::soc_ifc::{self, SocIfcReg};
use caliptra_ureg::{Mmio, MmioMut, RealMmio, RealMmioMut};

// https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#command-description
pub const MAX_SEED_WORDS: usize = 12;
const WORDS_PER_BLOCK: usize = 4;
// Bound CSRNG command and entropy-source startup polling even before ROM arms WDT.
// Deliberately larger than the KAT bound: ENTROPY_SRC can be fed slowly.
const ENTROPY_POLL_LIMIT: u32 = 4_000_000;
const ES_ALERT_HANG: u32 = 0x1fb;

// ROM defaults used when a CPTRA_iTRNG{,1}_ENTROPY_CONFIG field is zero. See
// the "Entropy Source Configuration Registers" section of the ROM README.
const DEFAULT_ALERT_THRESHOLD: u32 = 2;
const DEFAULT_HEALTH_TEST_WINDOW: u32 = 1024;
// Assumes a min-entropy of 1 per sample (NIST SP 800-90B 4.4.1, alpha = 2^-40).
const DEFAULT_REPCNT_THRESHOLD: u32 = 41;
// Reset values of the entropy_src thresholds; these never fail.
const UNUSED_HI_THRESHOLD: u32 = 0xffff;
const UNUSED_LO_THRESHOLD: u32 = 0;

/// Register tokens for the entropy sources and the entropy combiner.
pub struct EntropyRegs {
    es0: EntropySrcReg,
    es1: EntropySrc1Reg,
    combiner: EntropyCombinerReg,
}

impl EntropyRegs {
    /// # Safety
    ///
    /// Caller must ensure that all concurrent use of these peripherals in the
    /// firmware is done in a compatible way. The simplest way to enforce this
    /// is to only call this function once.
    pub unsafe fn new() -> Self {
        Self {
            es0: EntropySrcReg::new(),
            es1: EntropySrc1Reg::new(),
            combiner: EntropyCombinerReg::new(),
        }
    }

    /// Borrow the combiner token for setup before handing ownership to CSRNG.
    pub fn combiner_mut(&mut self) -> &mut EntropyCombinerReg {
        &mut self.combiner
    }
}

/// A unique handle to the underlying CSRNG peripheral and its entropy sources.
///
/// All register fields are zero-sized types, so `Csrng` itself is zero-sized
/// and `#[repr(u32)] Trng` stays 4 bytes.
pub struct Csrng {
    csrng: CsrngReg,
    entropy: EntropyRegs,
}

impl Csrng {
    /// Returns a handle to the CSRNG in TRNG mode, configuring `entropy_src`
    /// from `CPTRA_iTRNG{,1}_ENTROPY_CONFIG_*` (for ROM and standalone tests).
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
        entropy: EntropyRegs,
        soc_ifc: &SocIfcReg,
        persistent_data: PersistentDataAccessor,
    ) -> CaliptraResult<Self> {
        Self::with_seed(csrng, entropy, soc_ifc, Seed::EntropySrc, persistent_data)
    }

    /// Returns a handle to the CSRNG assuming ROM has already configured and
    /// locked `entropy_src` (for FMC and Runtime).
    ///
    /// Enables the already-configured entropy sources if disabled (e.g. after
    /// ROM handoff), enables CSRNG if disabled, and instantiates a fresh DRBG
    /// without reading or mutating ROM persistent data.
    pub fn new_configured(csrng: CsrngReg, entropy: EntropyRegs) -> CaliptraResult<Self> {
        let mut result = Self { csrng, entropy };
        result.check_combiner()?;
        result.ensure_entropy_src_enabled(&Seed::EntropySrc)?;
        result.enable_and_instantiate(Seed::EntropySrc)?;
        Ok(result)
    }

    /// # Safety
    ///
    /// The caller MUST ensure that the CSRNG peripheral is in a state where new
    /// entropy is accessible via the generate command.
    pub unsafe fn assume_initialized(csrng: CsrngReg, entropy: EntropyRegs) -> Self {
        Self { csrng, entropy }
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
        entropy: EntropyRegs,
        soc_ifc: &SocIfcReg,
        seed: Seed,
        mut persistent_data: PersistentDataAccessor,
    ) -> CaliptraResult<Self> {
        let mut result = Self { csrng, entropy };
        result.check_combiner()?;
        result.configure_entropy_sources(soc_ifc, &mut persistent_data)?;
        result.enable_and_instantiate(seed)?;
        Ok(result)
    }

    fn enable_and_instantiate(&mut self, seed: Seed) -> CaliptraResult<()> {
        let c = self.csrng.regs_mut();

        if c.ctrl().read().enable() == MULTIBIT_FALSE {
            c.ctrl().write(|w| {
                w.enable(MULTIBIT_TRUE)
                    .sw_app_enable(MULTIBIT_TRUE)
                    .read_int_state(MULTIBIT_TRUE)
            });
        }

        self.send_command(Command::Uninstantiate)?;
        self.send_command(Command::Instantiate(seed))
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
        self.wait_for_genbits()?;
        let w0 = self.csrng.regs().genbits().read();
        let w1 = self.csrng.regs().genbits().read();
        let w2 = self.csrng.regs().genbits().read();
        let w3 = self.csrng.regs().genbits().read();
        self.wait_for_csrng_idle(CaliptraError::DRIVER_CSRNG_GENERATE, EntropyCheck::Check)?;
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

    fn check_combiner(&mut self) -> CaliptraResult<()> {
        EntropySources::from_hw(&mut self.entropy).check_combiner()
    }

    /// Program and enable ES0, and ES1 in dual-iTRNG mode, unless already
    /// enabled by an earlier stage. Dual mode always waits for both sources.
    #[inline(never)]
    fn configure_entropy_sources(
        &mut self,
        soc_ifc: &SocIfcReg,
        persistent: &mut PersistentDataAccessor,
    ) -> CaliptraResult<()> {
        let r = soc_ifc.regs();
        let lock = r.cptra_security_state().read().debug_locked();
        let sources = EntropySources::from_hw(&mut self.entropy);
        let need_wait = if !sources.all_enabled() {
            let rom = &mut persistent.get_mut().rom;
            load_entropy_configurations(&r, rom, sources.secondary.is_some())?;
            program_entropy_source(
                &sources.es0,
                &rom.entropy_cfg,
                rom.entropy_cfg_extension,
                lock,
            );
            if let Some(sec) = &sources.secondary {
                program_entropy_source(
                    &sec.es1,
                    &rom.es1_entropy_cfg,
                    rom.es1_entropy_cfg_extension,
                    lock,
                );
            }
            sources.set_module_enable(MULTIBIT_TRUE);
            true
        } else {
            sources.secondary.is_some()
        };
        if need_wait {
            sources.wait_until_ready()?;
        }
        Ok(())
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
    #[inline(never)]
    fn set_entropy_source_enable(&mut self, enable: u32) {
        EntropySources::from_hw(&mut self.entropy).set_module_enable(enable);
    }

    pub(crate) fn disable_entropy_source(&mut self) {
        self.set_entropy_source_enable(MULTIBIT_FALSE);
    }

    pub(crate) fn enable_entropy_source(&mut self) {
        self.set_entropy_source_enable(MULTIBIT_TRUE);
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
        self.check_combiner()?;
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

    #[inline(never)]
    fn do_generate_slice(
        &mut self,
        _token: GenerateToken,
        out: &mut [u32],
        num_128_bit_blocks: usize,
    ) -> CaliptraResult<()> {
        self.send_command(Command::Generate { num_128_bit_blocks })?;

        for block in out.chunks_mut(WORDS_PER_BLOCK) {
            self.wait_for_genbits()?;
            for word in block.iter_mut() {
                *word = self.csrng.regs().genbits().read();
            }
        }
        self.wait_for_csrng_idle(CaliptraError::DRIVER_CSRNG_GENERATE, EntropyCheck::Check)
    }

    fn do_generate<const N: usize>(
        &mut self,
        token: GenerateToken,
        num_128_bit_blocks: usize,
    ) -> CaliptraResult<[u32; N]> {
        let mut result = [0u32; N];
        self.do_generate_slice(token, &mut result, num_128_bit_blocks)?;
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
    #[inline(never)]
    fn ensure_entropy_src_enabled(&mut self, seed: &Seed) -> CaliptraResult<()> {
        if !matches!(seed, Seed::EntropySrc) {
            return Ok(());
        }
        let sources = EntropySources::from_hw(&mut self.entropy);
        if !sources.all_enabled() {
            sources.set_module_enable(MULTIBIT_TRUE);
        }
        sources.wait_until_ready()
    }

    pub fn update(&mut self, additional_data: &[u32]) -> CaliptraResult<()> {
        // if we are given too much data, do multiple updates
        for data in additional_data.chunks(MAX_SEED_WORDS) {
            self.send_command(Command::Update(data))?;
        }
        Ok(())
    }

    /// Returns the number of failing health checks for the primary entropy
    /// source (`ES0`). On dual-iTRNG hardware, `ES1` counts are not included.
    pub fn health_fail_counts(&self) -> HealthFailCounts {
        let e = self.entropy.es0.regs();

        HealthFailCounts {
            total: e.alert_summary_fail_counts().read().any_fail_count(),
            specific: e.alert_fail_counts().read(),
        }
    }

    pub fn uninstantiate(mut self) {
        let _ = self.send_command(Command::Uninstantiate);
    }

    /// Uninstantiate the DRBG, then check the dual-iTRNG combiner (if active).
    ///
    /// The entropy sources stay enabled, and neither they nor the combiner are
    /// zeroized. The combiner check still runs if Uninstantiate fails; the
    /// Uninstantiate error takes precedence.
    pub fn zeroize(&mut self) -> CaliptraResult<()> {
        let (uninst, sources) = self.uninstantiate_for_scrub();
        uninst.and(sources.check_combiner())
    }

    /// Clear DRBG and seed state before handing off to the next boot stage.
    ///
    /// Uninstantiates the DRBG, disables the entropy sources (dropping queued
    /// seeds), zeroizes the dual-iTRNG combiner if active, checks the combiner,
    /// and disables then re-enables CSRNG. The entropy sources themselves are
    /// not zeroized. Cleanup continues if Uninstantiate fails; its error takes
    /// precedence. The next stage instantiates a fresh DRBG through
    /// [`Csrng::new_configured`].
    pub fn clear_for_handoff(&mut self) -> CaliptraResult<()> {
        let (uninst, sources) = self.uninstantiate_for_scrub();
        sources.set_module_enable(MULTIBIT_FALSE);
        if let Some(sec) = &sources.secondary {
            // Zeroize leaves the lock and FIPS policy in place.
            sec.combiner.combiner_ctrl().modify(|w| w.zeroize(true));
        }
        let combiner_ok = sources.check_combiner();
        let c = self.csrng.regs_mut();
        let ctrl = u32::from(c.ctrl().read());
        c.ctrl().modify(|w| w.enable(MULTIBIT_FALSE));
        c.ctrl().write(|_| ctrl.into());
        uninst.and(combiner_ok)
    }

    /// Common start of `zeroize` and `clear_for_handoff`. Kept as one function
    /// because inlining it into both costs ROM space.
    fn uninstantiate_for_scrub(&mut self) -> (CaliptraResult<()>, EntropySources<RealMmioMut<'_>>) {
        let uninst = self.send_command(Command::Uninstantiate);
        let sources = EntropySources::from_hw(&mut self.entropy);
        (uninst, sources)
    }

    /// Wait for the CSRNG command interface to be ready to accept a word.
    fn wait_for_cmd_rdy(
        &mut self,
        err: CaliptraError,
        entropy_check: EntropyCheck,
    ) -> CaliptraResult<()> {
        self.wait_for_csrng(err, entropy_check, WaitMode::CmdRdy)
    }

    fn wait_for_genbits(&mut self) -> CaliptraResult<()> {
        self.wait_for_csrng(
            CaliptraError::DRIVER_CSRNG_GENERATE,
            EntropyCheck::Check,
            WaitMode::Genbits,
        )
    }

    /// Wait for the CSRNG command to be acknowledged and the main SM to return
    /// to Idle.
    fn wait_for_csrng_idle(
        &mut self,
        err: CaliptraError,
        entropy_check: EntropyCheck,
    ) -> CaliptraResult<()> {
        self.wait_for_csrng(err, entropy_check, WaitMode::Idle)
    }

    #[inline(never)]
    fn wait_for_csrng(
        &mut self,
        err: CaliptraError,
        entropy_check: EntropyCheck,
        mode: WaitMode,
    ) -> CaliptraResult<()> {
        const MAIN_SM_IDLE: u32 = 0x4e;
        let check_sources = !matches!(entropy_check, EntropyCheck::Skip);
        let csrng = self.csrng.regs();
        let sources = EntropySources::from_hw(&mut self.entropy);
        for _ in 0..ENTROPY_POLL_LIMIT {
            if check_sources {
                sources.check_combiner()?;
            }
            let reg = csrng.sw_cmd_sts().read();
            if reg.cmd_sts() != 0 || u32::from(csrng.err_code().read()) != 0 {
                return Err(err);
            }
            let ready = match mode {
                WaitMode::CmdRdy => reg.cmd_rdy(),
                WaitMode::Genbits => csrng.genbits_vld().read().genbits_vld(),
                WaitMode::Idle => {
                    reg.cmd_rdy()
                        && reg.cmd_ack()
                        && csrng.main_sm_state().read().main_sm_state() == MAIN_SM_IDLE
                }
            };
            if ready {
                return Ok(());
            }
            if check_sources && matches!(mode, WaitMode::Idle) {
                sources.check_for_hang()?;
            }
        }
        Err(
            if matches!(mode, WaitMode::Idle) && matches!(entropy_check, EntropyCheck::AwaitSeed) {
                CaliptraError::DRIVER_CSRNG_ENTROPY_TIMEOUT
            } else {
                err
            },
        )
    }

    #[inline(never)]
    fn send_command(&mut self, command: Command) -> CaliptraResult<()> {
        // https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#general-command-format
        let acmd: u32;
        let clen: usize;
        let flag0: MultiBitBool;
        let glen: usize;
        let extra_words: &[u32];
        let err: CaliptraError;
        let entropy_check: EntropyCheck;

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
                        // Attribute completion stalls to entropy only for hardware seeds.
                        entropy_check = EntropyCheck::AwaitSeed;
                    }

                    Seed::Constant(constant) => {
                        clen = constant.len().min(MAX_SEED_WORDS);
                        flag0 = MultiBitBool::True;
                        extra_words = &constant[..clen];
                        entropy_check = EntropyCheck::Check;
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
                entropy_check = EntropyCheck::Check;
            }

            Command::Update(words) => {
                acmd = 4;
                clen = words.len().min(MAX_SEED_WORDS);
                flag0 = MultiBitBool::True;
                glen = 0;
                extra_words = &words[..clen];
                err = CaliptraError::DRIVER_CSRNG_UPDATE;
                entropy_check = EntropyCheck::Check;
            }

            Command::Uninstantiate => {
                acmd = 5;
                clen = 0;
                flag0 = MultiBitBool::False;
                glen = 0;
                extra_words = &[];
                err = CaliptraError::DRIVER_CSRNG_UNINSTANTIATE;
                // Uninstantiate does not consume entropy; never let a sticky combiner
                // fault or hung entropy source prevent scrubbing the DRBG.
                entropy_check = EntropyCheck::Skip;
            }
        }

        // Write mandatory 32-bit command header.
        self.wait_for_cmd_rdy(err, entropy_check)?;
        self.csrng.regs_mut().cmd_req().write(|w| {
            w.acmd(acmd)
                .clen(clen as u32)
                .flag0(flag0 as u32)
                .glen(glen as u32)
        });

        // Write optional extra words.
        for &word in extra_words {
            self.wait_for_cmd_rdy(err, entropy_check)?;
            self.csrng.regs_mut().cmd_req().write(|_| word.into());
        }

        if matches!(command, Command::Generate { .. }) {
            // Generate commands are only acknowledged after GENBITS are read.
            self.wait_for_cmd_rdy(err, entropy_check)
        } else {
            self.wait_for_csrng_idle(err, entropy_check)
        }
    }
}

/// How a CSRNG wait treats the entropy sources and the combiner.
#[derive(Clone, Copy)]
enum EntropyCheck {
    /// Ignore them.
    Skip,
    /// Fail the wait if the combiner or an entropy source reports a fault.
    Check,
    /// As `Check`, for a command that is waiting for a hardware seed: a
    /// timeout is reported as an entropy timeout.
    AwaitSeed,
}

enum WaitMode {
    CmdRdy,
    Genbits,
    Idle,
}

/// Secondary entropy source and combiner registers present only in dual-iTRNG
/// mode. Paired in one struct so ES1 and the combiner cannot be accessed
/// independently.
struct DualSources<M: Mmio> {
    es1: entropy_src::RegisterBlock<M>,
    combiner: entropy_combiner::RegisterBlock<M>,
}

/// Active entropy source registers for single- or dual-iTRNG hardware.
///
/// Constructed ephemerally via [`EntropySources::from_hw`] so [`Csrng`] stays
/// zero-sized (keeping `#[repr(u32)] Trng` at 4 bytes) while expressing
/// dual-iTRNG presence in the type system via `Option<DualSources<M>>`.
struct EntropySources<M: Mmio> {
    es0: entropy_src::RegisterBlock<M>,
    secondary: Option<DualSources<M>>,
}

impl<M: Mmio> EntropySources<M> {
    #[inline(never)]
    fn all_enabled(&self) -> bool {
        self.es0.module_enable().read().module_enable() == MULTIBIT_TRUE
            && self
                .secondary
                .as_ref()
                .is_none_or(|sec| sec.es1.module_enable().read().module_enable() == MULTIBIT_TRUE)
    }
}

impl<'a> EntropySources<RealMmioMut<'a>> {
    #[inline(never)]
    fn from_hw(regs: &'a mut EntropyRegs) -> Self {
        // SAFETY: read-only hardware configuration strap.
        let dual = unsafe { SocIfcReg::new() }
            .regs()
            .cptra_hw_config()
            .read()
            .dual_i_trng_en();
        let es0 = regs.es0.regs_mut();
        let secondary = dual.then(|| DualSources {
            es1: regs.es1.regs_mut(),
            combiner: regs.combiner.regs_mut(),
        });
        Self { es0, secondary }
    }

    #[inline(never)]
    fn check_combiner(&self) -> CaliptraResult<()> {
        match &self.secondary {
            None => Ok(()),
            Some(sec) => crate::entropy_combiner::check_locked(&sec.combiner),
        }
    }

    #[inline(never)]
    fn check_for_hang(&self) -> CaliptraResult<()> {
        check_one_hang(&self.es0)?;
        if let Some(sec) = &self.secondary {
            check_one_hang(&sec.es1)?;
        }
        Ok(())
    }

    #[inline(never)]
    fn wait_until_ready(&self) -> CaliptraResult<()> {
        for _ in 0..ENTROPY_POLL_LIMIT {
            self.check_combiner()?;
            // Check both, even if the first source has not started.
            let ready0 = poll_entropy_source(&self.es0)?;
            let ready1 = match &self.secondary {
                Some(sec) => poll_entropy_source(&sec.es1)?,
                None => true,
            };
            if ready0 && ready1 {
                return Ok(());
            }
        }
        Err(CaliptraError::DRIVER_CSRNG_ENTROPY_TIMEOUT)
    }
}

impl<M: MmioMut> EntropySources<M> {
    fn set_module_enable(&self, enable: u32) {
        self.es0.module_enable().write(|w| w.module_enable(enable));
        if let Some(sec) = &self.secondary {
            sec.es1.module_enable().write(|w| w.module_enable(enable));
        }
    }
}

#[inline(never)]
fn classify_entropy_src_alert(
    entropy_src: &entropy_src::RegisterBlock<RealMmioMut<'_>>,
) -> CaliptraError {
    let counts = entropy_src.alert_fail_counts().read();
    if counts.repcnt_fail_count() > 0 || counts.repcnts_fail_count() > 0 {
        CaliptraError::DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED
    } else if counts.adaptp_lo_fail_count() > 0
        || counts.adaptp_hi_fail_count() > 0
        || counts.adaptps_fail_count() > 0
    {
        CaliptraError::DRIVER_CSRNG_ADAPTP_HEALTH_CHECK_FAILED
    } else {
        CaliptraError::DRIVER_CSRNG_OTHER_HEALTH_CHECK_FAILED
    }
}

#[inline(never)]
fn check_one_hang(es: &entropy_src::RegisterBlock<RealMmioMut<'_>>) -> CaliptraResult<()> {
    if es.main_sm_state().read().main_sm_state() == ES_ALERT_HANG {
        return Err(classify_entropy_src_alert(es));
    }
    Ok(())
}

#[inline(never)]
fn poll_entropy_source(
    entropy_src: &entropy_src::RegisterBlock<RealMmioMut<'_>>,
) -> CaliptraResult<bool> {
    const CONT_HT_RUNNING: u32 = 0x1a2;
    const BOOT_PHASE_DONE: u32 = 0x8e;
    match entropy_src.main_sm_state().read().main_sm_state() {
        ES_ALERT_HANG => Err(classify_entropy_src_alert(entropy_src)),
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

pub(crate) const MULTIBIT_FALSE: u32 = MultiBitBool::False as u32;
pub(crate) const MULTIBIT_TRUE: u32 = MultiBitBool::True as u32;

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

/// Ensure the ES0 (and, in dual-iTRNG mode, ES1) entropy configurations are
/// cached in ROM persistent data.
///
/// On cold reset this reads CPTRA_iTRNG{,1}_ENTROPY_CONFIG_{0,1,2} and caches
/// the result in ROM persistent data; later resets reuse the cache written
/// by the same ROM. FMC and Runtime do not read this cache.
fn load_entropy_configurations(
    soc_ifc: &soc_ifc::RegisterBlock<RealMmio>,
    rom: &mut crate::persistent::RomPersistentData,
    dual: bool,
) -> CaliptraResult<()> {
    let cold_reset = matches!(reset_reason(), ResetReason::ColdReset);
    if !cold_reset
        && rom.entropy_cfg.configured != 0
        && (!dual || rom.es1_entropy_cfg.configured != 0)
    {
        return Ok(());
    }

    let (es0_cfg, es0_ext) = source_config(
        soc_ifc.cptra_i_trng_entropy_config_0().read(),
        soc_ifc.cptra_i_trng_entropy_config_1().read(),
        soc_ifc.cptra_i_trng_entropy_config_2().read(),
    );
    if dual {
        let (es1_cfg, es1_ext) = source_config(
            soc_ifc.cptra_i_trng1_entropy_config_0().read(),
            soc_ifc.cptra_i_trng1_entropy_config_1().read(),
            soc_ifc.cptra_i_trng1_entropy_config_2().read(),
        );
        // Combining requires two conditioned sources; do not accept a
        // characterization bypass in either one.
        if es0_ext.bypass() || es1_ext.bypass() {
            return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_BAD_STATE);
        }
        rom.es1_entropy_cfg = es1_cfg;
        rom.es1_entropy_cfg_extension = es1_ext;
    }

    rom.entropy_cfg = es0_cfg;
    rom.entropy_cfg_extension = es0_ext;
    Ok(())
}

/// Decode one source's CPTRA_iTRNG_ENTROPY_CONFIG_{0,1,2}. A zero field
/// selects the ROM default.
fn source_config(
    cfg0: soc_ifc::regs::EntropyConfig0ReadVal,
    cfg1: soc_ifc::regs::EntropyConfig1ReadVal,
    cfg2: soc_ifc::regs::EntropyConfig2ReadVal,
) -> (EntropyConfiguration, EntropyConfigurationExtension) {
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

    (
        EntropyConfiguration {
            configured: 1,
            alert_threshold: or_default(cfg1.alert_threshold(), DEFAULT_ALERT_THRESHOLD),
            health_test_window: window,
            repcnt_threshold: or_default(cfg1.repetition_count(), DEFAULT_REPCNT_THRESHOLD),
            adaptp_hi_threshold: hi,
            adaptp_lo_threshold: lo,
        },
        ext,
    )
}

/// The discriminants are the `CONF.RNG_BIT_ENABLE` encodings.
#[repr(u32)]
enum EntropySourceMode {
    SingleBit = MULTIBIT_TRUE,
    MultiChannel = MULTIBIT_FALSE,
}

struct HealthTestThresholds {
    repcnt: u32,
    adaptp_hi: u32,
    adaptp_lo: u32,
    repcnts: u32,
    adaptps: u32,
}

/// Program one entropy_src instance while it is disabled and unlocked.
///
/// Single-bit mode uses the per-lane tests (REPCNT, ADAPTP_HI/LO); multi-channel
/// mode uses the symbol tests (REPCNTS, ADAPTPS). The other set stays at its
/// never-failing reset value.
fn program_entropy_source(
    e: &entropy_src::RegisterBlock<RealMmioMut<'_>>,
    cfg: &EntropyConfiguration,
    ext: EntropyConfigurationExtension,
    lock: bool,
) {
    if e.module_enable().read().module_enable() == MULTIBIT_TRUE
        || !e.sw_regupd().read().sw_regupd()
    {
        return;
    }
    e.alert_threshold().write(|w| {
        w.alert_threshold(cfg.alert_threshold)
            .alert_threshold_inv(!cfg.alert_threshold & 0xffff)
    });
    e.health_test_windows()
        .write(|w| w.fips_window(cfg.health_test_window));

    let mode = if ext.rng_bit_enable() {
        EntropySourceMode::SingleBit
    } else {
        EntropySourceMode::MultiChannel
    };
    let thresholds = match mode {
        EntropySourceMode::SingleBit => HealthTestThresholds {
            repcnt: cfg.repcnt_threshold,
            adaptp_hi: cfg.adaptp_hi_threshold,
            adaptp_lo: cfg.adaptp_lo_threshold,
            repcnts: UNUSED_HI_THRESHOLD,
            adaptps: UNUSED_HI_THRESHOLD,
        },
        EntropySourceMode::MultiChannel => HealthTestThresholds {
            repcnt: UNUSED_HI_THRESHOLD,
            adaptp_hi: UNUSED_HI_THRESHOLD,
            adaptp_lo: UNUSED_LO_THRESHOLD,
            repcnts: cfg.repcnt_threshold,
            adaptps: cfg.adaptp_hi_threshold,
        },
    };
    e.repcnt_threshold()
        .write(|w| w.repcnt_threshold(thresholds.repcnt));
    e.adaptp_hi_threshold()
        .write(|w| w.adaptp_hi_threshold(thresholds.adaptp_hi));
    e.adaptp_lo_threshold()
        .write(|w| w.adaptp_lo_threshold(thresholds.adaptp_lo));
    e.repcnts_threshold()
        .write(|w| w.repcnts_threshold(thresholds.repcnts));
    e.adaptps_threshold()
        .write(|w| w.adaptps_threshold(thresholds.adaptps));

    e.conf().write(|w| {
        // Conditioning is enabled, but SoC-supplied thresholds are not an
        // approved qualification profile, so FIPS_FLAG stays false.
        w.fips_enable(MULTIBIT_TRUE)
            .fips_flag(MULTIBIT_FALSE)
            .entropy_data_reg_enable(MULTIBIT_FALSE)
            // Score lanes individually rather than summed.
            .threshold_scope(MULTIBIT_FALSE)
            .rng_bit_enable(mode as u32)
            .rng_bit_sel(ext.rng_bit_sel())
    });
    // The SoC may request bypass so entropy can be characterized without
    // conditioning. Dual-iTRNG mode rejects this before programming.
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

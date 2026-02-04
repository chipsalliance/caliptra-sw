/*++

Licensed under the Apache-2.0 license.

Inspired by OpenTitan's driver interface functions for the entropy_src and
CSRNG peripherals:
https://opentitan.org/book/sw/device/lib/dif/dif_entropy_src_h.html
https://opentitan.org/book/sw/device/lib/dif/dif_csrng_h.html

An overview of the entropy_src and CSRNG peripherals can be found at:
https://opentitan.org/book/hw/ip/entropy_src/index.html
https://opentitan.org/book/hw/ip/csrng/index.html

File Name:

    csrng.rs

Abstract:

    Software interface to the Cryptographically Secure Random Number Generator
    (CSRNG) peripheral.

--*/
use crate::persistent::EntropyConfiguration;
use crate::soc_ifc::reset_reason;
use crate::{wait, CaliptraError, CaliptraResult, PersistentDataAccessor, ResetReason};
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::{self, regs::AlertFailCountsReadVal, EntropySrcReg};
use caliptra_registers::soc_ifc::{self, SocIfcReg};

use core::mem::MaybeUninit;

// https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#command-description
pub const MAX_SEED_WORDS: usize = 12;
const WORDS_PER_BLOCK: usize = 4;

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
        persistent_data: PersistentDataAccessor,
    ) -> CaliptraResult<Self> {
        const FALSE: u32 = MultiBitBool::False as u32;
        const TRUE: u32 = MultiBitBool::True as u32;

        let mut result = Self { csrng, entropy_src };
        let e = result.entropy_src.regs_mut();

        // Configure and enable entropy_src if not already enabled.
        // If already enabled, assume it was configured correctly by a previous call.
        if e.module_enable().read().module_enable() == FALSE {
            // Configure entropy_src
            let entropy_cfg = read_entropy_configuration(&soc_ifc.regs(), persistent_data);
            set_health_check_thresholds(e, entropy_cfg);

            e.conf().write(|w| {
                w.fips_enable(TRUE)
                    .entropy_data_reg_enable(FALSE)
                    .threshold_scope(TRUE)
                    .rng_bit_enable(FALSE)
            });

            // We allow the SoC to set bypass mode so that entropy can be
            // characterized directly, without passing through conditioning.
            if (soc_ifc.regs().ss_strap_generic().at(2).read() >> 31) & 1 == 1 {
                e.entropy_control().modify(|w| w.es_type(TRUE));
            }
            e.module_enable().write(|w| w.module_enable(TRUE));
            check_for_alert_state(result.entropy_src.regs())?;

            // Lock entropy_src configuration if not in debug mode.
            // Per security model: ROM programs once, then locks permanently.
            // - SW_REGUPD: When cleared, configuration registers become read-only
            // In debug mode (debug_locked == false), leave unlocked for characterization.
            // We leave the module enable able to be turned off for potential power savings in runtime.
            if soc_ifc.regs().cptra_security_state().read().debug_locked() {
                let e = result.entropy_src.regs_mut();
                e.sw_regupd().modify(|w| w.sw_regupd(false));
            }
        }

        let c = result.csrng.regs_mut();

        if c.ctrl().read().enable() == FALSE {
            c.ctrl()
                .write(|w| w.enable(TRUE).sw_app_enable(TRUE).read_int_state(TRUE));
        }

        send_command(&mut result.csrng, Command::Uninstantiate)?;
        send_command(&mut result.csrng, Command::Instantiate(seed))?;

        Ok(result)
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
        check_for_alert_state(self.entropy_src.regs())?;

        send_command(
            &mut self.csrng,
            Command::Generate {
                num_128_bit_blocks: 12 / WORDS_PER_BLOCK,
            },
        )?;

        let mut result = MaybeUninit::<[u32; 12]>::uninit();
        let dest = result.as_mut_ptr() as *mut u32;
        unsafe {
            wait::until(|| self.csrng.regs().genbits_vld().read().genbits_vld());
            dest.add(0).write(self.csrng.regs().genbits().read());
            dest.add(1).write(self.csrng.regs().genbits().read());
            dest.add(2).write(self.csrng.regs().genbits().read());
            dest.add(3).write(self.csrng.regs().genbits().read());
            wait::until(|| self.csrng.regs().genbits_vld().read().genbits_vld());
            dest.add(4).write(self.csrng.regs().genbits().read());
            dest.add(5).write(self.csrng.regs().genbits().read());
            dest.add(6).write(self.csrng.regs().genbits().read());
            dest.add(7).write(self.csrng.regs().genbits().read());
            wait::until(|| self.csrng.regs().genbits_vld().read().genbits_vld());
            dest.add(8).write(self.csrng.regs().genbits().read());
            dest.add(9).write(self.csrng.regs().genbits().read());
            dest.add(10).write(self.csrng.regs().genbits().read());
            dest.add(11).write(self.csrng.regs().genbits().read());
            Ok(result.assume_init())
        }
    }

    pub fn reseed(&mut self, seed: Seed) -> CaliptraResult<()> {
        send_command(&mut self.csrng, Command::Reseed(seed))
    }

    pub fn update(&mut self, additional_data: &[u32]) -> CaliptraResult<()> {
        // if we are given too much data, do multiple updates
        for data in additional_data.chunks(MAX_SEED_WORDS) {
            send_command(&mut self.csrng, Command::Update(data))?;
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
        let _ = send_command(&mut self.csrng, Command::Uninstantiate);
    }
}

fn check_for_alert_state(
    entropy_src: entropy_src::RegisterBlock<ureg::RealMmio>,
) -> CaliptraResult<()> {
    // https://opentitan.org/book/hw/ip/entropy_src/doc/theory_of_operation.html#main-state-machine-diagram
    // https://github.com/chipsalliance/caliptra-rtl/blob/main/src/entropy_src/rtl/entropy_src_main_sm_pkg.sv
    const ALERT_HANG: u32 = 0x1fb;
    const CONT_HT_RUNNING: u32 = 0x1a2;
    const BOOT_PHASE_DONE: u32 = 0x8e;

    loop {
        match entropy_src.main_sm_state().read().main_sm_state() {
            ALERT_HANG => {
                let alert_counts = entropy_src.alert_fail_counts().read();

                if alert_counts.repcnt_fail_count() > 0 || alert_counts.repcnts_fail_count() > 0 {
                    return Err(CaliptraError::DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED);
                }

                if alert_counts.adaptp_lo_fail_count() > 0
                    || alert_counts.adaptp_hi_fail_count() > 0
                {
                    return Err(CaliptraError::DRIVER_CSRNG_ADAPTP_HEALTH_CHECK_FAILED);
                }

                return Err(CaliptraError::DRIVER_CSRNG_OTHER_HEALTH_CHECK_FAILED);
            }

            CONT_HT_RUNNING | BOOT_PHASE_DONE => {
                return Ok(());
            }

            _ => (),
        }
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

fn send_command(csrng: &mut CsrngReg, command: Command) -> CaliptraResult<()> {
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
    csrng.regs_mut().cmd_req().write(|w| {
        w.acmd(acmd)
            .clen(clen as u32)
            .flag0(flag0 as u32)
            .glen(glen as u32)
    });

    // Write optional extra words.
    for &word in extra_words {
        csrng.regs_mut().cmd_req().write(|_| word.into());
    }

    // Wait for command.
    loop {
        let reg = csrng.regs().sw_cmd_sts().read();

        // Order matters. Check for errors first.
        if reg.cmd_sts() != 0 || u32::from(csrng.regs().err_code().read()) != 0 {
            // TODO: Somehow convey additional error information found in
            // the ERR_CODE register.
            return Err(err);
        }

        // TODO: if the hardware is fixed to make the ack flag sticky, we should
        // check that as well before exiting the loop.
        if reg.cmd_rdy() {
            return Ok(());
        }
    }
}

fn read_entropy_configuration(
    soc_ifc: &soc_ifc::RegisterBlock<ureg::RealMmio>,
    mut persistent_data: PersistentDataAccessor,
) -> EntropyConfiguration {
    // Some of the entropy config registers are not lockable,
    // so we keep them in persistent storage so that they cannot
    // be maliciously modified later.
    let entropy_cfg = persistent_data.get_mut().rom.entropy_cfg.clone();
    let cold_reset = matches!(reset_reason(), ResetReason::ColdReset);
    // use the cached config only if we aren't in cold reset (assuming it has been configured)
    if !cold_reset && entropy_cfg.configured != 0 {
        return entropy_cfg;
    }

    // Configure alert threshold from CPTRA_ITRNG_ENTROPY_CONFIG_1[31:16]
    // Default alert threshold value
    const DEFAULT_ALERT_THRESHOLD: u32 = 2;

    let alert_threshold = soc_ifc.cptra_i_trng_entropy_config_1().read().rsvd();

    let alert_threshold = if alert_threshold == 0 {
        DEFAULT_ALERT_THRESHOLD
    } else {
        alert_threshold
    };

    // Configure health test windows from SS_STRAP_GENERIC[2][15:0]
    // This is the window size for all health tests.
    // This value is used when entropy is being tested in FIPS mode.
    // The default value is (2048 bits * 1 clock/4 bits);
    const DEFAULT_HEALTH_TEST_WINDOW: u32 = 512;

    let health_test_window = soc_ifc.ss_strap_generic().at(2).read() & 0xffff;

    let health_test_window = if health_test_window == 0 {
        DEFAULT_HEALTH_TEST_WINDOW
    } else {
        health_test_window
    };

    // Configure Repetition Count Test threshold

    // The Repetition Count test fails if:
    //  * An RNG wire repeats the same bit THRESHOLD times in a row.
    // See section 4.4.1 of NIST.SP.800-90B for more information of about this test.

    // If the SOC doesn't specify a repcnt threshold, use this default, which assumes a min-entropy of 1.
    const DEFAULT_REPCNT_THRESHOLD: u32 = 41;

    let repcnt_threshold = soc_ifc
        .cptra_i_trng_entropy_config_1()
        .read()
        .repetition_count();

    let repcnt_threshold = if repcnt_threshold == 0 {
        DEFAULT_REPCNT_THRESHOLD
    } else {
        repcnt_threshold
    };

    // The Adaptive Proportion test fails if:
    //  * Any window has more than the HI threshold of 1's; or,
    //  * Any window has less than the LO threshold of 1's.
    // See section 4.4.2 of NIST.SP.800-90B for more information of about this test.

    // If soc doesn't set the window size, then use these defaults.
    // Use 75% and 25% of the 2048 bit FIPS window size for the default HI and LO thresholds
    // respectively.
    //
    // This window value of 2048 comes from the OpenTitan documentation, since two noise
    // channels are used. https://opentitan.org/book/hw/ip/entropy_src/index.html#description
    const ADAPTP_WINDOW_SIZE_BITS: u32 = 2048;
    const ADAPTP_DEFAULT_HI: u32 = 3 * (ADAPTP_WINDOW_SIZE_BITS / 4);
    const ADAPTP_DEFAULT_LO: u32 = ADAPTP_WINDOW_SIZE_BITS / 4;

    let config0 = soc_ifc.cptra_i_trng_entropy_config_0().read();
    let adaptp_hi_threshold = config0.high_threshold();
    let adaptp_lo_threshold = config0.low_threshold();

    let adaptp_hi_threshold = if adaptp_hi_threshold == 0 {
        ADAPTP_DEFAULT_HI
    } else {
        adaptp_hi_threshold
    };

    let adaptp_lo_threshold = if adaptp_lo_threshold == 0 {
        ADAPTP_DEFAULT_LO
    } else {
        adaptp_lo_threshold
    };

    // ensure lo < hi by using defaults if hi >= lo
    let (adaptp_hi_threshold, adaptp_lo_threshold) = if adaptp_hi_threshold <= adaptp_lo_threshold {
        (ADAPTP_DEFAULT_HI, ADAPTP_DEFAULT_LO)
    } else {
        (adaptp_hi_threshold, adaptp_lo_threshold)
    };

    let entropy_cfg = EntropyConfiguration {
        configured: 1,
        alert_threshold,
        health_test_window,
        repcnt_threshold,
        adaptp_hi_threshold,
        adaptp_lo_threshold,
    };
    // save for later resets
    persistent_data.get_mut().rom.entropy_cfg = entropy_cfg.clone();
    entropy_cfg
}

/// Configure thresholds for the NIST health checks.
fn set_health_check_thresholds(
    e: entropy_src::RegisterBlock<ureg::RealMmioMut>,
    entropy_cfg: EntropyConfiguration,
) {
    // configure the alert threshold and its inverse as required
    e.alert_threshold().write(|w| {
        w.alert_threshold(entropy_cfg.alert_threshold)
            .alert_threshold_inv((!entropy_cfg.alert_threshold) & 0xffff)
    });

    e.health_test_windows()
        .write(|w| w.fips_window(entropy_cfg.health_test_window));

    e.repcnt_thresholds()
        .write(|w| w.fips_thresh(entropy_cfg.repcnt_threshold));

    e.repcnts_thresholds()
        .write(|w| w.fips_thresh(entropy_cfg.repcnt_threshold));

    e.adaptp_hi_thresholds()
        .write(|w| w.fips_thresh(entropy_cfg.adaptp_hi_threshold));

    e.adaptp_lo_thresholds()
        .write(|w| w.fips_thresh(entropy_cfg.adaptp_lo_threshold));
}

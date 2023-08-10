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
use crate::{wait, CaliptraError, CaliptraResult};
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::{self, regs::AlertFailCountsReadVal, EntropySrcReg};
use core::{iter::FusedIterator, num::NonZeroUsize};

// https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#command-description
const MAX_SEED_WORDS: usize = 12;
const MAX_GENERATE_BLOCKS: usize = 4096;
const WORDS_PER_GENERATE_BLOCK: usize = 4;

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
    pub fn new(csrng: CsrngReg, entropy_src: EntropySrcReg) -> CaliptraResult<Self> {
        Self::with_seed(csrng, entropy_src, Seed::EntropySrc)
    }

    /// # Safety
    ///
    /// The caller MUST ensure that the CSRNG peripheral is in a state where new
    /// entropy is accessible via the generate command.
    pub unsafe fn assume_initialized(
        csrng: caliptra_registers::csrng::CsrngReg,
        entropy_src: caliptra_registers::entropy_src::EntropySrcReg,
    ) -> Self {
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
        seed: Seed,
    ) -> CaliptraResult<Self> {
        const FALSE: u32 = MultiBitBool::False as u32;
        const TRUE: u32 = MultiBitBool::True as u32;

        let mut result = Self { csrng, entropy_src };
        let e = result.entropy_src.regs_mut();

        // Configure and enable entropy_src if needed.
        if e.module_enable().read().module_enable() == FALSE {
            set_health_check_thresholds(e);

            e.conf().write(|w| {
                w.fips_enable(TRUE)
                    .entropy_data_reg_enable(FALSE)
                    .threshold_scope(TRUE)
                    .rng_bit_enable(FALSE)
            });
            e.module_enable().write(|w| w.module_enable(TRUE));
            check_for_alert_state(result.entropy_src.regs())?;
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

    /// Returns an iterator over `num_words` random [`u32`]s.
    ///
    /// This function will round up to the nearest multiple of four words.
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
    /// let num_words = NonZeroUsize::new(1).unwrap();
    /// let mut random_words = csrng.generate(num_words)?;
    ///
    /// // Rounds up to nearest multiple of four.
    /// assert_eq!(random_words.len(), 4);
    ///
    /// for word in random_words {
    ///     // Do something with `word`.
    /// }
    /// ```
    pub fn generate(&mut self, num_words: NonZeroUsize) -> CaliptraResult<Iter> {
        check_for_alert_state(self.entropy_src.regs())?;

        // Round up to nearest multiple of 128-bit block.
        let num_128_bit_blocks = (num_words.get() + 3) / 4;
        let num_words = num_128_bit_blocks * WORDS_PER_GENERATE_BLOCK;

        send_command(&mut self.csrng, Command::Generate { num_128_bit_blocks })?;

        Ok(Iter {
            csrng: &mut self.csrng,
            num_words_left: num_words,
        })
    }

    pub fn reseed(&mut self, seed: Seed) -> CaliptraResult<()> {
        send_command(&mut self.csrng, Command::Reseed(seed))
    }

    pub fn update(&mut self, additional_data: &[u32]) -> CaliptraResult<()> {
        send_command(&mut self.csrng, Command::Update(additional_data))
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
    const ALERT_HANG: u32 = 0x15c;
    const CONT_HT_RUNNING: u32 = 0x1a2;
    const BOOT_PHASE_DONE: u32 = 0x8e;

    loop {
        match entropy_src.main_sm_state().read().main_sm_state() {
            ALERT_HANG => {
                let alert_counts = entropy_src.alert_fail_counts().read();

                if alert_counts.repcnt_fail_count() > 0 {
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

/// An iterator over random [`u32`]s.
///
/// This struct is created by the [`generate`] method on [`Csrng`].
///
/// [`generate`]: Csrng::generate
pub struct Iter<'a> {
    // It's not clear what reseeding or updating the CSRNG state would do
    // to an existing generate request. Prevent these operations from happening
    // concurrent to this iterator's life.
    csrng: &'a mut CsrngReg,
    num_words_left: usize,
}

impl Iterator for Iter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let csrng = self.csrng.regs();
        if self.num_words_left == 0 {
            None
        } else {
            if self.num_words_left % WORDS_PER_GENERATE_BLOCK == 0 {
                // Wait for CSRNG to generate next block of 4 words.
                wait::until(|| csrng.genbits_vld().read().genbits_vld());
            }

            self.num_words_left -= 1;

            Some(csrng.genbits().read())
        }
    }
}

impl ExactSizeIterator for Iter<'_> {
    fn len(&self) -> usize {
        self.num_words_left
    }
}

impl FusedIterator for Iter<'_> {}

impl Drop for Iter<'_> {
    fn drop(&mut self) {
        // Exhaust this generate request.
        for _ in self {}
    }
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
            glen = num_128_bit_blocks.min(MAX_GENERATE_BLOCKS);
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
        if reg.cmd_sts() || u32::from(csrng.regs().err_code().read()) != 0 {
            // TODO: Somehow convey additional error information found in
            // the ERR_CODE register.
            return Err(err);
        }

        if reg.cmd_rdy() {
            return Ok(());
        }
    }
}

fn set_health_check_thresholds(e: entropy_src::RegisterBlock<ureg::RealMmioMut>) {
    // Configure thresholds for the two approved NIST health checks:
    //  1. Repetition Count Test
    //  2. Adaptive Proportion Test
    //
    // The Repetition Count test fails if:
    //  * An RNG wire repeats the same bit THRESHOLD times in a row.
    //
    // We pick as our threshold a cutoff value C such that the probability that
    // a C consecutive-run of the most likely bit is less than some "very small"
    // probability. The idea is that a catastrophic failure in the entropy
    // source would easily trip this threshold, but a healthy entropy source,
    // over the course of normal operation, would "almost certainly" not.
    //
    // We calculate the cutoff value using the formula in 4.4.1 of NIST SP
    // 800-90B:
    //
    // C = 1 + ceil(-lg(false_positive_probability) / min_entropy_estimate)
    //
    // where the false_positive_probability is 2^-40 (one false positive for
    // every 128 GiB harvested).
    // Therefore, C = 1 + ceil(40 / min_entropy_estimate)
    //
    // TODO: We need a min-entropy estimate of the physical source to calculate
    // more accurate thresholds. For now, we'll use a min-entropy estimate of 1,
    // which assumes that a '0' and '1' bit are equally likely to be produced by
    // the itrng. Alternatively, parameterize thresholds in `Csrng::new()` and
    // `Csrng::with_seed()`.
    const REPETITION_COUNT_THRESHOLD: u32 = 41;

    e.repcnt_thresholds()
        .write(|w| w.fips_thresh(REPETITION_COUNT_THRESHOLD));

    // The Adaptive Proportion test fails if:
    //  * Any window has more than the HI threshold of 1's; or,
    //  * Any window has less than the LO threshold of 1's.
    //
    // Given a window size W and a min-entropy estimate (H) of the physical
    // source, we'd expect each window to have W/2^H of the most likely bit and
    // W*(1 - 1/2^H) of the least likely bit.
    //
    // TODO: Adjust thresholds based on min-entropy. Since we don't have
    // a min-entropy estimate or know which bit is most likely, we'll use a
    // conservative 75% and 25% of the window size for the HI and LO thresholds
    // respectively.
    const TRNG_BITS_PER_CYCLE: u32 = 4;
    let window_size_bits = e.health_test_windows().read().fips_window() * TRNG_BITS_PER_CYCLE;
    let threshold_hi = 3 * (window_size_bits / 4);
    let threshold_lo = window_size_bits / 4;
    e.adaptp_hi_thresholds()
        .write(|w| w.fips_thresh(threshold_hi));
    e.adaptp_lo_thresholds()
        .write(|w| w.fips_thresh(threshold_lo));
}

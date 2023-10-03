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
use caliptra_registers::soc_ifc::{self, SocIfcReg};

use core::array;

// https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#command-description
const MAX_SEED_WORDS: usize = 12;
const WORDS_PER_BLOCK: usize = 4;

struct IsCompleteBlocks<const NUM_WORDS: usize>;

impl<const NUM_WORDS: usize> IsCompleteBlocks<NUM_WORDS> {
    const ASSERT: () = assert!(
        NUM_WORDS != 0 && NUM_WORDS % WORDS_PER_BLOCK == 0,
        "NUM_WORDS must be non-zero and divisible by WORDS_PER_BLOCK"
    );
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
    ) -> CaliptraResult<Self> {
        Self::with_seed(csrng, entropy_src, soc_ifc, Seed::EntropySrc)
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
    ) -> CaliptraResult<Self> {
        const FALSE: u32 = MultiBitBool::False as u32;
        const TRUE: u32 = MultiBitBool::True as u32;

        let mut result = Self { csrng, entropy_src };
        let e = result.entropy_src.regs_mut();

        // Configure and enable entropy_src if needed.
        if e.module_enable().read().module_enable() == FALSE {
            set_health_check_thresholds(e, soc_ifc.regs());

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
        self.generate()
    }

    /// Return 16 randomly generated [`u32`]s.
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
    /// let random_words: [u32; 16] = csrng.generate()?;
    ///
    /// for word in random_words {
    ///     // Do something with `word`.
    /// }
    /// ```
    pub fn generate16(&mut self) -> CaliptraResult<[u32; 16]> {
        self.generate()
    }

    fn generate<const N: usize>(&mut self) -> CaliptraResult<[u32; N]> {
        #[allow(clippy::let_unit_value)]
        let _ = IsCompleteBlocks::<N>::ASSERT;

        check_for_alert_state(self.entropy_src.regs())?;

        send_command(
            &mut self.csrng,
            Command::Generate {
                num_128_bit_blocks: N / WORDS_PER_BLOCK,
            },
        )?;

        Ok(array::from_fn(|i| {
            if i % WORDS_PER_BLOCK == 0 {
                // Wait for CSRNG to generate next block of words.
                wait::until(|| self.csrng.regs().genbits_vld().read().genbits_vld());
            }

            self.csrng.regs().genbits().read()
        }))
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

fn set_health_check_thresholds(
    e: entropy_src::RegisterBlock<ureg::RealMmioMut>,
    soc_ifc: soc_ifc::RegisterBlock<ureg::RealMmio>,
) {
    // Configure thresholds for the two approved NIST health checks:
    //  1. Repetition Count Test
    //  2. Adaptive Proportion Test

    {
        // The Repetition Count test fails if:
        //  * An RNG wire repeats the same bit THRESHOLD times in a row.
        // See section 4.4.1 of NIST.SP.800-90B for more information of about this test.

        // If the SOC doesn't specify a threshold, use this default, which assumes a min-entropy of 1.
        const DEFAULT_THRESHOLD: u32 = 41;

        let threshold = soc_ifc
            .cptra_i_trng_entropy_config_1()
            .read()
            .repetition_count();

        e.repcnt_thresholds().write(|w| {
            w.fips_thresh(if threshold == 0 {
                DEFAULT_THRESHOLD
            } else {
                threshold
            })
        });
    }

    {
        // The Adaptive Proportion test fails if:
        //  * Any window has more than the HI threshold of 1's; or,
        //  * Any window has less than the LO threshold of 1's.
        // See section 4.4.2 of NIST.SP.800-90B for more information of about this test.

        // Use 75% and 25% of the 2048 bit FIPS window size for the default HI and LO thresholds
        // respectively.
        const WINDOW_SIZE_BITS: u32 = 2048;
        const DEFAULT_HI: u32 = 3 * (WINDOW_SIZE_BITS / 4);
        const DEFAULT_LO: u32 = WINDOW_SIZE_BITS / 4;

        // TODO: What to do if HI <= LO?
        let threshold_hi = soc_ifc
            .cptra_i_trng_entropy_config_0()
            .read()
            .high_threshold();

        let threshold_lo = soc_ifc
            .cptra_i_trng_entropy_config_0()
            .read()
            .low_threshold();

        e.adaptp_hi_thresholds().write(|w| {
            w.fips_thresh(if threshold_hi == 0 {
                DEFAULT_HI
            } else {
                threshold_hi
            })
        });

        e.adaptp_lo_thresholds().write(|w| {
            w.fips_thresh(if threshold_lo == 0 {
                DEFAULT_LO
            } else {
                threshold_lo
            })
        });
    }
}

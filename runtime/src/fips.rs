/*++

Licensed under the Apache-2.0 license.

File Name:

    fips.rs

Abstract:

    File contains FIPS module and FIPS self test.

--*/
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_common::cprintln;
use caliptra_drivers::Aes;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::Ecc384;
use caliptra_drivers::Hmac;
use caliptra_drivers::KeyVault;
use caliptra_drivers::Mldsa87;
use caliptra_drivers::Sha256;
use caliptra_drivers::Sha2_512_384;
use caliptra_drivers::Sha2_512_384Acc;
use zeroize::Zeroize;

use crate::Drivers;

pub struct FipsModule;

/// Command-count scheduling state; a zero threshold disables autonomous tests.
pub(crate) struct SelfTestSchedule {
    threshold: u32,
    completed_commands: u32,
}

impl SelfTestSchedule {
    /// Decode the input-wire snapshot supplied at RT startup.
    /// Later input changes cannot alter this schedule; RT must restart to resample them.
    pub(crate) fn new(config: u32) -> CaliptraResult<Self> {
        // Core CPTRA_GENERIC_INPUT_WIRES[1]: enable[0], count[16:1], scale[18:17].
        // Bits [31:19] are reserved and must be zero when enabled.
        const ENABLE_MASK: u32 = 1;
        const COUNT_SHIFT: u32 = 1;
        const COUNT_MASK: u32 = 0xffff;
        const SCALE_SHIFT: u32 = 17;
        const SCALE_MASK: u32 = 0x3;
        const MULTIPLIER_LOG2_STEP: u32 = 4;
        const RESERVED_MASK: u32 =
            !(ENABLE_MASK | (COUNT_MASK << COUNT_SHIFT) | (SCALE_MASK << SCALE_SHIFT));

        let threshold = if config & ENABLE_MASK == 0 {
            // Disabled configurations ignore all other fields.
            0
        } else {
            let count = (config >> COUNT_SHIFT) & COUNT_MASK;
            // An enabled policy must be enforceable: reject unsupported builds,
            // a zero command count, or undefined configuration bits.
            if !cfg!(feature = "fips_self_test") || count == 0 || config & RESERVED_MASK != 0 {
                return Err(CaliptraError::RUNTIME_INVALID_SELF_TEST_CONFIG);
            }
            let scale = (config >> SCALE_SHIFT) & SCALE_MASK;
            // Scale is a base-16 exponent: 0/1/2/3 select x1/x16/x256/x4096.
            // Shifting by 4 * scale computes count * 16^scale.
            // Even the maximum 65535 * 4096 fits in u32.
            count << (MULTIPLIER_LOG2_STEP * scale)
        };
        Ok(Self {
            threshold,
            completed_commands: 0,
        })
    }

    pub(crate) fn command_completed(&mut self) {
        // Saturate while a due test waits for an idle mailbox; further commands
        // must not wrap the count or clear the pending trigger.
        if self.completed_commands < self.threshold {
            self.completed_commands += 1;
        }
    }

    pub(crate) fn is_due(&self) -> bool {
        self.threshold != 0 && self.completed_commands == self.threshold
    }

    /// A successful manual or autonomous suite starts a new command-count window.
    pub(crate) fn test_passed(&mut self) {
        self.completed_commands = 0;
    }
}

/// Fips command handler.
impl FipsModule {
    /// Clear data structures in DCCM.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn zeroize(env: &mut Drivers) {
        unsafe {
            // Zeroize the crypto blocks.
            Mldsa87::zeroize();
            Aes::zeroize();
            Ecc384::zeroize();
            Hmac::zeroize();
            Sha256::zeroize();
            Sha2_512_384::zeroize();
            Sha2_512_384Acc::zeroize();

            // Zeroize the key vault.
            KeyVault::zeroize();

            // Lock the SHA Accelerator.
            Sha2_512_384Acc::lock();
        }

        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            caliptra_drivers::FipsTestHook::halt_if_hook_set(
                caliptra_drivers::FipsTestHook::HALT_SHUTDOWN_RT,
            )
        };

        env.persistent_data.get_mut().zeroize();
    }
}

#[cfg(feature = "fips_self_test")]
pub mod fips_self_test_cmd {
    use super::*;
    use crate::RtBootStatus::{RtFipSelfTestComplete, RtFipSelfTestStarted};
    use caliptra_cfi_lib::cfi_assert_eq_8_words;
    use caliptra_common::{verifier::FirmwareImageVerificationEnv, FMC_SIZE, RUNTIME_SIZE};
    use caliptra_drivers::{ResetReason, ShaAccLockState};
    use caliptra_image_types::{ImageTocEntry, RomInfo};
    use caliptra_image_verify::ImageVerifier;
    use zerocopy::IntoBytes;

    // Helper function to create a slice from a memory region
    unsafe fn create_slice(toc: &ImageTocEntry) -> &'static [u8] {
        let ptr = toc.load_addr as *mut u8;
        core::slice::from_raw_parts(ptr, toc.size as usize)
    }
    pub enum SelfTestStatus {
        Idle,
        InProgress(fn(&mut Drivers) -> CaliptraResult<()>),
        Done,
    }

    #[cfg_attr(feature = "cfi", cfi_mod_fn)]
    fn copy_and_verify_image(env: &mut Drivers) -> CaliptraResult<()> {
        env.mbox.write_cmd(0)?;
        env.mbox.set_dlen(
            env.persistent_data.get().manifest1.size
                + env.persistent_data.get().manifest1.fmc.size
                + env.persistent_data.get().manifest1.runtime.size,
        )?;
        env.mbox
            .copy_bytes_to_mbox(env.persistent_data.get().manifest1.as_bytes())?;

        let fmc_toc = &env.persistent_data.get().manifest1.fmc;
        let rt_toc = &env.persistent_data.get().manifest1.runtime;

        if fmc_toc.size > FMC_SIZE {
            return Err(CaliptraError::RUNTIME_INVALID_FMC_SIZE);
        }
        if rt_toc.size > RUNTIME_SIZE {
            return Err(CaliptraError::RUNTIME_INVALID_RUNTIME_SIZE);
        }

        let fmc = unsafe { create_slice(fmc_toc) };
        let rt = unsafe { create_slice(rt_toc) };

        env.mbox.copy_bytes_to_mbox(fmc.as_bytes())?;
        env.mbox.copy_bytes_to_mbox(rt.as_bytes())?;

        let mut venv = FirmwareImageVerificationEnv {
            sha256: &mut env.sha256,
            sha2_512_384: &mut env.sha2_512_384,
            sha2_512_384_acc: &mut env.sha2_512_384_acc,
            soc_ifc: &mut env.soc_ifc,
            ecc384: &mut env.ecc384,
            mldsa87: &mut env.mldsa87,
            data_vault: &env.persistent_data.get().data_vault,
            pcr_bank: &mut env.pcr_bank,
            image: env.mbox.raw_mailbox_contents(),
            dma: &env.dma,
            persistent_data: env.persistent_data.get(),
        };

        let mut verifier = ImageVerifier::new(&mut venv);
        let _info = verifier.verify(
            &env.persistent_data.get().manifest1,
            env.persistent_data.get().manifest1.size
                + env.persistent_data.get().manifest1.fmc.size
                + env.persistent_data.get().manifest1.runtime.size,
            ResetReason::UpdateReset,
        )?;
        cprintln!("[rt] Verify complete");
        Ok(())
    }

    #[cfg_attr(feature = "cfi", cfi_mod_fn)]
    pub(crate) fn execute(env: &mut Drivers) -> CaliptraResult<()> {
        caliptra_drivers::report_boot_status(RtFipSelfTestStarted.into());
        cprintln!("[rt] FIPS self test");
        execute_kats(env)?;
        rom_integrity_test(env)?;
        copy_and_verify_image(env)?;
        caliptra_drivers::report_boot_status(RtFipSelfTestComplete.into());
        Ok(())
    }

    /// Execute KAT for cryptographic algorithms implemented in H/W.
    fn execute_kats(env: &mut Drivers) -> CaliptraResult<()> {
        let mut kats_env = caliptra_kat::KatsEnv {
            // SHA1 Engine
            sha1: &mut env.sha1,

            // sha256
            sha256: &mut env.sha256,

            // SHA2-512/384 Engine
            sha2_512_384: &mut env.sha2_512_384,

            // SHA2-512/384 Accelerator
            sha2_512_384_acc: &mut env.sha2_512_384_acc,

            // Hmac-512/384 Engine
            hmac: &mut env.hmac,

            // Cryptographically Secure Random Number Generator
            trng: &mut env.trng,

            // LMS Engine
            lms: &mut env.lms,

            // MLDSA87 Engine
            mldsa87: &mut env.mldsa87,

            // Ecc384 Engine
            ecc384: &mut env.ecc384,

            // AES Engine,
            aes: &mut env.aes,

            // SHA Acc Lock State
            sha_acc_lock_state: ShaAccLockState::NotAcquired,
        };

        caliptra_kat::execute_kat(&mut kats_env)?;
        Ok(())
    }

    #[cfg_attr(feature = "cfi", cfi_mod_fn)]
    fn rom_integrity_test(env: &mut Drivers) -> CaliptraResult<()> {
        // Extract the expected has from the fht.
        let rom_info = env.persistent_data.get().fht.rom_info_addr.get()?;

        // WARNING: It is undefined behavior to dereference a zero (null) pointer in
        // rust code. This is only safe because the dereference is being done by an
        // an assembly routine ([`caliptra_ureg::opt_riscv::copy_16_words`]) rather
        // than dereferencing directly in Rust.
        #[allow(clippy::zero_ptr)]
        let rom_start = 0 as *const [u32; 16];

        let n_blocks =
            env.persistent_data.get().fht.rom_info_addr.get()? as *const RomInfo as usize / 64;

        let mut digest = unsafe { env.sha256.digest_blocks_raw(rom_start, n_blocks)? };
        if digest.0 != rom_info.sha256_digest {
            digest.zeroize();
            cprintln!("ROM integrity test failed");
            return Err(CaliptraError::ROM_INTEGRITY_FAILURE);
        } else {
            cfi_assert_eq_8_words(&digest.0, &rom_info.sha256_digest);
        }
        digest.zeroize();

        // Run digest function and compare with expected hash.
        Ok(())
    }
}
pub struct FipsShutdownCmd;
impl FipsShutdownCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(env: &mut Drivers) -> CaliptraResult<usize> {
        FipsModule::zeroize(env);
        env.is_shutdown = true;

        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autonomous_self_test_disabled_by_default() {
        for config in [0, !1] {
            let mut schedule = SelfTestSchedule::new(config).unwrap();
            for _ in 0..100 {
                schedule.command_completed();
                assert!(!schedule.is_due());
            }
        }
    }

    #[cfg(feature = "fips_self_test")]
    #[test]
    fn autonomous_self_test_threshold_and_reset() {
        let mut schedule = SelfTestSchedule::new(1 | (3 << 1)).unwrap();
        for _ in 0..2 {
            schedule.command_completed();
            assert!(!schedule.is_due());
        }
        schedule.command_completed();
        assert!(schedule.is_due());
        for _ in 0..100 {
            schedule.command_completed();
            assert!(schedule.is_due());
        }
        assert_eq!(schedule.completed_commands, 3);
        schedule.test_passed();
        assert!(!schedule.is_due());
        assert_eq!(schedule.completed_commands, 0);
    }

    #[cfg(feature = "fips_self_test")]
    #[test]
    fn autonomous_self_test_multiplier_encoding() {
        for (encoding, multiplier) in [(0, 1), (1, 16), (2, 256), (3, 4096)] {
            let mut schedule = SelfTestSchedule::new(1 | (2 << 1) | (encoding << 17)).unwrap();
            assert_eq!(schedule.threshold, 2 * multiplier);
            for _ in 0..(2 * multiplier - 1) {
                schedule.command_completed();
                assert!(!schedule.is_due());
            }
            schedule.command_completed();
            assert!(schedule.is_due());
        }
    }

    #[cfg(feature = "fips_self_test")]
    #[test]
    fn autonomous_self_test_maximum_threshold() {
        let mut schedule = SelfTestSchedule::new(0x7_ffff).unwrap();
        assert_eq!(schedule.threshold, 268_431_360);
        schedule.completed_commands = schedule.threshold - 1;
        schedule.command_completed();
        schedule.command_completed();
        assert!(schedule.is_due());
        assert_eq!(schedule.completed_commands, 268_431_360);
    }

    #[test]
    fn autonomous_self_test_rejects_invalid_configuration() {
        for config in [1, 1 | (3 << 17), 3 | (1 << 19), u32::MAX] {
            assert!(matches!(
                SelfTestSchedule::new(config),
                Err(CaliptraError::RUNTIME_INVALID_SELF_TEST_CONFIG)
            ));
        }
    }

    #[cfg(not(feature = "fips_self_test"))]
    #[test]
    fn autonomous_self_test_rejects_unsupported_enable() {
        assert!(matches!(
            SelfTestSchedule::new(3),
            Err(CaliptraError::RUNTIME_INVALID_SELF_TEST_CONFIG)
        ));
    }
}

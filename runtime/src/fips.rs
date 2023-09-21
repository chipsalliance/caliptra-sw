// Licensed under the Apache-2.0 license

use caliptra_common::cprintln;
use caliptra_common::mailbox_api::{MailboxResp, MailboxRespHeader};
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::Ecc384;
use caliptra_drivers::Hmac384;
use caliptra_drivers::KeyVault;
use caliptra_drivers::Sha256;
use caliptra_drivers::Sha384;
use caliptra_drivers::Sha384Acc;
use caliptra_registers::mbox::enums::MboxStatusE;

use crate::Drivers;

pub struct FipsModule;

/// Fips command handler.
impl FipsModule {
    /// Clear data structures in DCCM.
    fn zeroize(env: &mut Drivers) {
        unsafe {
            // Zeroize the crypto blocks.
            Ecc384::zeroize();
            Hmac384::zeroize();
            Sha256::zeroize();
            Sha384::zeroize();
            Sha384Acc::zeroize();

            // Zeroize the key vault.
            KeyVault::zeroize();

            // Lock the SHA Accelerator.
            Sha384Acc::lock();
        }
        env.persistent_data.get_mut().zeroize();
    }
}

#[cfg(feature = "fips_self_test")]
pub mod fips_self_test_cmd {
    use super::*;
    use crate::RtBootStatus::{RtFipSelfTestComplete, RtFipSelfTestStarted};
    use caliptra_common::HexBytes;
    use caliptra_common::{
        verifier::FirmwareImageVerificationEnv, FMC_ORG, FMC_SIZE, RUNTIME_ORG, RUNTIME_SIZE,
    };
    use caliptra_drivers::{ResetReason, ShaAccLockState};
    use caliptra_image_types::RomInfo;
    use caliptra_image_verify::ImageVerifier;
    use zerocopy::AsBytes;

    // Helper function to create a slice from a memory region
    unsafe fn create_slice(org: u32, size: usize) -> &'static [u8] {
        let ptr = org as *mut u8;
        core::slice::from_raw_parts(ptr, size)
    }
    pub enum SelfTestStatus {
        Idle,
        InProgress(fn(&mut Drivers) -> CaliptraResult<()>),
        Done,
    }

    fn copy_and_verify_image(env: &mut Drivers) -> CaliptraResult<()> {
        env.mbox.write_cmd(0)?;
        env.mbox.set_dlen(
            env.persistent_data.get().manifest1.size
                + env.persistent_data.get().manifest1.fmc.size
                + env.persistent_data.get().manifest1.runtime.size,
        );
        env.mbox
            .copy_bytes_to_mbox(env.persistent_data.get().manifest1.as_bytes())?;

        let fmc_size = env.persistent_data.get().manifest1.fmc.size;
        if fmc_size > FMC_SIZE {
            return Err(CaliptraError::RUNTIME_INVALID_FMC_SIZE);
        }
        let fmc = unsafe { create_slice(FMC_ORG, fmc_size as usize) };
        env.mbox.copy_bytes_to_mbox(fmc.as_bytes())?;

        let runtime_size = env.persistent_data.get().manifest1.runtime.size;
        if runtime_size > RUNTIME_SIZE {
            return Err(CaliptraError::RUNTIME_INVALID_RUNTIME_SIZE);
        }
        let rt = unsafe { create_slice(RUNTIME_ORG, runtime_size as usize) };
        env.mbox.copy_bytes_to_mbox(rt.as_bytes())?;

        let mut venv = FirmwareImageVerificationEnv {
            sha256: &mut env.sha256,
            sha384: &mut env.sha384,
            sha384_acc: &mut env.sha384_acc,
            soc_ifc: &mut env.soc_ifc,
            ecc384: &mut env.ecc384,
            data_vault: &mut env.data_vault,
            pcr_bank: &mut env.pcr_bank,
        };

        let mut verifier = ImageVerifier::new(&mut venv);
        let _info = verifier.verify(
            &env.persistent_data.get().manifest1,
            env.persistent_data.get().manifest1.size
                + env.persistent_data.get().manifest1.fmc.size
                + env.persistent_data.get().manifest1.runtime.size,
            ResetReason::UpdateReset,
        )?;
        env.mbox.unlock();
        cprintln!("[rt] Verify complete");
        Ok(())
    }

    pub(crate) fn execute(env: &mut Drivers) -> CaliptraResult<()> {
        caliptra_drivers::report_boot_status(RtFipSelfTestStarted.into());
        cprintln!("[rt] FIPS self test");
        rom_integrity_test(env)?;
        execute_kats(env)?;
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

            // SHA2-384 Engine
            sha384: &mut env.sha384,

            // SHA2-384 Accelerator
            sha384_acc: &mut env.sha384_acc,

            // Hmac384 Engine
            hmac384: &mut env.hmac384,

            /// Cryptographically Secure Random Number Generator
            trng: &mut env.trng,

            // LMS Engine
            lms: &mut env.lms,

            /// Ecc384 Engine
            ecc384: &mut env.ecc384,

            /// SHA Acc Lock State
            sha_acc_lock_state: ShaAccLockState::NotAcquired,
        };

        caliptra_kat::execute_kat(&mut kats_env)?;
        Ok(())
    }

    fn rom_integrity_test(env: &mut Drivers) -> CaliptraResult<()> {
        // Extract the expected has from the fht.
        let rom_info = env.persistent_data.get().fht.rom_info_addr.get()?;

        // WARNING: It is undefined behavior to dereference a zero (null) pointer in
        // rust code. This is only safe because the dereference is being done by an
        // an assembly routine ([`ureg::opt_riscv::copy_16_words`]) rather
        // than dereferencing directly in Rust.
        #[allow(clippy::zero_ptr)]
        let rom_start = 0 as *const [u32; 16];

        let n_blocks =
            env.persistent_data.get().fht.rom_info_addr.get()? as *const RomInfo as usize / 64;

        let digest = unsafe { env.sha256.digest_blocks_raw(rom_start, n_blocks)? };
        cprintln!("ROM Digest: {}", HexBytes(&<[u8; 32]>::from(digest)));
        if digest.0 != rom_info.sha256_digest {
            cprintln!("ROM integrity test failed");
            return Err(CaliptraError::ROM_INTEGRITY_FAILURE);
        }

        // Run digest function and compare with expected hash.
        Ok(())
    }
}
pub struct FipsShutdownCmd;
impl FipsShutdownCmd {
    pub(crate) fn execute(env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        FipsModule::zeroize(env);
        env.mbox.set_status(MboxStatusE::CmdComplete);
        env.is_shutdown = true;

        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }
}

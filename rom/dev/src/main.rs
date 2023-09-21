/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(feature = "fake-rom", allow(unused_imports))]

use crate::{lock::lock_registers, print::HexBytes};
use caliptra_cfi_lib::CfiCounter;
use caliptra_registers::soc_ifc::SocIfcReg;
use core::hint::black_box;

use caliptra_drivers::{
    cprintln, report_fw_error_fatal, report_fw_error_non_fatal, CaliptraError, Ecc384, Hmac384,
    KeyVault, Mailbox, ResetReason, Sha256, Sha384, Sha384Acc, ShaAccLockState, SocIfc,
};
use caliptra_error::CaliptraResult;
use caliptra_image_types::RomInfo;
use caliptra_kat::KatsEnv;
use rom_env::RomEnv;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!(concat!(
    env!("OUT_DIR"),
    "/start_preprocessed.S"
)));

mod exception;
mod fht;
mod flow;
mod fuse;
mod kat;
mod lock;
mod pcr;
mod rom_env;
mod wdt;

use caliptra_drivers::printer as print;

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
Running Caliptra ROM ...
"#;

extern "C" {
    static CALIPTRA_ROM_INFO: RomInfo;
}

#[no_mangle]
pub extern "C" fn rom_entry() -> ! {
    cprintln!("{}", BANNER);

    let mut env = match unsafe { rom_env::RomEnv::new_from_registers() } {
        Ok(env) => env,
        Err(e) => handle_fatal_error(e.into()),
    };

    if !cfg!(feature = "no-cfi") {
        cprintln!("[state] CFI Enabled");
        CfiCounter::reset(&mut env.trng);
    } else {
        cprintln!("[state] CFI Disabled");
    }

    let _lifecyle = match env.soc_ifc.lifecycle() {
        caliptra_drivers::Lifecycle::Unprovisioned => "Unprovisioned",
        caliptra_drivers::Lifecycle::Manufacturing => "Manufacturing",
        caliptra_drivers::Lifecycle::Production => "Production",
        caliptra_drivers::Lifecycle::Reserved2 => "Unknown",
    };
    cprintln!("[state] LifecycleState = {}", _lifecyle);

    if cfg!(feature = "fake-rom")
        && env.soc_ifc.lifecycle() == caliptra_drivers::Lifecycle::Production
    {
        cprintln!("Fake ROM in Production lifecycle prohibited");
        handle_fatal_error(CaliptraError::ROM_GLOBAL_FAKE_ROM_IN_PRODUCTION.into());
    }

    cprintln!(
        "[state] DebugLocked = {}",
        if env.soc_ifc.debug_locked() {
            "Yes"
        } else {
            "No"
        }
    );

    // Start the watchdog timer
    wdt::start_wdt(&mut env.soc_ifc);

    let reset_reason = env.soc_ifc.reset_reason();

    if !cfg!(feature = "fake-rom") {
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

            /// SHA Acc lock state.
            /// SHA Acc is guaranteed to be locked on Cold and Warm Resets;
            /// On an Update Reset, it is expected to be unlocked.
            /// Not having it unlocked will result in a fatal error.
            sha_acc_lock_state: if reset_reason == ResetReason::UpdateReset {
                ShaAccLockState::NotAcquired
            } else {
                ShaAccLockState::AssumedLockState
            },
        };
        let result = run_fips_tests(&mut kats_env);
        if let Err(err) = result {
            handle_fatal_error(err.into());
        }
    }

    if let Err(err) = flow::run(&mut env) {
        //
        // For the update reset case, when we fail the image validation
        // we will need to continue to jump to the FMC after
        // reporting the error in the registers.
        //
        if reset_reason == ResetReason::UpdateReset {
            handle_non_fatal_error(err.into());
        } else {
            handle_fatal_error(err.into());
        }
    }

    // Stop the watchdog timer.
    wdt::stop_wdt(&mut env.soc_ifc);

    // Lock the datavault registers.
    lock_registers(&mut env, reset_reason);

    // Reset the CFI counter.
    if !cfg!(feature = "no-cfi") {
        CfiCounter::corrupt();
    }

    #[cfg(not(feature = "no-fmc"))]
    launch_fmc(&mut env);

    #[cfg(feature = "no-fmc")]
    caliptra_drivers::ExitCtrl::exit(0);
}

fn run_fips_tests(env: &mut KatsEnv) -> CaliptraResult<()> {
    let rom_info = unsafe { &CALIPTRA_ROM_INFO };
    rom_integrity_test(env, &rom_info.sha256_digest)?;
    kat::execute_kat(env)
}

fn rom_integrity_test(env: &mut KatsEnv, expected_digest: &[u32; 8]) -> CaliptraResult<()> {
    // WARNING: It is undefined behavior to dereference a zero (null) pointer in
    // rust code. This is only safe because the dereference is being done by an
    // an assembly routine ([`ureg::opt_riscv::copy_16_words`]) rather
    // than dereferencing directly in Rust.
    #[allow(clippy::zero_ptr)]
    let rom_start = 0 as *const [u32; 16];

    let n_blocks = unsafe { &CALIPTRA_ROM_INFO as *const RomInfo as usize / 64 };
    let digest = unsafe { env.sha256.digest_blocks_raw(rom_start, n_blocks)? };
    cprintln!("ROM Digest: {}", HexBytes(&<[u8; 32]>::from(digest)));
    if digest.0 != *expected_digest {
        cprintln!("ROM integrity test failed");
        return Err(CaliptraError::ROM_INTEGRITY_FAILURE);
    }
    Ok(())
}

fn launch_fmc(env: &mut RomEnv) -> ! {
    // Function is defined in start.S
    extern "C" {
        fn exit_rom(entry: u32) -> !;
    }

    // Get the fmc entry point from data vault
    let entry = env.data_vault.fmc_entry_point();

    cprintln!("[exit] Launching FMC @ 0x{:08X}", entry);

    // Exit ROM and jump to specified entry point
    unsafe { exit_rom(entry) }
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X} ra=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc,
        exception.ra
    );

    {
        let mut soc_ifc = unsafe { SocIfcReg::new() };
        let soc_ifc = soc_ifc.regs_mut();
        let ext_info = soc_ifc.cptra_fw_extended_error_info();
        ext_info.at(0).write(|_| exception.mcause);
        ext_info.at(1).write(|_| exception.mscause);
        ext_info.at(2).write(|_| exception.mepc);
        ext_info.at(3).write(|_| exception.ra);
    }

    handle_fatal_error(CaliptraError::ROM_GLOBAL_EXCEPTION.into());
}

#[no_mangle]
#[inline(never)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };

    // If the NMI was fired by caliptra instead of the uC, this register
    // contains the reason(s)
    let err_interrupt_status = u32::from(
        soc_ifc
            .regs()
            .intr_block_rf()
            .error_internal_intr_r()
            .read(),
    );

    cprintln!(
        "NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X} ra=0x{:08X} error_internal_intr_r={:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc,
        exception.ra,
        err_interrupt_status,
    );

    {
        let soc_ifc = soc_ifc.regs_mut();
        let ext_info = soc_ifc.cptra_fw_extended_error_info();
        ext_info.at(0).write(|_| exception.mcause);
        ext_info.at(1).write(|_| exception.mscause);
        ext_info.at(2).write(|_| exception.mepc);
        ext_info.at(3).write(|_| exception.ra);
        ext_info.at(4).write(|_| err_interrupt_status);
    }

    // Check if the NMI was due to WDT expiry.
    let mut error = CaliptraError::ROM_GLOBAL_NMI;

    let wdt_status = soc_ifc.regs().cptra_wdt_status().read();
    if wdt_status.t1_timeout() || wdt_status.t2_timeout() {
        cprintln!("WDT Expired");
        error = CaliptraError::ROM_GLOBAL_WDT_EXPIRED;
    }

    handle_fatal_error(error.into());
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
fn rom_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("Panic!!");
    panic_is_possible();

    handle_fatal_error(CaliptraError::ROM_GLOBAL_PANIC.into());
}

fn handle_non_fatal_error(code: u32) {
    cprintln!("ROM Non-Fatal Error: 0x{:08X}", code);
    report_fw_error_non_fatal(code);
}

#[no_mangle]
extern "C" fn cfi_panic_handler(code: u32) -> ! {
    cprintln!("CFI Panic code=0x{:08X}", code);

    handle_fatal_error(code);
}

#[allow(clippy::empty_loop)]
fn handle_fatal_error(code: u32) -> ! {
    cprintln!("ROM Fatal Error: 0x{:08X}", code);
    report_fw_error_fatal(code);
    // Populate the non-fatal error code too; if there was a
    // non-fatal error stored here before we don't want somebody
    // mistakenly thinking that was the reason for their mailbox
    // command failure.
    report_fw_error_non_fatal(code);

    unsafe {
        // Zeroize the crypto blocks.
        Ecc384::zeroize();
        Hmac384::zeroize();
        Sha256::zeroize();
        Sha384::zeroize();
        Sha384Acc::zeroize();

        // Zeroize the key vault.
        KeyVault::zeroize();

        // Stop the watchdog timer.
        // Note: This is an idempotent operation.
        SocIfc::stop_wdt1();
    }

    loop {
        unsafe {
            // SoC firmware might be stuck waiting for Caliptra to finish
            // executing this pending mailbox transaction. Notify them that
            // we've failed.
            Mailbox::abort_pending_soc_to_uc_transactions();

            // The SHA accelerator may still be in use by the SoC;
            // try to lock it as soon as possible.
            //
            // WDT is disabled at this point so there is no issue
            // of it firing due to the lock taking too long.
            Sha384Acc::try_lock();
        }
    }
}

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}

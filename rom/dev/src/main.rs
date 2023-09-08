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
use core::hint::black_box;

use caliptra_drivers::{
    cprintln, report_fw_error_fatal, report_fw_error_non_fatal, CaliptraError, Ecc384, Hmac384,
    KeyVault, Mailbox, ResetReason, RomAddr, Sha256, Sha384, Sha384Acc, SocIfc,
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

    let rom_info = unsafe { &CALIPTRA_ROM_INFO };

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
        };
        let result = run_fips_tests(&mut kats_env, rom_info);
        if let Err(err) = result {
            handle_fatal_error(err.into());
        }
    }

    let reset_reason = env.soc_ifc.reset_reason();

    let result = flow::run(&mut env);
    match result {
        Ok(Some(mut fht)) => {
            fht.rom_info_addr = RomAddr::from(rom_info);
            fht::store(&mut env, fht);
        }
        Ok(None) => {}
        Err(err) => {
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
    }

    // Stop the watchdog timer.
    // [TODO] Reset the watchdog timer and let FMC take ownership of it.
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

fn run_fips_tests(env: &mut KatsEnv, rom_info: &RomInfo) -> CaliptraResult<()> {
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
        "EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    handle_fatal_error(CaliptraError::ROM_GLOBAL_EXCEPTION.into());
}

#[no_mangle]
#[inline(never)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    handle_fatal_error(CaliptraError::ROM_GLOBAL_NMI.into());
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

        // Lock the SHA Accelerator.
        Sha384Acc::lock();

        // Stop the watchdog timer.
        // Note: This is an idempotent operation.
        SocIfc::stop_wdt1();
    }

    loop {
        // SoC firmware might be stuck waiting for Caliptra to finish
        // executing this pending mailbox transaction. Notify them that
        // we've failed.
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}

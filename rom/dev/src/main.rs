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
#![cfg_attr(feature = "fips-test-hooks", allow(dead_code))]
#![allow(unused_imports)]
#![allow(dead_code)]
use crate::lock::lock_cold_reset_reg;
use crate::{lock::lock_registers, print::HexBytes};
use caliptra_cfi_lib::{cfi_assert_eq, CfiCounter};
use caliptra_common::RomBootStatus::{KatComplete, KatStarted};
use caliptra_common::{handle_fatal_error, RomBootStatus};
use caliptra_drivers::{
    cprintln, hmac_kdf, report_boot_status, report_fw_error_non_fatal, Aes, AesKey, Array4x16,
    Array4x4, AxiAddr, CaliptraError, DeobfuscationEngine, Dma, DmaWriteOrigin,
    DmaWriteTransaction, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage,
    KeyWriteArgs, LEArray4x8, MlKem1024, MlKem1024Message, MlKem1024MessageSource, MlKem1024Seeds,
    MlKem1024SharedKey, MlKem1024SharedKeyOut, ResetReason, ShaAccLockState, SocIfc, Trng,
};
use caliptra_error::CaliptraResult;
use caliptra_image_types::RomInfo;
use caliptra_kat::KatsEnv;
use caliptra_kat::*;
use caliptra_registers::abr::AbrReg;
use caliptra_registers::aes::AesReg;
use caliptra_registers::aes_clp::AesClpReg;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::doe::DoeReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use core::hint::black_box;
use rom_env::RomEnv;
use zerocopy::{FromBytes, IntoBytes};
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!(concat!(
    env!("OUT_DIR"),
    "/start_preprocessed.S"
)));

mod crypto;
mod exception;
mod fht;
mod flow;
mod fuse;
mod key_ladder;
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

/// Populates a KV slot with a known constant.
pub fn populate_slot(
    hmac: &mut Hmac,
    trng: &mut Trng,
    slot: KeyId,
    usage: KeyUsage,
) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Array4x16(&Array4x16::default()),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(slot, usage).into(),
        HmacMode::Hmac512,
    )
}

pub struct TestRegisters {
    pub soc: SocIfc,
    pub hmac: Hmac,
    pub aes: Aes,
    pub trng: Trng,
    pub dma: Dma,
    pub doe: DeobfuscationEngine,
}

impl Default for TestRegisters {
    fn default() -> Self {
        let soc_ifc = unsafe { SocIfcReg::new() };
        let soc = SocIfc::new(soc_ifc);
        let hmac = unsafe { Hmac::new(HmacReg::new()) };
        let aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };
        let trng = unsafe {
            Trng::new(
                CsrngReg::new(),
                EntropySrcReg::new(),
                SocIfcTrngReg::new(),
                &SocIfcReg::new(),
            )
            .unwrap()
        };
        let dma = Dma::default();
        let doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };

        Self {
            soc,
            hmac,
            aes,
            trng,
            dma,
            doe,
        }
    }
}

pub fn kv_release(test_regs: &mut TestRegisters) {
    let fuse_addr = 0xa401_0200u64;
    cprintln!("[demo] OCP LOCK key release addr: {:08x}", fuse_addr);
    let kv_release_size = 64;

    let write_addr = AxiAddr::from(fuse_addr);
    let write_transaction = DmaWriteTransaction {
        write_addr,
        fixed_addr: false,
        length: kv_release_size,
        origin: DmaWriteOrigin::KeyVault,
        aes_mode: false,
        aes_gcm: false,
    };
    test_regs.dma.setup_dma_write(write_transaction, 0);
    test_regs.dma.wait_for_dma_complete();
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
        let mut entropy_gen = || env.trng.generate4();
        CfiCounter::reset(&mut entropy_gen);
        CfiCounter::reset(&mut entropy_gen);
        CfiCounter::reset(&mut entropy_gen);
    } else {
        cprintln!("[state] CFI Disabled");
    }

    // Check if TRNG is correctly sourced as per hw config.
    validate_trng_config(&mut env);

    report_boot_status(RomBootStatus::CfiInitialized.into());

    let reset_reason = env.soc_ifc.reset_reason();

    // Lock the Cold Reset registers since they need to remain locked on an Update or Warm reset.
    if reset_reason != ResetReason::ColdReset {
        lock_cold_reset_reg(&mut env);
    }

    let lifecyle = match env.soc_ifc.lifecycle() {
        caliptra_drivers::Lifecycle::Unprovisioned => "Unprovisioned",
        caliptra_drivers::Lifecycle::Manufacturing => "Manufacturing",
        caliptra_drivers::Lifecycle::Production => "Production",
        caliptra_drivers::Lifecycle::Reserved2 => "Unknown",
    };
    cprintln!("[state] LifecycleState = {}", lifecyle);

    if let Err(err) = crate::flow::debug_unlock::debug_unlock(&mut env) {
        handle_fatal_error(err.into());
    }

    // UDS programming.
    if let Err(err) = crate::flow::UdsProgrammingFlow::program_uds(&mut env) {
        handle_fatal_error(err.into());
    }

    if cfg!(feature = "fake-rom")
        && (env.soc_ifc.lifecycle() == caliptra_drivers::Lifecycle::Production)
        && !(env.soc_ifc.prod_en_in_fake_mode())
    {
        cprintln!("Fake ROM in Prod lifecycle disabled");
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

    if env.soc_ifc.ocp_lock_enabled() {
        cprintln!("[ROM] OCP-LOCK Supported");
    } else {
        cprintln!("[ROM] OCP-LOCK Unsupported");
    }

    // Set the ROM version
    let rom_info = unsafe { &CALIPTRA_ROM_INFO };
    if !cfg!(feature = "fake-rom") {
        env.soc_ifc.set_rom_fw_rev_id(rom_info.version);
    } else {
        env.soc_ifc.set_rom_fw_rev_id(0xFFFF);
    }

    // Start the watchdog timer
    wdt::start_wdt(&mut env.soc_ifc);

    cprintln!(
        r"  ______     ______ .______       __        ______     ______  __  ___     _______   _______ .___  ___.   ______   "
    );
    cprintln!(
        r" /  __  \   /      ||   _  \     |  |      /  __  \   /      ||  |/  /    |       \ |   ____||   \/   |  /  __  \  "
    );
    cprintln!(
        r"|  |  |  | |  ,----'|  |_)  |    |  |     |  |  |  | |  ,----'|  '  /     |  .--.  ||  |__   |  \  /  | |  |  |  | "
    );
    cprintln!(
        r"|  |  |  | |  |     |   ___/     |  |     |  |  |  | |  |     |    <      |  |  |  ||   __|  |  |\/|  | |  |  |  | "
    );
    cprintln!(
        r"|  `--'  | |  `----.|  |         |  `----.|  `--'  | |  `----.|  .  \     |  '--'  ||  |____ |  |  |  | |  `--'  | "
    );
    cprintln!(
        r" \______/   \______|| _|         |_______| \______/   \______||__|\__\    |_______/ |_______||__|  |__|  \______/  "
    );
    cprintln!(
        r"                                                                                                                   "
    );

    let mut test_regs = TestRegisters::default();

    cprintln!(
        "[demo] OCP LOCK enabled? {}",
        test_regs.soc.ocp_lock_enabled()
    );

    if !test_regs.soc.ocp_lock_enabled() {
        cprintln!("[demo] OCP LOCK not enabled, skipping demo");
        loop {}
    }

    pub const DOE_TEST_IV: [u32; 4] = [0xc6b407a2, 0xd119a37d, 0xb7a5bdeb, 0x26214aed];

    cprintln!(
        "[demo] OCP LOCK Decrypt HEK seed from with IV {} into slot 22",
        HexBytes(DOE_TEST_IV.as_bytes())
    );

    test_regs
        .doe
        .decrypt_hek_seed(&Array4x4::from(DOE_TEST_IV), KeyId::KeyId22)
        .unwrap();

    const ENCRYPTED_MEK: [u8; 64] = [
        0xa5, 0x30, 0x8a, 0x37, 0xfa, 0x5d, 0xdd, 0x82, 0xee, 0x36, 0xf1, 0x7f, 0x0a, 0x96, 0x0a,
        0xc2, 0xbc, 0xe6, 0xde, 0x51, 0xdc, 0xca, 0xa8, 0x69, 0x8e, 0x6b, 0x9b, 0x36, 0xf3, 0xe5,
        0x75, 0xfd, 0x55, 0x87, 0x81, 0x23, 0x49, 0x15, 0x4a, 0x12, 0x82, 0xd9, 0x03, 0x01, 0xe6,
        0x34, 0xdb, 0xc1, 0x26, 0x5e, 0x85, 0x81, 0x5e, 0x38, 0xc6, 0x90, 0xf9, 0x08, 0xe2, 0x2a,
        0x18, 0x37, 0x6e, 0x6f,
    ];

    let cdi_slot = HmacKey::Key(KeyReadArgs::new(KeyId::KeyId3));
    let mdk_slot = HmacTag::Key(KeyWriteArgs::from(KeyWriteArgs::new(
        KeyId::KeyId16,
        KeyUsage::default().set_aes_key_en(),
    )));

    cprintln!("[demo] Populating slot 3");

    populate_slot(
        &mut test_regs.hmac,
        &mut test_regs.trng,
        KeyId::KeyId3,
        KeyUsage::default().set_hmac_key_en(),
    )
    .unwrap();

    cprintln!("[demo] Deriving MDK into slot 16");

    hmac_kdf(
        &mut test_regs.hmac,
        cdi_slot,
        b"OCP_LOCK_MDK",
        None,
        &mut test_regs.trng,
        mdk_slot,
        HmacMode::Hmac512,
    )
    .unwrap();

    // If you uncomment this, then aes_256_ecb_decrypt_kv succeeds
    // populate_slot(
    //     &mut test_regs.hmac,
    //     &mut test_regs.trng,
    //     KeyId::KeyId16,
    //     KeyUsage::default().set_hmac_key_en(),
    // )
    // .unwrap();

    cprintln!("[demo] Populating slot 3");
    let hek_seed = test_regs.soc.fuse_bank().ocp_hek_seed();

    let cdi_slot = HmacKey::Key(KeyReadArgs::new(KeyId::KeyId3));
    let hek_slot = HmacTag::Key(KeyWriteArgs::from(KeyWriteArgs::new(
        KeyId::KeyId22,
        KeyUsage::default().set_hmac_key_en(),
    )));

    populate_slot(
        &mut test_regs.hmac,
        &mut test_regs.trng,
        KeyId::KeyId3,
        KeyUsage::default().set_hmac_key_en(),
    )
    .unwrap();

    cprintln!("[demo] Deriving HEK into slot 16");

    hmac_kdf(
        &mut test_regs.hmac,
        cdi_slot,
        b"OCP_LOCK_HEK", // TODO: Use real label from spec.
        Some(hek_seed.as_bytes()),
        &mut test_regs.trng,
        hek_slot,
        HmacMode::Hmac512,
    )
    .unwrap();

    if test_regs.soc.ocp_lock_get_lock_in_progress() {
        cprintln!("[demo] OCP LOCK in progress already!");
        loop {}
    }

    cprintln!("[demo] OCP LOCK set in progress");
    test_regs.soc.ocp_lock_set_lock_in_progress();

    if !test_regs.soc.ocp_lock_get_lock_in_progress() {
        cprintln!("[demo] OCP LOCK not in progress");
        loop {}
    }

    cprintln!(
        "[demo] OCP LOCK decrypting encrypted MEK: {}",
        HexBytes(&ENCRYPTED_MEK)
    );

    if let Err(e) = test_regs.aes.aes_256_ecb_decrypt_kv(&ENCRYPTED_MEK) {
        cprintln!(
            "[demo] OCP LOCK error decrypting encrypted MEK: {}",
            u32::from(e)
        );
    }

    cprintln!("[demo] OCP LOCK releasing key");

    kv_release(&mut test_regs);

    cprintln!("[demo] OCP LOCK key release complete");

    if true {
        loop {}
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

    // Lock the datavault registers.
    lock_registers(&mut env, reset_reason);

    // Reset the CFI counter.
    if !cfg!(feature = "no-cfi") {
        CfiCounter::corrupt();
    }

    // FIPS test hooks mode does not allow handoff to FMC to prevent incorrect/accidental usage
    #[cfg(feature = "fips-test-hooks")]
    handle_fatal_error(CaliptraError::ROM_GLOBAL_FIPS_HOOKS_ROM_EXIT.into());

    #[cfg(not(any(feature = "no-fmc", feature = "fips-test-hooks")))]
    launch_fmc(&mut env);

    #[cfg(feature = "no-fmc")]
    caliptra_drivers::ExitCtrl::exit(0);
}

fn run_fips_tests(env: &mut KatsEnv) -> CaliptraResult<()> {
    report_boot_status(KatStarted.into());

    cprintln!("[kat] SHA2-256");
    Sha256Kat::default().execute(env.sha256)?;

    #[cfg(feature = "fips-test-hooks")]
    unsafe {
        caliptra_drivers::FipsTestHook::halt_if_hook_set(
            caliptra_drivers::FipsTestHook::HALT_SELF_TESTS,
        )
    };

    // ROM integrity check needs SHA2-256 KAT to be executed first per FIPS requirement AS10.20.
    let rom_info = unsafe { &CALIPTRA_ROM_INFO };
    rom_integrity_test(env, &rom_info.sha256_digest)?;

    caliptra_kat::execute_kat(env)?;

    report_boot_status(KatComplete.into());

    Ok(())
}

fn rom_integrity_test(env: &mut KatsEnv, expected_digest: &[u32; 8]) -> CaliptraResult<()> {
    // WARNING: It is undefined behavior to dereference a zero (null) pointer in
    // rust code. This is only safe because the dereference is being done by an
    // an assembly routine ([`ureg::opt_riscv::copy_16_words`]) rather
    // than dereferencing directly in Rust.
    #[allow(clippy::zero_ptr)]
    let rom_start = 0 as *const [u32; 16];

    let n_blocks = unsafe { &CALIPTRA_ROM_INFO as *const RomInfo as usize / 64 };
    let mut digest = unsafe { env.sha256.digest_blocks_raw(rom_start, n_blocks)? };
    cprintln!("ROM Digest: {}", HexBytes(&<[u8; 32]>::from(digest)));
    if digest.0 != *expected_digest {
        digest.zeroize();
        cprintln!("ROM integrity test failed");
        return Err(CaliptraError::ROM_INTEGRITY_FAILURE);
    }
    digest.zeroize();
    Ok(())
}

fn launch_fmc(env: &mut RomEnv) -> ! {
    // Function is defined in start.S
    extern "C" {
        fn exit_rom(entry: u32) -> !;
    }

    // Get the fmc entry point from data vault
    let entry = env.persistent_data.get().data_vault.fmc_entry_point();

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
    cprintln!("[ROM] CFI Panic code=0x{:08X}", code);

    handle_fatal_error(code);
}

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}

#[inline(always)]
fn validate_trng_config(env: &mut RomEnv) {
    // NOTE: The usage of non-short-circuiting boolean operations (| and &) is
    // explicit here, and necessary to prevent the compiler from inserting a ton
    // of glitch-susceptible jumps into the generated code.

    cfi_assert_eq(
        env.soc_ifc.hw_config_internal_trng()
            & (!env.soc_ifc.mfg_flag_rng_unavailable() | env.soc_ifc.debug_locked()),
        matches!(env.trng, Trng::Internal(_)),
    );
    cfi_assert_eq(
        !env.soc_ifc.hw_config_internal_trng()
            & (!env.soc_ifc.mfg_flag_rng_unavailable() | env.soc_ifc.debug_locked()),
        matches!(env.trng, Trng::External(_)),
    );
    cfi_assert_eq(
        env.soc_ifc.mfg_flag_rng_unavailable() & !env.soc_ifc.debug_locked(),
        matches!(env.trng, Trng::MfgMode()),
    );
    cfi_assert_eq(
        env.soc_ifc.hw_config_internal_trng()
            & (!env.soc_ifc.mfg_flag_rng_unavailable() | env.soc_ifc.debug_locked()),
        matches!(env.trng, Trng::Internal(_)),
    );
    cfi_assert_eq(
        !env.soc_ifc.hw_config_internal_trng()
            & (!env.soc_ifc.mfg_flag_rng_unavailable() | env.soc_ifc.debug_locked()),
        matches!(env.trng, Trng::External(_)),
    );
    cfi_assert_eq(
        env.soc_ifc.mfg_flag_rng_unavailable() & !env.soc_ifc.debug_locked(),
        matches!(env.trng, Trng::MfgMode()),
    );
}

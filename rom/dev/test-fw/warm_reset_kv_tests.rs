// Licensed under the Apache-2.0 license

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(feature = "std")]
pub fn main() {}

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("../src/start.S"));

#[path = "../src/exception.rs"]
mod exception;

use caliptra_drivers::{cprintln, ExitCtrl};

#[no_mangle]
#[inline(never)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    ExitCtrl::exit(1);
}

#[no_mangle]
#[inline(never)]
#[cfg(not(feature = "std"))]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    ExitCtrl::exit(1);
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
fn handle_panic(pi: &core::panic::PanicInfo) -> ! {
    if let Some(loc) = pi.location() {
        cprintln!("Panic at file {} line {}", loc.file(), loc.line())
    }
    ExitCtrl::exit(1);
}

#[no_mangle]
#[cfg(not(feature = "std"))]
extern "C" fn cfi_panic_handler(code: u32) -> ! {
    caliptra_test_harness::println!("[test] CFI Panic code=0x{:08X}", code);

    caliptra_drivers::report_fw_error_fatal(0xdead2);

    caliptra_drivers::ExitCtrl::exit(u32::MAX)
}

#[no_mangle]
#[cfg(not(feature = "std"))]
pub extern "C" fn rom_entry() -> ! {
    use caliptra_cfi_lib::CfiCounter;
    use caliptra_drivers::{
        cprintln, printer::HexBytes, Aes, AesKey, AesOperation, ExitCtrl, Hmac, HmacKey, HmacMode,
        KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, ResetReason, SocIfc, Trng,
    };
    use caliptra_registers::hmac::HmacReg;
    use caliptra_registers::{aes::AesReg, aes_clp::AesClpReg};
    use caliptra_registers::{
        csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg,
        soc_ifc_trng::SocIfcTrngReg,
    };

    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    // Init CFI
    let mut entropy_gen = || trng.generate4();
    CfiCounter::reset(&mut entropy_gen);

    let mut aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });
    let reset_reason = soc_ifc.reset_reason();
    let key = [1u8; 48];
    let zero = [0u8; 48];

    match reset_reason {
        ResetReason::ColdReset => {
            // first run, we put a key in the KV
            cprintln!("Writing key to KV");
            hmac384
                .hmac(
                    HmacKey::Array4x12(&key.into()).into(),
                    (&zero).into(),
                    &mut trng,
                    KeyWriteArgs::new(KeyId::KeyId7, KeyUsage::default().set_aes_key_en()).into(),
                    HmacMode::Hmac384,
                )
                .unwrap();

            // AES ECB encrypt the zero block with the KV key
            let mut ciphertext = [0u8; 16];
            aes.aes_256_ecb(
                AesKey::KV(KeyReadArgs::new(KeyId::KeyId7)),
                AesOperation::Encrypt,
                &[0u8; 16],
                &mut ciphertext,
            )
            .unwrap();

            cprintln!("Cold reset AES ciphertext: {}", HexBytes(&ciphertext));

            // indicate to test that we can be reset now
            let mut soc_ifc = unsafe { SocIfcReg::new() };
            soc_ifc.regs_mut().cptra_boot_status().write(|_| 1);
            loop {}
        }
        ResetReason::WarmReset => {
            let mut ciphertext = [0u8; 16];
            aes.aes_256_ecb(
                AesKey::KV(caliptra_drivers::KeyReadArgs::new(KeyId::KeyId7)),
                AesOperation::Encrypt,
                &[0u8; 16],
                &mut ciphertext,
            )
            .unwrap();

            cprintln!("Warm reset AES ciphertext: {}", HexBytes(&ciphertext));
            let expected_ciphertext: [u8; 16] = [
                0x07, 0x8E, 0xBC, 0xA6, 0x9F, 0xAF, 0x36, 0x61, 0xA7, 0xBC, 0x50, 0x70, 0x0B, 0x4D,
                0x7B, 0x79,
            ];
            if ciphertext == expected_ciphertext {
                ExitCtrl::exit(0)
            } else {
                ExitCtrl::exit(1)
            }
        }
        _ => {
            cprintln!("Unexpected reset reason");
            ExitCtrl::exit(1)
        }
    }
}

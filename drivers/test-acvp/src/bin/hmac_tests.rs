/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_tests.rs

Abstract:

    File contains ACVP test cases for the HMAC-384 KDF (SP 800-108).

    The vector under test is supplied out-of-band in `stimulus/current.txt`,
    which is rewritten by the host-side runner before each invocation:

        line 1: hex-encoded key (48 bytes)
        line 2: hex-encoded label

    The label is fixed input data chosen by the implementation rather than
    supplied by the ACVP vector set, so the runner generates it and records it
    alongside the response.

    The derived key is reported over UART as `HMAC384KDF:<hex byte>` lines, one
    byte per line, for the runner to scrape.

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{hmac_kdf, Array4x12, Hmac, HmacMode, PersistentDataAccessor, Trng};
use caliptra_kat::{Hmac384KdfKat, Hmac512KdfKat};
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::test_suite;

const HMAC384_HASH_SIZE: usize = 48;

/// Largest label accepted, in bytes. The runner currently emits 16.
const MAX_LABEL_SIZE: usize = 256;

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(hex: &str, buf: &mut [u8]) -> Option<usize> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return None;
    }
    let n = hex.len() / 2;
    if n > buf.len() {
        return None;
    }
    for i in 0..n {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        buf[i] = (hi << 4) | lo;
    }
    Some(n)
}

// test_kat_384 MUST be run first; it initializes CFI.
fn test_kat_384() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
        .unwrap()
    };

    // Init CFI
    let mut entropy_gen = || {
        trng.generate4()
            .map_err(|e| caliptra_cfi_lib::CfiError(u32::from(e)))
    };
    CfiCounter::reset(&mut entropy_gen);

    assert!(Hmac384KdfKat::default()
        .execute(&mut hmac384, &mut trng)
        .is_ok());
}

fn test_kat_512() {
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
        .unwrap()
    };

    assert!(Hmac512KdfKat::default()
        .execute(&mut hmac, &mut trng)
        .is_ok());
}

fn test_kdf_acvp() {
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let hex_key = lines.next().unwrap().trim();
    let hex_label = lines.next().unwrap().trim();

    let mut key_buf = [0u8; HMAC384_HASH_SIZE];
    let mut label_buf = [0u8; MAX_LABEL_SIZE];
    hex_decode(hex_key, &mut key_buf).unwrap();
    let label_len = hex_decode(hex_label, &mut label_buf).unwrap();

    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
        .unwrap()
    };

    let mut out_buf = Array4x12::default();

    hmac_kdf(
        &mut hmac,
        (&Array4x12::from(&key_buf)).into(),
        &label_buf[..label_len],
        None,
        &mut trng,
        (&mut out_buf).into(),
        HmacMode::Hmac384,
    )
    .unwrap();

    let out = <[u8; HMAC384_HASH_SIZE]>::from(out_buf);
    for byte in out.iter() {
        println!("HMAC384KDF:{:02X}", byte);
    }
}

test_suite! {
    test_kat_384,
    test_kat_512,
    test_kdf_acvp,
}

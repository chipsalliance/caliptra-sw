/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_tests.rs

Abstract:

    File contains CAVP/ACVP test cases for HMAC-384 KDF

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{hmac_kdf, Array4x12, Hmac, HmacMode, Trng};
use caliptra_kat::{Hmac384KdfKat, Hmac512KdfKat};
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::{self, test_suite};

const HMAC384_HASH_SIZE: usize = 48;

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

// test_kat_384 MUST be run first to initialize CFI.
fn test_kat_384() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let mut entropy_gen = || trng.generate4();
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
        )
        .unwrap()
    };

    assert!(Hmac512KdfKat::default()
        .execute(&mut hmac, &mut trng)
        .is_ok());
}

fn test_kdf_acvp() {
    // stimulus/current.txt format (two lines):
    //   line 1: hex-encoded key (48 bytes)
    //   line 2: hex-encoded label
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let hex_key = lines.next().unwrap().trim();
    let hex_label = lines.next().unwrap().trim();

    let mut key_buf = [0u8; HMAC384_HASH_SIZE];
    let mut label_buf = [0u8; 256];
    hex_decode(hex_key, &mut key_buf).unwrap();
    let label_len = hex_decode(hex_label, &mut label_buf).unwrap();

    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
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

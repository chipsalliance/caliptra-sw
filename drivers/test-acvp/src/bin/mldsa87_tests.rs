/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa87_tests.rs

Abstract:

    File contains ACVP test cases for ML-DSA-87 (KEYGEN / SIGGEN / SIGVER).

    The vector under test is supplied out-of-band in `stimulus/current.txt`,
    which is rewritten by the host-side runner before each invocation. The
    first line selects the operation:

        MLDSA_KEYGEN
          line 2: hex seed (32 bytes)

        MLDSA_SIGGEN
          line 2: hex private key (4896 bytes)
          line 3: hex message

        MLDSA_SIGVER
          line 2: hex public key (2592 bytes)
          line 3: hex message
          line 4: hex signature (4627 bytes)

    Keys and signatures are reported as a single uppercase hex string; the
    verification verdict is reported as `MLDSA_SIGVER:01` or `:00`.

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    LEArray4x8, Mldsa87, Mldsa87PrivKey, Mldsa87PubKey, Mldsa87Result, Mldsa87Seed, Mldsa87SignRnd,
    Mldsa87Signature, PersistentDataAccessor, Trng,
};
use caliptra_registers::abr::AbrReg;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::test_suite;
use zerocopy::{FromBytes, IntoBytes};

/// ML-DSA-87 signature is 4627 bytes (FIPS 204). The driver stores it in
/// [u32; 1157] = 4628 bytes; the trailing byte is zero padding for word
/// alignment and is not part of the signature.
const MLDSA87_SIG_SIZE: usize = 4627;

// Static buffers sized for the largest ML-DSA-87 objects. These live in static
// storage because they are far too large for the test harness stack.
static mut ACVP_PUBKEY_BUF: [u8; 2592] = [0u8; 2592];
static mut ACVP_PRIVKEY_BUF: [u8; 4896] = [0u8; 4896];
static mut ACVP_KEYGEN_PRIVKEY: Mldsa87PrivKey = Mldsa87PrivKey::new([0u32; 1224]);
static mut ACVP_SIG_BUF: [u8; 4628] = [0u8; 4628];
static mut ACVP_MSG_BUF: [u8; 512] = [0u8; 512];
static mut ACVP_SEED_BUF: [u8; 32] = [0u8; 32];
static mut HEX_OUT_BUF: [u8; 9792] = [0u8; 9792]; // largest output: privkey 4896 bytes x 2

/// Hands out a `&mut` to one of the static scratch buffers above.
///
/// Goes through a raw pointer rather than taking a reference to the static
/// directly, which would trip the `static_mut_refs` lint. This firmware is
/// single-threaded and each buffer is claimed at most once per test run, so no
/// two live `&mut` can alias.
macro_rules! static_buf {
    ($name:ident) => {
        unsafe { &mut *(&raw mut $name) }
    };
}

/// Encode `data` as uppercase hex into `buf` and return the resulting `&str`.
///
/// The host runner scrapes these values with `[0-9A-F]+`, so the case matters.
fn hex_encode<'a>(data: &[u8], buf: &'a mut [u8]) -> &'a str {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (i, byte) in data.iter().enumerate() {
        buf[i * 2] = HEX[(byte >> 4) as usize];
        buf[i * 2 + 1] = HEX[(byte & 0xf) as usize];
    }
    core::str::from_utf8(&buf[..data.len() * 2]).unwrap()
}

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

fn new_trng() -> Trng {
    unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
        .unwrap()
    }
}

// test_mldsa_name MUST be run first; it initializes CFI, which the
// CFI-instrumented verification path depends on.
fn test_mldsa_name() {
    let mut trng = new_trng();
    let mut entropy_gen = || {
        trng.generate4()
            .map_err(|e| caliptra_cfi_lib::CfiError(u32::from(e)))
    };

    // This needs to happen in the first test
    CfiCounter::reset(&mut entropy_gen);

    let abr_reg = unsafe { AbrReg::new() };
    let regs = abr_reg.regs();

    let name = regs.mldsa_name().read();

    // MLDSA_CORE_NAME from RTL: 64'h3837412D_44534D4C representing "MLDSA-87"
    assert_eq!(name, [0x44534D4C, 0x3837412D]);
}

fn test_acvp() {
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let test_type = lines.next().unwrap().trim();

    match test_type {
        "MLDSA_KEYGEN" => {
            let mut abr_reg = unsafe { AbrReg::new() };
            let mut ml_dsa87 = Mldsa87::new(&mut abr_reg);

            let hex_seed = lines.next().unwrap().trim();
            let seed_buf = static_buf!(ACVP_SEED_BUF);
            hex_decode(hex_seed, seed_buf).unwrap();

            let mut trng = new_trng();

            let seed = LEArray4x8::from(*seed_buf);
            let priv_key = static_buf!(ACVP_KEYGEN_PRIVKEY);
            let pub_key = ml_dsa87
                .key_pair(Mldsa87Seed::Array4x8(&seed), &mut trng, Some(priv_key))
                .unwrap();

            let hex_buf = static_buf!(HEX_OUT_BUF);
            println!("MLDSA_PUBKEY:{}", hex_encode(pub_key.as_bytes(), hex_buf));
            let priv_key = static_buf!(ACVP_KEYGEN_PRIVKEY);
            let hex_buf = static_buf!(HEX_OUT_BUF);
            println!("MLDSA_PRIVKEY:{}", hex_encode(priv_key.as_bytes(), hex_buf));
        }

        "MLDSA_SIGGEN" => {
            let mut abr_reg = unsafe { AbrReg::new() };
            let mut ml_dsa87 = Mldsa87::new(&mut abr_reg);

            let hex_key = lines.next().unwrap().trim();
            let hex_msg = lines.next().unwrap().trim();

            let privkey_buf = static_buf!(ACVP_PRIVKEY_BUF);
            hex_decode(hex_key, privkey_buf).unwrap();

            let msg_buf = static_buf!(ACVP_MSG_BUF);
            let msg_len = hex_decode(hex_msg, msg_buf).unwrap();

            // contextLength is always 0 and deterministic signing is required
            // per the ACVP vector set, so sign_rnd is always all zeros.
            let sign_rnd = Mldsa87SignRnd::default();

            let mut trng = new_trng();

            let priv_key = Mldsa87PrivKey::read_from_bytes(privkey_buf.as_slice()).unwrap();
            let signature = ml_dsa87
                .sign_var_no_verify(
                    Mldsa87Seed::PrivKey(&priv_key),
                    &msg_buf[..msg_len],
                    &sign_rnd,
                    &mut trng,
                )
                .unwrap();

            let hex_buf = static_buf!(HEX_OUT_BUF);
            println!(
                "MLDSA_SIGGEN:{}",
                hex_encode(&signature.as_bytes()[..MLDSA87_SIG_SIZE], hex_buf)
            );
        }

        "MLDSA_SIGVER" => {
            let mut abr_reg = unsafe { AbrReg::new() };
            let mut ml_dsa87 = Mldsa87::new(&mut abr_reg);

            let hex_pubkey = lines.next().unwrap().trim();
            let hex_msg = lines.next().unwrap().trim();
            let hex_sig = lines.next().unwrap().trim();

            let pubkey_buf = static_buf!(ACVP_PUBKEY_BUF);
            let msg_buf = static_buf!(ACVP_MSG_BUF);
            let sig_buf = static_buf!(ACVP_SIG_BUF);

            hex_decode(hex_pubkey, pubkey_buf).unwrap();
            let msg_len = hex_decode(hex_msg, msg_buf).unwrap();
            hex_decode(hex_sig, sig_buf).unwrap();

            let pub_key = Mldsa87PubKey::read_from_bytes(pubkey_buf.as_slice()).unwrap();
            let signature = Mldsa87Signature::read_from_bytes(sig_buf.as_slice()).unwrap();

            let result = ml_dsa87
                .verify_var(&pub_key, &msg_buf[..msg_len], &signature)
                .unwrap();

            match result {
                Mldsa87Result::Success => println!("MLDSA_SIGVER:01"),
                Mldsa87Result::SigVerifyFailed => println!("MLDSA_SIGVER:00"),
            }
        }

        _ => panic!("Unknown test type"),
    }
}

test_suite! {
    test_mldsa_name,
    test_acvp,
}

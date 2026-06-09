/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa87_tests.rs

Abstract:

    File contains ACVP test cases for ML-DSA-87 (KEYGEN / SIGGEN / SIGVER).

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    LEArray4x8, Mldsa87, Mldsa87PrivKey, Mldsa87PubKey, Mldsa87Result, Mldsa87Seed,
    Mldsa87SignRnd, Mldsa87Signature, Trng,
};
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::mldsa::MldsaReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::{self, test_suite};
use zerocopy::{FromBytes, IntoBytes};

// Static buffers sized for the largest ML-DSA-87 objects
static mut ACVP_PUBKEY_BUF: [u8; 2592] = [0u8; 2592];
static mut ACVP_PRIVKEY_BUF: [u8; 4896] = [0u8; 4896];
static mut ACVP_KEYGEN_PRIVKEY: Mldsa87PrivKey = Mldsa87PrivKey::new([0u32; 1224]);
static mut ACVP_SIG_BUF: [u8; 4628] = [0u8; 4628];
static mut ACVP_MSG_BUF: [u8; 512] = [0u8; 512];
static mut ACVP_SEED_BUF: [u8; 32] = [0u8; 32];
static mut HEX_OUT_BUF: [u8; 9792] = [0u8; 9792]; // largest output: privkey 4896 bytes × 2

fn hex_encode<'a>(data: &[u8], buf: &'a mut [u8]) -> &'a str {
    const HEX: &[u8] = b"0123456789abcdef";
    for (i, &b) in data.iter().enumerate() {
        buf[i * 2] = HEX[(b >> 4) as usize];
        buf[i * 2 + 1] = HEX[(b & 0xf) as usize];
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

fn test_acvp() {
    // stimulus/current.txt format depends on test type (line 1):
    //
    //   MLDSA_KEYGEN:
    //     line 1: "MLDSA_KEYGEN"
    //     line 2: hex seed (32 bytes)
    //
    //   MLDSA_SIGGEN:
    //     line 1: "MLDSA_SIGGEN"
    //     line 2: hex private key (4896 bytes)
    //     line 3: hex message (up to 512 bytes)
    //
    //   MLDSA_SIGVER:
    //     line 1: "MLDSA_SIGVER"
    //     line 2: hex public key (2592 bytes)
    //     line 3: hex message (up to 512 bytes)
    //     line 4: hex signature (4627 bytes)
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let test_type = lines.next().unwrap().trim();

    match test_type {
        "MLDSA_KEYGEN" => {
            let mut ml_dsa87 = unsafe { Mldsa87::new(MldsaReg::new()) };
            let hex_seed = lines.next().unwrap().trim();

            let seed_buf = unsafe { &mut ACVP_SEED_BUF };
            hex_decode(hex_seed, seed_buf).unwrap();

            let mut trng = unsafe {
                Trng::new(
                    CsrngReg::new(),
                    EntropySrcReg::new(),
                    SocIfcTrngReg::new(),
                    &SocIfcReg::new(),
                )
                .unwrap()
            };

            let seed = LEArray4x8::from(*seed_buf);
            let priv_key = unsafe { &mut ACVP_KEYGEN_PRIVKEY };
            let pub_key = ml_dsa87
                .key_pair_no_pct(Mldsa87Seed::Array4x8(&seed), &mut trng, Some(priv_key))
                .unwrap();

            let hex_buf = unsafe { &mut HEX_OUT_BUF };
            println!("MLDSA_PUBKEY:{}", hex_encode(pub_key.as_bytes(), hex_buf));
            println!(
                "MLDSA_PRIVKEY:{}",
                hex_encode(unsafe { ACVP_KEYGEN_PRIVKEY.as_bytes() }, hex_buf)
            );
        }

        "MLDSA_SIGGEN" => {
            let mut ml_dsa87 = unsafe { Mldsa87::new(MldsaReg::new()) };
            let hex_key = lines.next().unwrap().trim();

            let mut trng = unsafe {
                Trng::new(
                    CsrngReg::new(),
                    EntropySrcReg::new(),
                    SocIfcTrngReg::new(),
                    &SocIfcReg::new(),
                )
                .unwrap()
            };

            let privkey_buf = unsafe { &mut ACVP_PRIVKEY_BUF };
            hex_decode(hex_key, privkey_buf).unwrap();
            let hex_msg = lines.next().unwrap().trim();
            let msg_buf = unsafe { &mut ACVP_MSG_BUF };
            let msg_len = hex_decode(hex_msg, msg_buf).unwrap();

            // deterministic=true per ACVP requirements; sign_rnd is always all zeros.
            let sign_rnd = Mldsa87SignRnd::default();

            let priv_key = Mldsa87PrivKey::read_from_bytes(privkey_buf.as_slice()).unwrap();
            let signature = ml_dsa87
                .sign_var_no_verify(
                    Mldsa87Seed::PrivKey(&priv_key),
                    &msg_buf[..msg_len],
                    &sign_rnd,
                    &mut trng,
                )
                .unwrap();

            // ML-DSA-87 signature is 4627 bytes (FIPS 204). The driver stores it in
            // [u32; 1157] = 4628 bytes; the last byte is zero-padding.
            const MLDSA87_SIG_SIZE: usize = 4627;
            let hex_buf = unsafe { &mut HEX_OUT_BUF };
            println!(
                "MLDSA_SIGGEN:{}",
                hex_encode(&signature.as_bytes()[..MLDSA87_SIG_SIZE], hex_buf)
            );
        }

        "MLDSA_SIGVER" => {
            let mut ml_dsa87 = unsafe { Mldsa87::new(MldsaReg::new()) };

            let hex_pubkey = lines.next().unwrap().trim();
            let hex_msg = lines.next().unwrap().trim();
            let hex_sig = lines.next().unwrap().trim();

            let pubkey_buf = unsafe { &mut ACVP_PUBKEY_BUF };
            let msg_buf = unsafe { &mut ACVP_MSG_BUF };
            let sig_buf = unsafe { &mut ACVP_SIG_BUF };

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
    test_acvp,
}

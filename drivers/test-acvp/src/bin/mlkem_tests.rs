/*++

Licensed under the Apache-2.0 license.

File Name:

    mlkem_tests.rs

Abstract:

    File contains ACVP test cases for ML-KEM-1024 (KEYGEN / ENCAPS / DECAPS).

    The vector under test is supplied out-of-band in `stimulus/current.txt`,
    which is rewritten by the host-side runner before each invocation. The
    first line selects the operation:

        MLKEM_KEYGEN
          line 2: hex seed d (32 bytes)
          line 3: hex seed z (32 bytes)

        MLKEM_ENCAPS
          line 2: hex encapsulation key (1568 bytes)
          line 3: hex message (32 bytes)

        MLKEM_DECAPS
          line 2: hex decapsulation key (3168 bytes)
          line 3: hex ciphertext (1568 bytes)

    Each operation reports a single line of uppercase hex, with a space
    separating the two values where an operation produces a pair.

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    MlKem1024, MlKem1024Ciphertext, MlKem1024DecapsKey, MlKem1024EncapsKey, MlKem1024Message,
    MlKem1024MessageSource, MlKem1024Seed, MlKem1024Seeds, MlKem1024SharedKey,
    MlKem1024SharedKeyOut, PersistentDataAccessor, Trng,
};
use caliptra_registers::abr::AbrReg;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::{print, test_suite};
use zerocopy::{FromBytes, IntoBytes};

// Static buffers to avoid stack overflow for the large ML-KEM structures.
static mut EK_BUF: [u8; 1568] = [0u8; 1568]; // encapsulation key
static mut DK_BUF: [u8; 3168] = [0u8; 3168]; // decapsulation key
static mut CT_BUF: [u8; 1568] = [0u8; 1568]; // ciphertext

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

/// Seeds the ABR entropy register, which the ML-KEM engine consumes for
/// side-channel countermeasures.
fn seed_abr_entropy() {
    let mut trng = new_trng();
    let mut abr_reg = unsafe { AbrReg::new() };
    let regs = abr_reg.regs_mut();
    let entropy = trng.generate16().unwrap();
    entropy.write_to_reg(regs.entropy());
}

// test_mlkem_name MUST be run first; it initializes CFI.
fn test_mlkem_name() {
    let mut trng = new_trng();
    let mut entropy_gen = || {
        trng.generate4()
            .map_err(|e| caliptra_cfi_lib::CfiError(u32::from(e)))
    };

    // This needs to happen in the first test
    CfiCounter::reset(&mut entropy_gen);

    let abr_reg = unsafe { AbrReg::new() };
    let regs = abr_reg.regs();

    let name = regs.mlkem_name().read();

    // MLKEM_CORE_NAME from RTL: 64'h32343130_4D2D4B45 representing "KEM-1024"
    assert_eq!(name, [0x4D2D4B45, 0x32343130]);
}

/// Prints `data` as uppercase hex, one byte at a time, with no trailing
/// newline. The host runner scrapes these values with `[0-9A-F]+`, so the case
/// matters.
fn print_hex(data: &[u8]) {
    for byte in data.iter() {
        print!("{:02X}", byte);
    }
}

fn test_acvp() {
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let test_type = lines.next().unwrap().trim();

    match test_type {
        "MLKEM_KEYGEN" => {
            let hex_d = lines.next().unwrap().trim();
            let hex_z = lines.next().unwrap().trim();

            let mut d_bytes = [0u8; 32];
            let mut z_bytes = [0u8; 32];
            hex_decode(hex_d, &mut d_bytes).unwrap();
            hex_decode(hex_z, &mut z_bytes).unwrap();

            let seed_d = MlKem1024Seed::read_from_bytes(&d_bytes).unwrap();
            let seed_z = MlKem1024Seed::read_from_bytes(&z_bytes).unwrap();

            seed_abr_entropy();
            let mut abr_reg = unsafe { AbrReg::new() };
            let mut mlkem = MlKem1024::new(&mut abr_reg);

            let (encaps_key, decaps_key) = mlkem
                .key_pair(MlKem1024Seeds::Arrays(&seed_d, &seed_z), None)
                .unwrap();

            // MLKEM_KEYGEN:<ek: 3136 hex chars> <dk: 6336 hex chars>
            print!("MLKEM_KEYGEN:");
            print_hex(encaps_key.as_bytes());
            print!(" ");
            print_hex(decaps_key.as_bytes());
            println!();
        }

        "MLKEM_ENCAPS" => {
            let hex_ek = lines.next().unwrap().trim();
            let hex_msg = lines.next().unwrap().trim();

            let ek_buf = static_buf!(EK_BUF);
            hex_decode(hex_ek, ek_buf).unwrap();

            let mut msg_bytes = [0u8; 32];
            hex_decode(hex_msg, &mut msg_bytes).unwrap();

            let encaps_key = MlKem1024EncapsKey::read_from_bytes(ek_buf.as_slice()).unwrap();
            let message = MlKem1024Message::read_from_bytes(&msg_bytes).unwrap();
            let mut shared_key_out = MlKem1024SharedKey::default();

            seed_abr_entropy();
            let mut abr_reg = unsafe { AbrReg::new() };
            let mut mlkem = MlKem1024::new(&mut abr_reg);

            let ciphertext = mlkem
                .encapsulate(
                    &encaps_key,
                    MlKem1024MessageSource::Array(&message),
                    MlKem1024SharedKeyOut::Array(&mut shared_key_out),
                )
                .unwrap();

            // MLKEM_ENCAPS:<ciphertext: 3136 hex chars> <shared_key: 64 hex chars>
            print!("MLKEM_ENCAPS:");
            print_hex(ciphertext.as_bytes());
            print!(" ");
            print_hex(shared_key_out.as_bytes());
            println!();
        }

        "MLKEM_DECAPS" => {
            let hex_dk = lines.next().unwrap().trim();
            let hex_ct = lines.next().unwrap().trim();

            let dk_buf = static_buf!(DK_BUF);
            let ct_buf = static_buf!(CT_BUF);
            hex_decode(hex_dk, dk_buf).unwrap();
            hex_decode(hex_ct, ct_buf).unwrap();

            let decaps_key = MlKem1024DecapsKey::read_from_bytes(dk_buf.as_slice()).unwrap();
            let ciphertext = MlKem1024Ciphertext::read_from_bytes(ct_buf.as_slice()).unwrap();
            let mut shared_key_out = MlKem1024SharedKey::default();

            seed_abr_entropy();
            let mut abr_reg = unsafe { AbrReg::new() };
            let mut mlkem = MlKem1024::new(&mut abr_reg);

            mlkem
                .decapsulate(
                    &decaps_key,
                    &ciphertext,
                    MlKem1024SharedKeyOut::Array(&mut shared_key_out),
                )
                .unwrap();

            // MLKEM_DECAPS:<shared_key: 64 hex chars>
            print!("MLKEM_DECAPS:");
            print_hex(shared_key_out.as_bytes());
            println!();
        }

        _ => panic!("Unknown test type"),
    }
}

test_suite! {
    test_mlkem_name,
    test_acvp,
}

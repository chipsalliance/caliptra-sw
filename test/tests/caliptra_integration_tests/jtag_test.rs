// Licensed under the Apache-2.0 license

use caliptra_builder::{firmware, get_elf_path, ImageOptions};

use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_hw_model_types::DeviceLifecycle;
use caliptra_test::swap_word_bytes_inplace;
use openssl::sha::sha384;
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use zerocopy::AsBytes;

fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

#[derive(PartialEq, Debug)]
enum RegAccess {
    Invalid,
    RO,
    RW,
}

fn gdb_mem_test<R>(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<R>,
    addr: u32,
    size: u8,
    access_type: RegAccess,
) where
    R: std::io::Read,
{
    stdin
        .write_all(format!("mem_access_test 0x{:x} {}\n", addr, size).as_bytes())
        .expect("Failed to write to stdin");

    let mut output = String::new();
    loop {
        stdout.read_line(&mut output).unwrap();
        if output.contains("Done") || output.contains("Cannot access memory at address") {
            break;
        }
    }

    let actual_access_type = if output.contains("Write Accepted") {
        RegAccess::RW
    } else if output.contains("Read Accepted") {
        RegAccess::RO
    } else {
        RegAccess::Invalid
    };

    assert_eq!(
        actual_access_type, access_type,
        "Addr: 0x{:08x} Size: {:} Log:\n{}",
        addr, size, output
    );

    // Openocd's GDB server ACKs 8 byte writes immediatelly for a speedup on large transfers. This has a side
    // effect of causing the next successful write to erroneously report a failure. Perform writes to a known
    // writable address until it stops reporting failures.
    if size == 8 && actual_access_type != RegAccess::RW {
        let mut output = String::new();
        loop {
            stdin
                .write_all("recover\n".as_bytes())
                .expect("Failed to write to stdin");

            stdout.read_line(&mut output).unwrap();
            if output.contains("Recovered") {
                break;
            }
        }
    }
}

#[test]
fn gdb_test() {
    #![cfg_attr(not(feature = "fpga_realtime"), ignore)]

    let security_state = *SecurityState::default()
        .set_debug_locked(false)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::APP_WITH_UART,
        ImageOptions {
            fmc_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();
    let vendor_pk_hash = sha384(image.manifest.preamble.vendor_pub_keys.as_bytes());
    let owner_pk_hash = sha384(image.manifest.preamble.owner_pub_keys.as_bytes());
    let vendor_pk_hash_words = bytes_to_be_words_48(&vendor_pk_hash);
    let owner_pk_hash_words = bytes_to_be_words_48(&owner_pk_hash);

    let fuses = Fuses {
        key_manifest_pk_hash: vendor_pk_hash_words,
        owner_pk_hash: owner_pk_hash_words,
        fmc_key_manifest_svn: 0b1111111,
        lms_verify: true,
        ..Default::default()
    };
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        fuses,
        ..Default::default()
    })
    .unwrap();

    hw.step();
    hw.step_until_output_contains("[rt] Runtime listening for mailbox commands...\n")
        .unwrap();

    #[cfg(feature = "fpga_realtime")]
    hw.launch_openocd().unwrap();

    let elf_path = get_elf_path(&firmware::APP_WITH_UART).unwrap();
    let mut gdb = Command::new("gdb-multiarch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg(elf_path)
        .spawn()
        .unwrap();

    let mut stdin = gdb.stdin.take().expect("Failed to open stdin");
    let mut stderr = BufReader::new(gdb.stderr.as_mut().unwrap());

    stdin
        .write_all(include_str!("smoke_testdata/gdb_script.txt").as_bytes())
        .expect("Failed to write to stdin");

    loop {
        let mut output = String::new();
        stderr.read_line(&mut output).unwrap();

        if output.contains("GDB Launched") {
            break;
        }
    }

    // Start of ROM
    gdb_mem_test(&mut stdin, &mut stderr, 0x00000000, 1, RegAccess::RO);
    gdb_mem_test(&mut stdin, &mut stderr, 0x00000000, 2, RegAccess::RO);
    gdb_mem_test(&mut stdin, &mut stderr, 0x00000000, 4, RegAccess::RO);
    gdb_mem_test(&mut stdin, &mut stderr, 0x00000000, 8, RegAccess::RO);
    // End of ROM
    gdb_mem_test(&mut stdin, &mut stderr, 0x0000BFFF, 1, RegAccess::RO);
    gdb_mem_test(&mut stdin, &mut stderr, 0x0000BFFE, 2, RegAccess::RO);
    gdb_mem_test(&mut stdin, &mut stderr, 0x0000BFFC, 4, RegAccess::RO);
    gdb_mem_test(&mut stdin, &mut stderr, 0x0000BFF8, 8, RegAccess::RO);

    // Start of ICCM
    gdb_mem_test(&mut stdin, &mut stderr, 0x40000000, 1, RegAccess::Invalid);
    gdb_mem_test(&mut stdin, &mut stderr, 0x40000000, 2, RegAccess::Invalid);
    gdb_mem_test(&mut stdin, &mut stderr, 0x40000000, 4, RegAccess::RW);
    gdb_mem_test(&mut stdin, &mut stderr, 0x40000000, 8, RegAccess::RO);
    // End of ICCM
    gdb_mem_test(&mut stdin, &mut stderr, 0x4001FFFF, 1, RegAccess::Invalid);
    gdb_mem_test(&mut stdin, &mut stderr, 0x4001FFFE, 2, RegAccess::Invalid);
    gdb_mem_test(&mut stdin, &mut stderr, 0x4001FFFC, 4, RegAccess::RW);
    gdb_mem_test(&mut stdin, &mut stderr, 0x4001FFF8, 8, RegAccess::RO);

    // Start of DCCM
    gdb_mem_test(&mut stdin, &mut stderr, 0x50000000, 1, RegAccess::RW);
    gdb_mem_test(&mut stdin, &mut stderr, 0x50000000, 2, RegAccess::RW);
    gdb_mem_test(&mut stdin, &mut stderr, 0x50000000, 4, RegAccess::RW);
    gdb_mem_test(&mut stdin, &mut stderr, 0x50000000, 8, RegAccess::RW);
    // End of DCCM
    gdb_mem_test(&mut stdin, &mut stderr, 0x5001FFFF, 1, RegAccess::RW);
    gdb_mem_test(&mut stdin, &mut stderr, 0x5001FFFE, 2, RegAccess::RW);
    gdb_mem_test(&mut stdin, &mut stderr, 0x5001FFFC, 4, RegAccess::RW);
    gdb_mem_test(&mut stdin, &mut stderr, 0x5001FFF8, 8, RegAccess::RW);
}

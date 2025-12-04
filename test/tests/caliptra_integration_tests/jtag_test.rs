// Licensed under the Apache-2.0 license

use caliptra_builder::{firmware, get_elf_path, ImageOptions};

use caliptra_api_types::DeviceLifecycle;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_test::image_pk_desc_hash;
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};

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

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn gdb_test() {
    #![cfg_attr(not(feature = "fpga_realtime"), ignore)]

    let security_state = *SecurityState::default()
        .set_debug_locked(false)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
        .unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &if cfg!(feature = "fpga_subsystem") {
            firmware::APP_WITH_UART_FPGA
        } else {
            firmware::APP_WITH_UART
        },
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let fuses = Fuses {
        vendor_pk_hash: vendor_pk_desc_hash,
        owner_pk_hash,
        fw_svn: [0x7F, 0, 0, 0],
        ..Default::default()
    };
    let mut hw = caliptra_hw_model::new(
        InitParams {
            fuses,
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step();
    hw.step_until_output_contains("[rt] RT listening for mailbox commands...\n")
        .unwrap();

    #[cfg(feature = "fpga_realtime")]
    hw.launch_openocd().unwrap();

    let elf_path = get_elf_path(&if cfg!(feature = "fpga_subsystem") {
        firmware::APP_WITH_UART_FPGA
    } else {
        firmware::APP_WITH_UART
    })
    .unwrap();
    let mut gdb = Command::new("gdb-multiarch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg(elf_path)
        .spawn()
        .unwrap();

    gdb.wait().unwrap();

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

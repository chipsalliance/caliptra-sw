/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_emu_bus::Clock;
use caliptra_emu_cpu::{Cpu, RvInstr, StepAction};
use caliptra_emu_periph::soc_reg::DebugManufService;
use caliptra_emu_periph::{
    CaliptraRootBus, CaliptraRootBusArgs, DownloadIdevidCsrCb, MailboxInternal, ReadyForFwCb,
    TbServicesCb, UploadUpdateFwCb,
};
use caliptra_hw_model::BusMmio;
use caliptra_hw_model_types::{DeviceLifecycle, SecurityState};
use clap::{arg, value_parser, ArgAction};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::registers::InMemoryRegister;
mod gdb;
use crate::gdb::gdb_target::GdbTarget;
use gdb::gdb_state;

use tock_registers::register_bitfields;

/// Firmware Load Command Opcode
const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

/// The number of CPU clock cycles it takes to write the firmware to the mailbox.
const FW_WRITE_TICKS: u64 = 1000;

const EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES: u64 = 20_000_000; // 20 million cycles

// CPU Main Loop (free_run no GDB)
fn free_run(mut cpu: Cpu<CaliptraRootBus>, trace_path: Option<PathBuf>) {
    if let Some(path) = trace_path {
        let mut f = File::create(path).unwrap();
        let trace_fn: &mut dyn FnMut(u32, RvInstr) = &mut |pc, instr| {
            let _ = write!(&mut f, "0x{:08x} ", pc);
            match instr {
                RvInstr::Instr32(instr) => {
                    let _ = writeln!(&mut f, "0x{:08x}", instr);
                }
                RvInstr::Instr16(instr) => {
                    let _ = writeln!(&mut f, "0x{:04x}", instr);
                }
            }
        };

        // Need to have the loop in the same scope as trace_fn to prevent borrowing rules violation
        while let StepAction::Continue = cpu.step(Some(trace_fn)) {}
    } else {
        while let StepAction::Continue = cpu.step(None) {}
    };
}

fn words_from_bytes_le(arr: &[u8; 48]) -> [u32; 12] {
    let mut result = [0u32; 12];
    for i in 0..result.len() {
        result[i] = u32::from_le_bytes(arr[i * 4..][..4].try_into().unwrap())
    }
    result
}

fn main() -> io::Result<()> {
    let args = clap::Command::new("caliptra-emu")
        .about("Caliptra emulator")
        .arg(
            arg!(--"rom" <FILE> "ROM binary path")
                .value_parser(value_parser!(PathBuf))
        )
        .arg(
            arg!(--"recovery-image-fw" <FILE> "Recovery firmware image binary path")
                .required(false)
                .value_parser(value_parser!(PathBuf))
        )
        .arg(
            arg!(--"update-recovery-image-fw" <FILE> "Update recovery firmware image binary path")
                .required(false)
                .value_parser(value_parser!(PathBuf))
        )
        .arg(
            arg!(--"recovery-image-manifest" <FILE> "Recovery image auth manifest binary path")
                .required(false)
                .value_parser(value_parser!(PathBuf))
        )
        .arg(
            arg!(--"recovery-image-mcurt" <FILE> "Recovery image mcurt binary path")
                .required(false)
                .value_parser(value_parser!(PathBuf))
        )
        .arg(
            arg!(--"gdb-port" <VALUE> "Gdb Debugger")
                .required(false)
        )
        .arg(
            arg!(--"trace-instr" ... "Trace instructions to a file in log-dir")
                .required(false)
                .action(ArgAction::SetTrue)
        )
        .arg(
            arg!(--"ueid" <U128> "128-bit Unique Endpoint Id")
                .required(false)
                .value_parser(value_parser!(u128))
                .default_value(&u128::MAX.to_string())
        )
        .arg(
            arg!(--"idevid-key-id-algo" <algo> "idevid certificate key id algorithm [sha1, sha256, sha384, fuse]")
                .required(false)
                .default_value("sha1"),
        )
        .arg(
            arg!(--"req-idevid-csr" ... "Request IDevID CSR. Downloaded CSR is store in log-dir.")
                .required(false)
                .action(ArgAction::SetTrue)
        )
        .arg(
            arg!(--"req-ldevid-cert" ... "Request LDevID Cert. Downloaded cert is stored in log-dir")
                .required(false)
                .action(ArgAction::SetTrue)
        )
        .arg(
            arg!(--"log-dir" <DIR> "Directory to log execution artifacts")
                .required(false)
                .value_parser(value_parser!(PathBuf))
                .default_value("/tmp")
        )
        .arg(
            arg!(--"mfg-pk-hash" ... "Hash of the four Manufacturer Public Keys")
                .required(false)
                .value_parser(value_parser!(String))
                .default_value(""),
        )
        .arg(
            arg!(--"owner-pk-hash" ... "Owner Public Key Hash")
                .required(false)
                .value_parser(value_parser!(String))
                .default_value(""),
        )
        .arg(
            arg!(--"device-lifecycle" ... "Device Lifecycle State [unprovisioned, manufacturing, production]")
                .required(false)
                .value_parser(value_parser!(String))
                .default_value("unprovisioned"),
        )
        .arg(
            arg!(--"wdt-timeout" <U64> "Watchdog Timer Timeout in CPU Clock Cycles")
                .required(false)
                .value_parser(value_parser!(u64))
                .default_value(&(EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES.to_string()))
        )
        .get_matches();

    let args_rom = args.get_one::<PathBuf>("rom").unwrap();
    let args_recovery_fw = args.get_one::<PathBuf>("recovery-image-fw");
    let args_update_recovery_fw = args.get_one::<PathBuf>("update-recovery-image-fw");
    let _args_recovery_image_manifest = args.get_one::<PathBuf>("recovery-image-manifest"); // TODO hook up to RRI
    let _args_recovery_image_mcurt = args.get_one::<PathBuf>("recovery-image-mcurt"); // TODO hook up to RRI
    let args_log_dir = args.get_one::<PathBuf>("log-dir").unwrap();
    let args_idevid_key_id_algo = args.get_one::<String>("idevid-key-id-algo").unwrap();
    let args_ueid = args.get_one::<u128>("ueid").unwrap();
    let wdt_timeout = args.get_one::<u64>("wdt-timeout").unwrap();
    let mut mfg_pk_hash = match hex::decode(args.get_one::<String>("mfg-pk-hash").unwrap()) {
        Ok(mfg_pk_hash) => mfg_pk_hash,
        Err(_) => {
            println!("Manufacturer public keys hash format is incorrect",);
            exit(-1);
        }
    };
    let mut owner_pk_hash = match hex::decode(args.get_one::<String>("owner-pk-hash").unwrap()) {
        Ok(owner_pk_hash) => owner_pk_hash,
        Err(_) => {
            println!("Owner public key hash format is incorrect",);
            exit(-1);
        }
    };
    let args_device_lifecycle = args.get_one::<String>("device-lifecycle").unwrap();

    if !Path::new(&args_rom).exists() {
        println!("ROM File {:?} does not exist", args_rom);
        exit(-1);
    }

    if (!mfg_pk_hash.is_empty() && mfg_pk_hash.len() != 48)
        || (!owner_pk_hash.is_empty() && owner_pk_hash.len() != 48)
    {
        println!(
            "Incorrect mfg_pk_hash: {} and/or owner_pk_hash: {} length",
            mfg_pk_hash.len(),
            owner_pk_hash.len()
        );
        exit(-1);
    }
    change_dword_endianess(&mut mfg_pk_hash);
    change_dword_endianess(&mut owner_pk_hash);

    let mut rom = File::open(args_rom)?;
    let mut rom_buffer = Vec::new();
    rom.read_to_end(&mut rom_buffer)?;

    if rom_buffer.len() > CaliptraRootBus::ROM_SIZE {
        println!(
            "ROM File Size must not exceed {} bytes",
            CaliptraRootBus::ROM_SIZE
        );
        exit(-1);
    }

    let mut current_fw_buf = Vec::new();
    if let Some(path) = args_recovery_fw {
        if !Path::new(&path).exists() {
            println!(
                "Current firmware file {:?} does not exist",
                args_recovery_fw
            );
            exit(-1);
        }
        let mut firmware = File::open(path)?;
        firmware.read_to_end(&mut current_fw_buf)?;
    }
    let current_fw_buf = Rc::new(current_fw_buf);

    let mut update_fw_buf = Vec::new();
    if let Some(path) = args_update_recovery_fw {
        if !Path::new(&path).exists() {
            println!(
                "Update firmware file {:?} does not exist",
                args_update_recovery_fw
            );
            exit(-1);
        }
        let mut firmware = File::open(path)?;
        firmware.read_to_end(&mut update_fw_buf)?;
    }
    let update_fw_buf = Rc::new(update_fw_buf);

    let log_dir = Rc::new(args_log_dir.to_path_buf());

    let clock = Clock::new();

    let req_idevid_csr = args.get_flag("req-idevid-csr");
    let req_ldevid_cert = args.get_flag("req-ldevid-cert");

    let mut security_state = SecurityState::default();
    security_state.set_device_lifecycle(
        match args_device_lifecycle.to_ascii_lowercase().as_str() {
            "manufacturing" => DeviceLifecycle::Manufacturing,
            "production" => DeviceLifecycle::Production,
            "unprovisioned" | "" => DeviceLifecycle::Unprovisioned,
            other => {
                println!("Unknown device lifecycle {:?}", other);
                exit(-1);
            }
        },
    );

    let bus_args = CaliptraRootBusArgs {
        rom: rom_buffer,
        log_dir: args_log_dir.clone(),
        tb_services_cb: TbServicesCb::new(move |val| match val {
            0x01 => exit(0xFF),
            0xFF => exit(0x00),
            _ => print!("{}", val as char),
        }),
        ready_for_fw_cb: ReadyForFwCb::new(move |args| {
            let firmware_buffer = current_fw_buf.clone();
            args.schedule_later(FW_WRITE_TICKS, move |mailbox: &mut MailboxInternal| {
                upload_fw_to_mailbox(mailbox, firmware_buffer);
            });
        }),
        security_state,
        upload_update_fw: UploadUpdateFwCb::new(move |mailbox: &mut MailboxInternal| {
            upload_fw_to_mailbox(mailbox, update_fw_buf.clone());
        }),
        download_idevid_csr_cb: DownloadIdevidCsrCb::new(
            move |mailbox: &mut MailboxInternal,
                  cptra_dbg_manuf_service_reg: &mut InMemoryRegister<
                u32,
                DebugManufService::Register,
            >| {
                download_idev_id_csr(mailbox, log_dir.clone(), cptra_dbg_manuf_service_reg);
            },
        ),
        ..Default::default()
    };

    let root_bus = CaliptraRootBus::new(&clock, bus_args);
    let soc_ifc = unsafe {
        caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
            0x3003_0000 as *mut u32,
            BusMmio::new(root_bus.soc_to_caliptra_bus()),
        )
    };

    if !mfg_pk_hash.is_empty() {
        let mfg_pk_hash = words_from_bytes_le(
            &mfg_pk_hash
                .try_into()
                .expect("mfg_pk_hash must be 48 bytes"),
        );
        soc_ifc.fuse_key_manifest_pk_hash().write(&mfg_pk_hash);
    }

    if !owner_pk_hash.is_empty() {
        let owner_pk_hash = words_from_bytes_le(
            &owner_pk_hash
                .try_into()
                .expect("owner_pk_hash must be 48 bytes"),
        );
        soc_ifc.fuse_owner_pk_hash().write(&owner_pk_hash);
    }

    // Populate DBG_MANUF_SERVICE_REG
    {
        const GEN_IDEVID_CSR_FLAG: u32 = 1 << 0;
        const GEN_LDEVID_CSR_FLAG: u32 = 1 << 1;

        let mut val = 0;
        if req_idevid_csr {
            val |= GEN_IDEVID_CSR_FLAG;
        }
        if req_ldevid_cert {
            val |= GEN_LDEVID_CSR_FLAG;
        }
        soc_ifc.cptra_dbg_manuf_service_reg().write(|_| val);
    }

    // Populate fuse_idevid_cert_attr
    {
        register_bitfields! [
            u32,
            IDevIdCertAttrFlags [
                KEY_ID_ALGO OFFSET(0) NUMBITS(2) [
                    SHA1 = 0b00,
                    SHA256 = 0b01,
                    SHA384 = 0b10,
                    FUSE = 0b11,
                ],
                RESERVED OFFSET(2) NUMBITS(30) [],
            ],
        ];

        // Determine the Algorithm used for IDEVID Certificate Subject Key Identifier
        let algo = match args_idevid_key_id_algo.to_ascii_lowercase().as_str() {
            "" | "sha1" => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA1,
            "sha256" => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA256,
            "sha384" => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA384,
            "fuse" => IDevIdCertAttrFlags::KEY_ID_ALGO::FUSE,
            _ => panic!("Unknown idev_key_id_algo {:?}", args_idevid_key_id_algo),
        };

        let flags: InMemoryRegister<u32, IDevIdCertAttrFlags::Register> = InMemoryRegister::new(0);
        flags.write(algo);
        let mut cert = [0u32; 24];
        // DWORD 00 - Flags
        cert[0] = flags.get();
        // DWORD 01 - 05 - IDEVID Subject Key Identifier (all zeroes)
        cert[6] = 1; // UEID Type
                     // DWORD 07 - 10 - UEID / Manufacturer Serial Number
        cert[7] = *args_ueid as u32;
        cert[8] = (*args_ueid >> 32) as u32;
        cert[9] = (*args_ueid >> 64) as u32;
        cert[10] = (*args_ueid >> 96) as u32;

        soc_ifc.fuse_idevid_cert_attr().write(&cert);
    }

    // Populate cptra_wdt_cfg
    {
        soc_ifc.cptra_wdt_cfg().at(0).write(|_| *wdt_timeout as u32);
        soc_ifc
            .cptra_wdt_cfg()
            .at(1)
            .write(|_| (*wdt_timeout >> 32) as u32);
    }

    let cpu = Cpu::new(root_bus, clock);

    // Check if Optional GDB Port is passed
    match args.get_one::<String>("gdb-port") {
        Some(port) => {
            // Create GDB Target Instance
            let mut gdb_target = GdbTarget::new(cpu);

            // Execute CPU through GDB State Machine
            gdb_state::wait_for_gdb_run(&mut gdb_target, port.parse().unwrap());
        }
        _ => {
            let instr_trace = if args.get_flag("trace-instr") {
                let mut path = args_log_dir.clone();
                path.push("caliptra_instr_trace.txt");
                Some(path)
            } else {
                None
            };

            // If no GDB Port is passed, Free Run
            free_run(cpu, instr_trace);
        }
    }

    Ok(())
}

fn change_dword_endianess(data: &mut Vec<u8>) {
    for idx in (0..data.len()).step_by(4) {
        data.swap(idx, idx + 3);
        data.swap(idx + 1, idx + 2);
    }
}

fn upload_fw_to_mailbox(mailbox: &mut MailboxInternal, firmware_buffer: Rc<Vec<u8>>) {
    let soc_mbox = mailbox.as_external().regs();
    // Write the cmd to mailbox.

    assert!(!soc_mbox.lock().read().lock());

    soc_mbox.cmd().write(|_| FW_LOAD_CMD_OPCODE);
    soc_mbox.dlen().write(|_| firmware_buffer.len() as u32);

    //
    // Write firmware image.
    //
    let word_size = std::mem::size_of::<u32>();
    let remainder = firmware_buffer.len() % word_size;
    let n = firmware_buffer.len() - remainder;

    for idx in (0..n).step_by(word_size) {
        soc_mbox.datain().write(|_| {
            u32::from_le_bytes(firmware_buffer[idx..idx + word_size].try_into().unwrap())
        });
    }

    // Handle the remainder bytes.
    if remainder > 0 {
        let mut last_word = firmware_buffer[n] as u32;
        for idx in 1..remainder {
            last_word |= (firmware_buffer[n + idx] as u32) << (idx << 3);
        }
        soc_mbox.datain().write(|_| last_word);
    }

    // Set the execute register.
    soc_mbox.execute().write(|w| w.execute(true));
}

fn download_idev_id_csr(
    mailbox: &mut MailboxInternal,
    path: Rc<PathBuf>,
    cptra_dbg_manuf_service_reg: &mut InMemoryRegister<u32, DebugManufService::Register>,
) {
    let mut path = path.to_path_buf();
    path.push("caliptra_ldevid_cert.der");

    let mut file = std::fs::File::create(path).unwrap();

    let soc_mbox = mailbox.as_external().regs();

    let byte_count = soc_mbox.dlen().read() as usize;
    let remainder = byte_count % core::mem::size_of::<u32>();
    let n = byte_count - remainder;

    for _ in (0..n).step_by(core::mem::size_of::<u32>()) {
        let buf = soc_mbox.dataout().read();
        file.write_all(&buf.to_le_bytes()).unwrap();
    }

    if remainder > 0 {
        let part = soc_mbox.dataout().read();
        for idx in 0..remainder {
            let byte = ((part >> (idx << 3)) & 0xFF) as u8;
            file.write_all(&[byte]).unwrap();
        }
    }

    // Complete the mailbox command.
    soc_mbox.status().write(|w| w.status(|w| w.cmd_complete()));

    // Clear the Idevid CSR requested bit.
    cptra_dbg_manuf_service_reg.modify(DebugManufService::REQ_IDEVID_CSR::CLEAR);
}

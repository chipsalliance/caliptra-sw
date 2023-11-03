/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

mod cli;

use caliptra_emu_bus::Clock;
use caliptra_emu_cpu::{Cpu, RvInstr, StepAction};
use caliptra_emu_periph::soc_reg::DebugManufService;
use caliptra_emu_periph::{
    CaliptraRootBus, CaliptraRootBusArgs, DownloadIdevidCsrCb, MailboxInternal, ReadyForFwCb,
    TbServicesCb, UploadUpdateFwCb,
};
use caliptra_hw_model::BusMmio;
use caliptra_hw_model_types::SecurityState;
use clap::Parser;
use rand::{Rng, SeedableRng};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::registers::InMemoryRegister;
mod gdb;
use crate::gdb::gdb_target::GdbTarget;
use gdb::gdb_state;
use tock_registers::register_bitfields;

use cli::{Args, ArgsIdevidAlgo};

/// Firmware Load Command Opcode
const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

/// The number of CPU clock cycles it takes to write the firmware to the mailbox.
const FW_WRITE_TICKS: u64 = 1000;

const EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES: u64 = 20_000_000; // 20 million cycles

/// CPU Main Loop (free_run no GDB)
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

/// CPU Main Loop (free_run no GDB)
fn glitched_run(
    mut cpu: Cpu<CaliptraRootBus>,
    trace_path: Option<PathBuf>,
    glitch_seed: Option<u64>,
) {
    let random_seed: u64 = glitch_seed.unwrap_or_else(rand::random);

    println!("Starting glitched run...");
    println!("Using seed: {random_seed:?}");

    let mut rng = rand::rngs::StdRng::seed_from_u64(random_seed);

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
        while let StepAction::Continue = cpu.step(Some(trace_fn)) {
            let skip = rng.gen_bool(1.0 / 100.0);

            if skip {
                cpu.skip_instr().expect("instruction to be skipped");
            }
        }
    } else {
        while let StepAction::Continue = cpu.step(None) {
            let skip = rng.gen_bool(1.0 / 100.0);

            if skip {
                cpu.skip_instr().expect("instruction to be skipped");
            }
        }
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
    let args = Args::parse();

    let mut mfg_pk_hash = match hex::decode(args.mfg_pk_hash) {
        Ok(mfg_pk_hash) => mfg_pk_hash,
        Err(_) => {
            eprintln!("Manufacturer public keys hash format is incorrect",);
            exit(-1);
        }
    };
    let mut owner_pk_hash = match hex::decode(args.owner_pk_hash) {
        Ok(owner_pk_hash) => owner_pk_hash,
        Err(_) => {
            eprintln!("Owner public key hash format is incorrect",);
            exit(-1);
        }
    };

    if !args.rom.exists() {
        eprintln!("ROM File {:?} does not exist", args.rom);
        exit(-1);
    }

    if (!mfg_pk_hash.is_empty() && mfg_pk_hash.len() != 48)
        || (!owner_pk_hash.is_empty() && owner_pk_hash.len() != 48)
    {
        eprintln!(
            "Incorrect mfg_pk_hash: {} and/or owner_pk_hash: {} length",
            mfg_pk_hash.len(),
            owner_pk_hash.len()
        );
        exit(-1);
    }

    change_dword_endianess(&mut mfg_pk_hash);
    change_dword_endianess(&mut owner_pk_hash);

    let rom = fs::read(args.rom)?;

    if rom.len() > CaliptraRootBus::ROM_SIZE {
        eprintln!(
            "ROM File Size must not exceed {} bytes",
            CaliptraRootBus::ROM_SIZE
        );
        exit(-1);
    }

    let mut current_fw_buf = Vec::new();
    if let Some(ref path) = args.firmware {
        if !path.exists() {
            eprintln!("Current firmware file {:?} does not exist", args.firmware);
            exit(-1);
        }

        current_fw_buf = fs::read(path)?;
    }
    let current_fw_buf = Rc::new(current_fw_buf);

    let mut update_fw_buf = Vec::new();
    if let Some(ref path) = args.update_firmware {
        if !path.exists() {
            eprintln!(
                "Update firmware file {:?} does not exist",
                args.update_firmware
            );
            exit(-1);
        }

        update_fw_buf = fs::read(path)?;
    }
    let update_fw_buf = Rc::new(update_fw_buf);

    let clock = Clock::new();

    let mut security_state = SecurityState::default();
    security_state.set_device_lifecycle(args.device_lifecycle.into());

    let logs_dir_clone = args.log_dir.clone();

    let download_idevid_csr_cb = DownloadIdevidCsrCb::new(
        move |mailbox: &mut MailboxInternal,
              cptra_dbg_manuf_service_reg: &mut InMemoryRegister<
            u32,
            DebugManufService::Register,
        >| {
            download_idev_id_csr(mailbox, &logs_dir_clone, cptra_dbg_manuf_service_reg);
        },
    );

    let bus_args = CaliptraRootBusArgs {
        rom,
        log_dir: args.log_dir.clone(),
        tb_services_cb: TbServicesCb::new(|val| match val {
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
        download_idevid_csr_cb,
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
        if args.req_idevid_csr {
            val |= GEN_IDEVID_CSR_FLAG;
        }
        if args.req_ldevid_cert {
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
        let algo = match args.idevid_key_id_algo {
            ArgsIdevidAlgo::Sha1 => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA1,
            ArgsIdevidAlgo::Sha256 => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA256,
            ArgsIdevidAlgo::Sha384 => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA384,
            ArgsIdevidAlgo::Fuse => IDevIdCertAttrFlags::KEY_ID_ALGO::FUSE,
        };

        let flags: InMemoryRegister<u32, IDevIdCertAttrFlags::Register> = InMemoryRegister::new(0);
        flags.write(algo);
        let mut cert = [0u32; 24];
        // DWORD 00 - Flags
        cert[0] = flags.get();
        // DWORD 01 - 05 - IDEVID Subject Key Identifier (all zeroes)
        cert[6] = 1; // UEID Type
                     // DWORD 07 - 10 - UEID / Manufacturer Serial Number
        cert[7] = args.ueid as u32;
        cert[8] = (args.ueid >> 32) as u32;
        cert[9] = (args.ueid >> 64) as u32;
        cert[10] = (args.ueid >> 96) as u32;

        soc_ifc.fuse_idevid_cert_attr().write(&cert);
    }

    // Populate cptra_wdt_cfg
    {
        soc_ifc
            .cptra_wdt_cfg()
            .at(0)
            .write(|_| args.wdt_timeout as u32);
        soc_ifc
            .cptra_wdt_cfg()
            .at(1)
            .write(|_| (args.wdt_timeout >> 32) as u32);
    }

    let cpu = Cpu::new(root_bus, clock);

    // Check if Optional GDB Port is passed
    if let Some(port) = args.gdb_port {
        // Create GDB Target Instance
        let mut gdb_target = GdbTarget::new(cpu);

        // Execute CPU through GDB State Machine
        gdb_state::wait_for_gdb_run(&mut gdb_target, port);
    } else {
        let instr_trace = args
            .trace_instr
            .then(|| args.log_dir.join("caliptra_instr_trace.txt"));

        // If no GDB Port is passed, Free or glitched Run
        if let Some(seed) = args.enable_glitching_simulation {
            glitched_run(cpu, instr_trace, seed);
        } else {
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
    path: &Path,
    cptra_dbg_manuf_service_reg: &mut InMemoryRegister<u32, DebugManufService::Register>,
) {
    let path = path.join("caliptra_ldevid_cert.der");

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

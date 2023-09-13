/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM Test FMC

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use caliptra_common::pcr::PCR_ID_STASH_MEASUREMENT;
use caliptra_common::{FuseLogEntry, FuseLogEntryId};
use caliptra_common::{PcrLogEntry, PcrLogEntryId};
use caliptra_drivers::pcr_log::MeasurementLogEntry;
use caliptra_drivers::{
    ColdResetEntry4::*, DataVault, Mailbox, PcrBank, PcrId, PersistentDataAccessor,
    MEASUREMENT_MAX_COUNT, PCR_LOG_MAX_COUNT,
};
use caliptra_registers::dv::DvReg;
use caliptra_registers::pv::PvReg;
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, FmcAliasCertTbs, LocalDevIdCertTbs};
use core::ptr;
use ureg::RealMmioMut;
use zerocopy::AsBytes;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("start.S"));

mod exception;
mod print;

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
Running Caliptra FMC ...
"#;

#[no_mangle]
pub extern "C" fn fmc_entry() -> ! {
    cprintln!("{}", BANNER);

    if cfg!(not(feature = "fake-fmc")) {
        let persistent_data = unsafe { PersistentDataAccessor::new() };
        assert!(persistent_data.get().fht.is_valid());
    }

    process_mailbox_commands();

    caliptra_drivers::ExitCtrl::exit(0)
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "FMC EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    loop {
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "FMC NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    loop {
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
#[allow(clippy::empty_loop)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("FMC Panic!!");
    loop {}
}

fn create_certs(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    //
    // Create LDEVID cert.
    //

    // Retrieve the public key and signature from the data vault.
    let data_vault = unsafe { DataVault::new(DvReg::new()) };
    let ldevid_pub_key = data_vault.ldev_dice_pub_key();
    let mut _pub_der: [u8; 97] = ldevid_pub_key.to_der();
    cprint_slice!("[fmc] LDEVID PUBLIC KEY DER", _pub_der);

    let sig = data_vault.ldev_dice_signature();

    let ecdsa_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };
    let mut tbs: [u8; core::mem::size_of::<LocalDevIdCertTbs>()] =
        [0u8; core::mem::size_of::<LocalDevIdCertTbs>()];
    copy_tbs(&mut tbs, true);

    let mut cert: [u8; 1024] = [0u8; 1024];
    let builder = Ecdsa384CertBuilder::new(
        &tbs[..core::mem::size_of::<LocalDevIdCertTbs>()],
        &ecdsa_sig,
    )
    .unwrap();
    let _cert_len = builder.build(&mut cert).unwrap();
    cprint_slice_ref!("[fmc] LDEVID cert", &cert[.._cert_len]);

    //
    // Create FMCALIAS cert.
    //

    // Retrieve the public key and signature from the data vault.
    let fmcalias_pub_key = data_vault.fmc_pub_key();
    let _pub_der: [u8; 97] = fmcalias_pub_key.to_der();
    cprint_slice!("[fmc] FMCALIAS PUBLIC KEY DER", _pub_der);

    let sig = data_vault.fmc_dice_signature();
    let ecdsa_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };

    let mut tbs: [u8; core::mem::size_of::<FmcAliasCertTbs>()] =
        [0u8; core::mem::size_of::<FmcAliasCertTbs>()];
    copy_tbs(&mut tbs, false);

    let mut cert: [u8; 1024] = [0u8; 1024];
    let builder =
        Ecdsa384CertBuilder::new(&tbs[..core::mem::size_of::<FmcAliasCertTbs>()], &ecdsa_sig)
            .unwrap();
    let _cert_len = builder.build(&mut cert).unwrap();
    cprint_slice_ref!("[fmc] FMCALIAS cert", &cert[.._cert_len]);

    mbox.status().write(|w| w.status(|w| w.cmd_complete()));
}

fn copy_tbs(tbs: &mut [u8], ldevid_tbs: bool) {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    // Copy the tbs from DCCM
    let src = if ldevid_tbs {
        &persistent_data.get().ldevid_tbs
    } else {
        &persistent_data.get().fmcalias_tbs
    };
    tbs.copy_from_slice(&src[..tbs.len()]);
}

fn get_pcr_entry(entry_index: usize) -> PcrLogEntry {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    persistent_data.get().pcr_log[entry_index]
}

fn get_measurement_entry(entry_index: usize) -> MeasurementLogEntry {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    persistent_data.get().measurement_log[entry_index]
}

fn process_mailbox_command(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let cmd = mbox.cmd().read();
    cprintln!("[fmc] Received command: 0x{:08X}", cmd);
    match cmd {
        0x1000_0000 => {
            read_pcr_log(mbox);
        }
        0x1000_0001 => {
            create_certs(mbox);
        }
        0x1000_0002 => {
            read_fuse_log(mbox);
        }
        0x1000_0003 => {
            read_fht(mbox);
        }
        0x1000_0004 => {
            trigger_update_reset(mbox);
        }
        0x1000_0005 => {
            read_datavault_coldresetentry4(mbox);
        }
        0x1000_0006 => {
            read_pcrs(mbox);
        }
        0x1000_0007 => {
            try_to_reset_pcrs(mbox);
        }
        0x1000_0008 => {
            read_rom_info(mbox);
        }
        0x1000_0009 => {
            read_pcr31(mbox);
        }
        0x1000_000A => {
            read_measurement_log(mbox);
        }

        _ => {}
    }
}

fn process_mailbox_commands() {
    let mut mbox = unsafe { caliptra_registers::mbox::MboxCsr::new() };
    let mbox = mbox.regs_mut();

    #[cfg(feature = "interactive_test_fmc")]
    loop {
        if mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            process_mailbox_command(&mbox);
        }
    }

    #[cfg(not(feature = "interactive_test_fmc"))]
    process_mailbox_command(&mbox);
}

fn read_pcr31(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    let pcr31: [u8; 48] = pcr_bank.read_pcr(PCR_ID_STASH_MEASUREMENT).into();
    send_to_mailbox(mbox, &pcr31, true);
}

fn read_datavault_coldresetentry4(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let data_vault = unsafe { DataVault::new(DvReg::new()) };
    send_to_mailbox(mbox, (FmcSvn as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.fmc_svn().as_bytes(), false);

    send_to_mailbox(mbox, (RomColdBootStatus as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.rom_cold_boot_status().as_bytes(), false);

    send_to_mailbox(mbox, (FmcEntryPoint as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.fmc_entry_point().as_bytes(), false);

    send_to_mailbox(mbox, (EccVendorPubKeyIndex as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.ecc_vendor_pk_index().as_bytes(), false);

    send_to_mailbox(mbox, (LmsVendorPubKeyIndex as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.lms_vendor_pk_index().as_bytes(), false);

    mbox.dlen()
        .write(|_| (core::mem::size_of::<u32>() * 10).try_into().unwrap());
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn trigger_update_reset(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    mbox.status().write(|w| w.status(|w| w.cmd_complete()));
    const STDOUT: *mut u32 = 0x3003_0624 as *mut u32;
    unsafe {
        ptr::write_volatile(STDOUT, 1_u32);
    }
}

fn read_pcr_log(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let mut pcr_entry_count = 0;
    loop {
        if pcr_entry_count == PCR_LOG_MAX_COUNT {
            break;
        }

        let pcr_entry = get_pcr_entry(pcr_entry_count);

        if PcrLogEntryId::from(pcr_entry.id) == PcrLogEntryId::Invalid {
            break;
        }

        pcr_entry_count += 1;
        send_to_mailbox(mbox, pcr_entry.as_bytes(), false);
    }

    mbox.dlen().write(|_| {
        (core::mem::size_of::<PcrLogEntry>() * pcr_entry_count)
            .try_into()
            .unwrap()
    });
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn read_measurement_log(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let mut measurement_entry_count = 0;
    loop {
        if measurement_entry_count == MEASUREMENT_MAX_COUNT {
            break;
        }

        let measurement_entry = get_measurement_entry(measurement_entry_count);

        if PcrLogEntryId::from(measurement_entry.pcr_entry.id) == PcrLogEntryId::Invalid {
            break;
        }

        measurement_entry_count += 1;
        send_to_mailbox(mbox, measurement_entry.as_bytes(), false);
    }

    mbox.dlen().write(|_| {
        (core::mem::size_of::<MeasurementLogEntry>() * measurement_entry_count)
            .try_into()
            .unwrap()
    });
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

fn read_pcrs(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    const PCR_COUNT: usize = 32;
    for i in 0..PCR_COUNT {
        let pcr = pcr_bank.read_pcr(PcrId::try_from(i as u8).unwrap());
        let mut pcr_bytes: [u32; 12] = pcr.try_into().unwrap();

        swap_word_bytes_inplace(&mut pcr_bytes);
        send_to_mailbox(mbox, pcr.as_bytes(), false);
    }

    mbox.dlen().write(|_| (48 * PCR_COUNT).try_into().unwrap());
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

// Returns a list of u8 values, 0 on success, 1 on failure:
//   - Whether PCR0 is locked
//   - Whether PCR1 is locked
//   - Whether PCR2 is unlocked
//   - Whether PCR31 is locked
fn try_to_reset_pcrs(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };

    let res0 = pcr_bank.erase_pcr(PcrId::PcrId0);
    let res1 = pcr_bank.erase_pcr(PcrId::PcrId1);
    let res2 = pcr_bank.erase_pcr(PcrId::PcrId2);
    let res31 = pcr_bank.erase_pcr(PcrId::PcrId31);

    let ret_vals: [u8; 4] = [
        if res0.is_err() { 0 } else { 1 },
        if res1.is_err() { 0 } else { 1 },
        if res2.is_ok() { 0 } else { 1 },
        if res31.is_err() { 0 } else { 1 },
    ];

    send_to_mailbox(mbox, &ret_vals, false);
    mbox.dlen().write(|_| ret_vals.len().try_into().unwrap());
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn read_rom_info(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    send_to_mailbox(
        mbox,
        persistent_data
            .get()
            .fht
            .rom_info_addr
            .get()
            .unwrap()
            .as_bytes(),
        true,
    );
}

fn read_fuse_log(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let mut fuse_entry_count = 0;
    loop {
        let fuse_entry = get_fuse_entry(fuse_entry_count);
        if FuseLogEntryId::from(fuse_entry.entry_id) == FuseLogEntryId::Invalid {
            break;
        }

        fuse_entry_count += 1;
        send_to_mailbox(mbox, fuse_entry.as_bytes(), false);
    }

    mbox.dlen().write(|_| {
        (core::mem::size_of::<FuseLogEntry>() * fuse_entry_count)
            .try_into()
            .unwrap()
    });
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn get_fuse_entry(entry_index: usize) -> FuseLogEntry {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    persistent_data.get().fuse_log[entry_index]
}

fn read_fht(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    send_to_mailbox(mbox, persistent_data.get().fht.as_bytes(), true);
}

fn send_to_mailbox(
    mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>,
    data: &[u8],
    update_mb_state: bool,
) {
    let data_len = data.len();
    let word_size = core::mem::size_of::<u32>();
    let remainder = data_len % word_size;
    let n = data_len - remainder;
    for idx in (0..n).step_by(word_size) {
        mbox.datain()
            .write(|_| u32::from_le_bytes(data[idx..idx + word_size].try_into().unwrap()));
    }

    if remainder > 0 {
        let mut last_word = data[n] as u32;
        for idx in 1..remainder {
            last_word |= (data[n + idx] as u32) << (idx << 3);
        }
        mbox.datain().write(|_| last_word);
    }

    if update_mb_state {
        mbox.dlen().write(|_| data_len as u32);
        mbox.status().write(|w| w.status(|w| w.data_ready()));
    }
}

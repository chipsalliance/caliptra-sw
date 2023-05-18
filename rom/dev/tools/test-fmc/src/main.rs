/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM Test FMC

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

extern "C" {
    static mut LDEVID_TBS_ORG: u8;
    static mut FMCALIAS_TBS_ORG: u8;
    static mut PCR_LOG_ORG: u8;
}

use caliptra_common::FirmwareHandoffTable;
use caliptra_common::{PcrLogEntry, PcrLogEntryId};
use caliptra_drivers::DataVault;
use caliptra_drivers::Mailbox;
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, FmcAliasCertTbs, LocalDevIdCertTbs};
use ureg::RealMmioMut;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

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

    extern "C" {
        static mut FHT_ORG: u8;
    }

    let slice = unsafe {
        let ptr = &mut FHT_ORG as *mut u8;
        cprintln!("[fmc] Loading FHT from 0x{:08X}", ptr as u32);
        core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<FirmwareHandoffTable>())
    };

    let fht = FirmwareHandoffTable::read_from(slice).unwrap();
    assert!(fht.is_valid());

    create_certs();

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

    // TODO: Signal non-fatal error to SOC

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

    // TODO: Signal non-fatal error to SOC

    loop {}
}

fn create_certs() {
    //
    // Create LDEVID cert.
    //

    // Retrieve the public key and signature from the data vault.
    let data_vault = DataVault::default();
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
}

fn copy_tbs(tbs: &mut [u8], ldevid_tbs: bool) {
    // Copy the tbs from DCCM
    let src = if ldevid_tbs {
        unsafe {
            let ptr = &mut LDEVID_TBS_ORG as *mut u8;
            core::slice::from_raw_parts_mut(ptr, tbs.len())
        }
    } else {
        unsafe {
            let ptr = &mut FMCALIAS_TBS_ORG as *mut u8;
            core::slice::from_raw_parts_mut(ptr, tbs.len())
        }
    };
    tbs.copy_from_slice(src);
}

fn get_pcr_entry(entry_index: usize) -> PcrLogEntry {
    // Copy the pcr log entry from DCCM
    let mut pcr_entry: [u8; core::mem::size_of::<PcrLogEntry>()] =
        [0u8; core::mem::size_of::<PcrLogEntry>()];

    let src = unsafe {
        let offset = core::mem::size_of::<PcrLogEntry>() * entry_index;
        let ptr = (&mut PCR_LOG_ORG as *mut u8).add(offset);
        core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<PcrLogEntry>())
    };

    pcr_entry.copy_from_slice(src);
    PcrLogEntry::read_from_prefix(pcr_entry.as_bytes()).unwrap()
}

fn process_mailbox_commands() {
    let mbox = caliptra_registers::mbox::RegisterBlock::mbox_csr();

    let cmd = mbox.cmd().read();
    cprintln!("[fmc] Received command: 0x{:08X}", cmd);
    match cmd {
        0x1000_0000 => {
            read_pcr_log(&mbox);
        }
        0x1000_0001 => {
            // TODO: Generate certs
        }
        _ => {
            // No-op
        }
    }
}

fn read_pcr_log(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let mut pcr_entry_count = 0;
    loop {
        let pcr_entry = get_pcr_entry(pcr_entry_count);
        if PcrLogEntryId::from(pcr_entry.id) == PcrLogEntryId::Invalid {
            break;
        }

        pcr_entry_count += 1;
        let pcr_entry_bytes = pcr_entry.as_bytes();
        let word_size = core::mem::size_of::<u32>();
        let remainder = pcr_entry_bytes.len() % word_size;
        let n = pcr_entry_bytes.len() - remainder;

        for idx in (0..n).step_by(word_size) {
            mbox.datain().write(|_| {
                u32::from_le_bytes(pcr_entry_bytes[idx..idx + word_size].try_into().unwrap())
            });
        }

        if remainder > 0 {
            let mut last_word = pcr_entry_bytes[n] as u32;
            for idx in 1..remainder {
                last_word |= (pcr_entry_bytes[n + idx] as u32) << (idx << 3);
            }
            mbox.datain().write(|_| last_word);
        }
    }

    mbox.dlen().write(|_| {
        (core::mem::size_of::<PcrLogEntry>() * pcr_entry_count)
            .try_into()
            .unwrap()
    });
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

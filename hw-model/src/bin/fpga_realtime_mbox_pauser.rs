// Licensed under the Apache-2.0 license

use caliptra_hw_model::{mmio::Rv32GenMmio, HwModel, InitParams};
use nix::sys::signal;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use caliptra_api::soc_mgr::SocManager;
use caliptra_registers::soc_ifc;

fn gen_image_hi() -> Vec<u8> {
    let rv32_gen = Rv32GenMmio::new();
    let soc_ifc =
        unsafe { soc_ifc::RegisterBlock::new_with_mmio(0x3003_0000 as *mut u32, &rv32_gen) };
    soc_ifc
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| b'h'.into());
    soc_ifc
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| b'i'.into());
    soc_ifc
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| 0x100 | u32::from(b'i'));
    soc_ifc.cptra_generic_output_wires().at(0).write(|_| 0xff);
    rv32_gen.into_inner().empty_loop().build()
}

// Atomic flag to indicate if SIGBUS was received
static SIGBUS_RECEIVED: AtomicBool = AtomicBool::new(false);

// Signal handler function
extern "C" fn handle_sigbus(_: i32) {
    SIGBUS_RECEIVED.store(true, Ordering::SeqCst);
}

fn main() {
    println!("Setup signal handler...");
    // Define the signal action
    let sig_action = SigAction::new(
        SigHandler::Handler(handle_sigbus),
        SaFlags::empty(),
        SigSet::empty(),
    );

    // Set the signal handler for SIGBUS
    unsafe {
        signal::sigaction(signal::Signal::SIGBUS, &sig_action)
            .expect("Failed to set SIGBUS handler");
    }

    // Spawn a thread that causes a SIGBUS error
    thread::spawn(|| {
        // Sleep for a short duration to ensure the main thread is ready
        thread::sleep(Duration::from_secs(2));

        let mut model = caliptra_hw_model::new_unbooted(InitParams {
            rom: &gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        model.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        // Set up the PAUSER as valid for the mailbox (using index 0)
        model
            .soc_ifc()
            .cptra_mbox_valid_pauser()
            .at(0)
            .write(|_| 0x1);
        model
            .soc_ifc()
            .cptra_mbox_pauser_lock()
            .at(0)
            .write(|w| w.lock(true));

        // Set the PAUSER to something invalid
        model.set_apb_pauser(0x2);

        // The accesses below trigger sigbus
        assert!(!model.soc_mbox().lock().read().lock());
        // Should continue to read 0 because the reads are being blocked by valid PAUSER
        assert!(!model.soc_mbox().lock().read().lock());

        // Set the PAUSER back to valid
        model.set_apb_pauser(0x1);

        // Should read 0 the first time still for lock available
        assert!(!model.soc_mbox().lock().read().lock());
        // Should read 1 now for lock taken
        assert!(model.soc_mbox().lock().read().lock());

        model.soc_mbox().cmd().write(|_| 4242);

        assert_eq!(model.soc_mbox().cmd().read(), 4242);
        // Continue with the rest of your program
        println!("Continuing execution...");
    });

    // Simulate some work in the main thread
    loop {
        if SIGBUS_RECEIVED.load(Ordering::SeqCst) {
            println!("Received SIGBUS signal!");
            // Handle the SIGBUS signal here
            exit(42);
        }
        println!("Working...");
        thread::sleep(Duration::from_secs(1));
    }
}

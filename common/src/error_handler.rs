// Licensed under the Apache-2.0 license
use caliptra_drivers::{
    cprintln, report_fw_error_fatal, report_fw_error_non_fatal, Ecc384, Hmac, KeyVault, Mailbox,
    Sha256, Sha2_512_384Acc, Sha384, SocIfc,
};

#[allow(clippy::empty_loop)]
pub fn handle_fatal_error(code: u32) -> ! {
    cprintln!("Fatal Error: 0x{:08X}", code);
    report_fw_error_fatal(code);
    // Populate the non-fatal error code too; if there was a
    // non-fatal error stored here before we don't want somebody
    // mistakenly thinking that was the reason for their mailbox
    // command failure.
    report_fw_error_non_fatal(code);

    unsafe {
        // Zeroize the crypto blocks.
        Ecc384::zeroize();
        Hmac::zeroize();
        Sha256::zeroize();
        Sha384::zeroize();
        Sha2_512_384Acc::zeroize();

        // Zeroize the key vault.
        KeyVault::zeroize();

        // Lock the SHA Accelerator.
        Sha2_512_384Acc::lock();

        // Stop the watchdog timer.
        // Note: This is an idempotent operation.
        SocIfc::stop_wdt1();
    }

    loop {
        // SoC firmware might be stuck waiting for Caliptra to finish
        // executing this pending mailbox transaction. Notify them that
        // we've failed.
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

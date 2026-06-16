// Licensed under the Apache-2.0 license
#[cfg(feature = "rom")]
use caliptra_cfi_lib::{cfi_assert_bool, cfi_launder};
use caliptra_drivers::{
    cprintln, report_fw_error_fatal, report_fw_error_non_fatal, Aes, Ecc384, Hmac, KeyVault,
    Mailbox, MlKem1024, Mldsa87, Sha256, Sha2_512_384, Sha2_512_384Acc, Sha3, SocIfc,
};
#[cfg(feature = "rom")]
use caliptra_drivers::{Dma, DmaRecovery};
#[cfg(feature = "rom")]
use caliptra_registers::soc_ifc::SocIfcReg;

#[allow(clippy::empty_loop)]
pub fn handle_fatal_error(code: u32) -> ! {
    cprintln!("Fatal Error: 0x{:08X}", code);

    #[cfg(feature = "rom")]
    {
        let soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });
        let wait_for_device_reset = soc_ifc.wait_for_device_reset_before_fatal_error();
        if cfi_launder(wait_for_device_reset) {
            cfi_assert_bool(wait_for_device_reset);
            wait_for_device_reset_before_fatal_error(&soc_ifc);
        } else {
            cfi_assert_bool(!wait_for_device_reset);
        }
    }

    report_fw_error_fatal(code);
    // Populate the non-fatal error code too; if there was a
    // non-fatal error stored here before we don't want somebody
    // mistakenly thinking that was the reason for their mailbox
    // command failure.
    report_fw_error_non_fatal(code);

    unsafe {
        // Zeroize the crypto blocks.
        Aes::zeroize();
        Ecc384::zeroize();
        Hmac::zeroize();
        Mldsa87::zeroize_no_wait();
        MlKem1024::zeroize_no_wait();
        Sha256::zeroize();
        Sha2_512_384::zeroize();
        Sha2_512_384Acc::zeroize();
        Sha3::zeroize();

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

#[cfg(feature = "rom")]
/// Wait for the recovery interface to request a device reset before reporting a fatal error.
///
/// This is only called when SS_STRAP_GENERIC[3][1] is set in subsystem mode. Stop WDT1 before
/// polling because the wait is intentionally controlled by the recovery initiator, then poll
/// DEVICE_RESET.RESET_CTRL until it reaches 0x1 (Reset Device).
fn wait_for_device_reset_before_fatal_error(soc_ifc: &SocIfc) {
    unsafe {
        SocIfc::stop_wdt1();
    }

    let dma = Dma::default();
    let dma_recovery = DmaRecovery::new(
        soc_ifc.recovery_interface_base_addr().into(),
        soc_ifc.caliptra_base_axi_addr().into(),
        soc_ifc.mci_base_addr().into(),
        &dma,
    );
    let _ = dma_recovery.wait_for_device_reset();
}

/*++
Licensed under the Apache-2.0 license.

File Name:

    axi_bypass.rs

Abstract:

    File contains test cases for the AXI bypass recovery flow.
    Note: This test is triggered from `caliptra-mcu-sw`.

--*/

#![no_std]
#![no_main]

use core::mem::ManuallyDrop;

use caliptra_drivers::{cprintln, AxiAddr, Dma, DmaRecovery, Mailbox, MailboxRecvTxn, SocIfc};
use caliptra_registers::{mbox::MboxCsr, sha512_acc::Sha512AccCsr, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

use zerocopy::FromBytes;

const SOC_MANIFEST_INDEX: u32 = 1;
const RECOVERY_STATUS_SUCCESSFUL: u32 = 0x3;

test_suite! {
    test_axi_bypass,
}

fn test_axi_bypass() {
    let soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });
    let dma = Dma::default();
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    let caliptra_base = AxiAddr::from(soc_ifc.caliptra_base_axi_addr());
    let recovery_base = AxiAddr::from(soc_ifc.recovery_interface_base_addr());
    let mci_base = soc_ifc.mci_base_addr();

    let dma_recovery =
        DmaRecovery::new(recovery_base, caliptra_base, AxiAddr::from(mci_base), &dma);
    cprintln!("Signaling Recovery status!");
    dma_recovery
        .set_device_status(DmaRecovery::DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE)
        .unwrap();
    cprintln!("Signaled Recovery status!");

    // Need to grab a lock of the Mailbox SRAM for the DMA engine.
    let txn: ManuallyDrop<MailboxRecvTxn<'_>> = ManuallyDrop::new(mbox.recovery_recv_txn());
    let recovery_bytes = dma_recovery
        .download_image_to_mbox(0)
        .unwrap();
    cprintln!("Got length: {}", recovery_bytes);

    let mbox_contents = txn.raw_mailbox_contents();

    cprintln!("Checking contents");
    let recovery_bytes = usize::try_from(recovery_bytes).unwrap();
    for word in mbox_contents[..recovery_bytes].chunks(4) {
        let word = u32::read_from_bytes(word).unwrap();
        if word != 0 {
            cprintln!("Saw word: 0x{:x}", word);
            assert_eq!(word, 0xFEEDCAFE);
        }
    }
    dma_recovery
        .set_recovery_status(DmaRecovery::RECOVERY_STATUS_SUCCESSFUL, 0)
        .unwrap();
}

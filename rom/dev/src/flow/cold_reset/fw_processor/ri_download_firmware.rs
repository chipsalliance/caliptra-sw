/*++

Licensed under the Apache-2.0 license.

File Name:

    ri_download_firmware.rs

Abstract:

    File contains RI_DOWNLOAD_FIRMWARE mailbox command.

--*/

use caliptra_common::RomBootStatus::FwProcessorDownloadImageComplete;
use caliptra_drivers::{
    cprintln, report_boot_status, CaliptraResult, Dma, Mailbox, MailboxRecvTxn, SocIfc,
};
use core::mem::ManuallyDrop;

use super::FirmwareProcessor;

pub struct RiDownloadFirmwareCmd;
impl RiDownloadFirmwareCmd {
    #[inline(always)]
    pub(crate) fn execute<'a>(
        mbox: &'a mut Mailbox,
        dma: &mut Dma,
        soc_ifc: &mut SocIfc,
        subsystem_mode: bool,
    ) -> CaliptraResult<(ManuallyDrop<MailboxRecvTxn<'a>>, u32)> {
        // Create a transaction to facilitate the download of the firmware image
        // from the recovery interface. This dummy transaction is necessary to
        // obtain and subsequently release the lock required to gain exclusive
        // access to the mailbox sram by the DMA engine, enabling it to write the
        // firmware image into the mailbox sram.
        let txn = ManuallyDrop::new(mbox.recovery_recv_txn());

        // Download the firmware image from the recovery interface.
        let image_size_bytes = if subsystem_mode {
            cprintln!("[fwproc] Downloading image from RRI to MCU SRAM");
            FirmwareProcessor::retrieve_image_from_recovery_interface_to_mcu(dma, soc_ifc)?
        } else {
            cprintln!("[fwproc] Downloading image from RRI to MBOX SRAM");
            FirmwareProcessor::retrieve_image_from_recovery_interface(dma, soc_ifc)?
        };
        cprintln!(
            "[fwproc] Received image from the Recovery Interface of size {} bytes",
            image_size_bytes
        );
        report_boot_status(FwProcessorDownloadImageComplete.into());
        Ok((txn, image_size_bytes))
    }
}

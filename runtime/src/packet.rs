/*++

Licensed under the Apache-2.0 license.

File Name:

    packet.rs

Abstract:

    File contains an API that reads commands and writes responses to the mailbox.

--*/

use caliptra_drivers::CaliptraResult;

use caliptra_common::mailbox_api::MailboxReqHeader;
use caliptra_drivers::CaliptraError;
use zerocopy::FromBytes;

#[derive(Debug)]
pub struct Packet {
    pub cmd: u32,
    // Using raw pointer to avoid lifetime issues
    payload_ptr: *const u8,
    payload_len: usize,
}

impl Packet {
    /// Retrieves the data in the mailbox and converts it into a Packet
    pub fn get_from_mbox(drivers: &mut crate::Drivers) -> CaliptraResult<Self> {
        let mbox = &mut drivers.mbox;
        let cmd = mbox.cmd();
        let dlen = mbox.dlen() as usize;

        // Get reference to raw mailbox contents
        let raw_data = mbox.raw_mailbox_contents();

        // Create the packet with raw pointers to the mailbox data
        let packet = Packet {
            cmd: cmd.into(),
            payload_ptr: raw_data.as_ptr(),
            payload_len: dlen,
        };

        // Verify incoming checksum
        // Make sure enough data was sent to even have a checksum
        if packet.payload().len() < core::mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        // Assumes chksum is always offset 0
        let req_hdr: &MailboxReqHeader = MailboxReqHeader::ref_from_bytes(
            &packet.payload()[..core::mem::size_of::<MailboxReqHeader>()],
        )
        .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        if !caliptra_common::checksum::verify_checksum(
            req_hdr.chksum,
            packet.cmd,
            &packet.payload()[core::mem::size_of_val(&req_hdr.chksum)..],
        ) {
            return Err(CaliptraError::RUNTIME_INVALID_CHECKSUM);
        }

        Ok(packet)
    }

    /// Returns the byte representation of the packet's payload
    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        Ok(self.payload())
    }

    /// Get a reference to the payload data
    pub fn payload(&self) -> &[u8] {
        unsafe {
            // Safety: This is safe because:
            // 1. None of the mailbox request handlers use the mailbox in a way that
            //    modifies the mailbox sram content before sending back a reply.
            core::slice::from_raw_parts(self.payload_ptr, self.payload_len)
        }
    }
}

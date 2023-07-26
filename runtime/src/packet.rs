// Licensed under the Apache-2.0 license

// License by Apache-2.0
use caliptra_drivers::CaliptraResult;

use caliptra_drivers::CaliptraError;
use zerocopy::{AsBytes, LayoutVerified};
use crate::mailbox_api::{
    MailboxReqHeader,
    MailboxRespHeader,
    MailboxResp,
};

#[derive(Debug, Clone)]
pub struct Packet {
    pub cmd: u32,
    pub payload: [u32; MAX_PAYLOAD_SIZE],
    pub len: usize,   // Length in bytes
}

const MAX_PAYLOAD_SIZE: usize = 1024;   // in dwords

impl Default for Packet {
    fn default() -> Self {
        Self {
            cmd: 0,
            payload: [0u32; MAX_PAYLOAD_SIZE],
            len: 0,
        }
    }
}

impl Packet {
    pub fn copy_from_mbox(drivers: &mut crate::Drivers) -> CaliptraResult<Self> {
        let mbox = &mut drivers.mbox;
        let cmd = mbox.cmd();
        let dlen_words = mbox.dlen_words() as usize;

        if dlen_words > MAX_PAYLOAD_SIZE {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        let mut packet = Packet {
            cmd,
            len: mbox.dlen() as usize,
            ..Default::default()
        };

        mbox.copy_from_mbox(
            packet
                .payload
                .get_mut(..dlen_words)
                .ok_or(CaliptraError::RUNTIME_INTERNAL)?,
        );

        // Verify incoming checksum
        // Make sure enough data was sent to even have a checksum
        if packet.len < core::mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)
        }

        // Assumes chksum is always offset 0
        let payload_bytes = packet.as_bytes()?;
        let req_hdr: &MailboxReqHeader =
            LayoutVerified::<&[u8], MailboxReqHeader>::new(&payload_bytes[..core::mem::size_of::<MailboxReqHeader>()])
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?
            .into_ref();

        if !caliptra_common::checksum::verify_checksum(
            req_hdr.chksum,
            packet.cmd,
            &payload_bytes[core::mem::size_of_val(&req_hdr.chksum)..],
        ) {
            return Err(CaliptraError::RUNTIME_INVALID_CHECKSUM);
        }

        Ok(packet)
    }

    pub fn copy_to_mbox(
            drivers: &mut crate::Drivers,
            resp: &mut MailboxResp,
            resp_size_ovrd: Option<usize>
    ) -> CaliptraResult<()> {
        let mbox = &mut drivers.mbox;

        // Generate response checksum
        resp.populate_chksum(resp_size_ovrd)?;

        // Send the payload
        // Use a slice if needed
        let resp_bytes = match resp_size_ovrd {
            Some(size) => &resp.as_bytes()[..size],
            None => resp.as_bytes(),
        };

        mbox.write_response(resp_bytes)
    }

    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        self.payload
            .as_bytes()
            .get(..self.len)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
    }

    pub fn as_bytes_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        self.payload
            .as_bytes_mut()
            .get_mut(..self.len)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
    }
}

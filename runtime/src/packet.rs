// Licensed under the Apache-2.0 license

// License by Apache-2.0
use caliptra_drivers::CaliptraResult;

use caliptra_drivers::CaliptraError;
use zerocopy::AsBytes;
use crate::mailbox_api::{
    cast_bytes_to_struct,
    cast_bytes_to_struct_mut,
    MailboxReqCommon,
    MailboxRespCommon,
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
        if packet.len < core::mem::size_of::<MailboxReqCommon>() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)
        }

        // Assumes chksum is always offset 0
        let payload_bytes = packet.as_bytes()?;
        let req_common: &MailboxReqCommon = cast_bytes_to_struct(payload_bytes)?;
        if !caliptra_common::checksum::verify_checksum(
            req_common.chksum,
            packet.cmd,
            &payload_bytes[core::mem::size_of_val(&req_common.chksum)..],
        ) {
            return Err(CaliptraError::RUNTIME_INVALID_CHECKSUM);
        }

        Ok(packet)
    }

    pub fn copy_to_mbox(mut self, drivers: &mut crate::Drivers) -> CaliptraResult<()> {
        let mbox = &mut drivers.mbox;

        if self.len > (MAX_PAYLOAD_SIZE * 4) {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        // We always send back at least the common args
        if self.len == 0 {
            self.len = core::mem::size_of::<MailboxRespCommon>()
        }

        // Generate response checksum
        // Assumes chksum is always offset 0
        // TODO: Having trouble getting the size/span of chksum without an actual instance
        //       of the struct, need to remove this "4" constant
        // No cmd associated a response, use 0 for checksum calc
        let checksum = caliptra_common::checksum::calc_checksum(0, &self.as_bytes()?[4..]);

        // Get the common fields as mutable and set checksum
        let resp_common: &mut MailboxRespCommon = cast_bytes_to_struct_mut(self.as_bytes_mut()?)?;
        resp_common.chksum = checksum;

        // Send the payload
        mbox.write_response(self.as_bytes()?)
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

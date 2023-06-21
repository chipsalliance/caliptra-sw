// Licensed under the Apache-2.0 license

// License by Apache-2.0
use caliptra_drivers::CaliptraResult;

use caliptra_drivers::CaliptraError;
use zerocopy::AsBytes;

#[derive(Debug, Clone)]
pub struct Packet {
    pub cmd: u32,
    pub payload: [u32; MAX_PAYLOAD_SIZE],
    pub len: usize,
}

const MAX_PAYLOAD_SIZE: usize = 1024;

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

        Ok(packet)
    }

    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        self.payload
            .as_bytes()
            .get(..self.len)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
    }
}

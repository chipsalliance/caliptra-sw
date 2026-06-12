/*++

Licensed under the Apache-2.0 license.

File Name:

    packet.rs

Abstract:

    File contains an API that reads commands and writes responses to the mailbox.

--*/

use caliptra_common::cprintln;
use caliptra_common::mailbox_api::{MailboxReqHeader, MailboxResp};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

/// Reads the pending mailbox command payload into `buf`.
///
/// Performs bounds check, FIFO drain, header size check, and checksum
/// verification. `buf` must be sized to the caller's request type
/// (e.g. `req.as_mut_bytes()`). Marked `#[inline(never)]` so this function
/// compiles once regardless of how many command handlers call it.
#[inline(never)]
pub fn copy_from_mbox(drivers: &mut crate::Drivers, buf: &mut [u8]) -> CaliptraResult<()> {
    let mbox = &mut drivers.mbox;
    let cmd = u32::from(mbox.cmd());
    let dlen = mbox.dlen() as usize;
    let dlen_words = mbox.dlen_words() as usize;

    let max_words = buf.len().div_ceil(4);
    if dlen_words > max_words {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }

    cprintln!("[rt]cmd=0x{:x}, len={}", cmd, dlen);

    if dlen < core::mem::size_of::<MailboxReqHeader>() {
        return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
    }

    mbox.copy_from_mbox_bytes(buf, dlen_words);

    let clamped = dlen.min(buf.len());
    let payload_bytes = &buf[..clamped];
    let req_hdr: &MailboxReqHeader = MailboxReqHeader::ref_from_bytes(
        &payload_bytes[..core::mem::size_of::<MailboxReqHeader>()],
    )
    .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

    if !caliptra_common::checksum::verify_checksum(
        req_hdr.chksum,
        cmd,
        &payload_bytes[core::mem::size_of_val(&req_hdr.chksum)..],
    ) {
        return Err(CaliptraError::RUNTIME_INVALID_CHECKSUM);
    }

    Ok(())
}

/// Writes `resp` to the mailbox
///
/// # Arguments
///
/// * `drivers` - Drivers
/// * `resp` - Response from a mailbox command that is to be copied to mailbox
pub fn copy_to_mbox(drivers: &mut crate::Drivers, resp: &mut MailboxResp) -> CaliptraResult<()> {
    let mbox = &mut drivers.mbox;

    // Generate response checksum
    resp.populate_chksum()?;

    // Send the payload
    mbox.write_response(resp.as_bytes()?)
}

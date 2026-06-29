/*++

Licensed under the Apache-2.0 license.

File Name:

    packet.rs

Abstract:

    File contains an API that reads commands and writes responses to the mailbox.

--*/

use caliptra_common::mailbox_api::{populate_checksum, MailboxReqHeader, MailboxRespHeaderVarSize};
use caliptra_common::{checksum::response_buffer_checksum, cprintln};
use caliptra_dpe_response_buffer::ResponseBuffer;
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::{FromBytes, IntoBytes};

use crate::MboxResponseWriter;

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

/// Write a fixed-size response `resp` to MBOX SRAM.
/// Fills `resp[0..4]` with the Caliptra checksum
/// then calls `mbox.write_response` which sets dlen and copies bytes.
#[inline(never)]
pub fn copy_to_mbox(drivers: &mut crate::Drivers, resp: &mut [u8]) -> CaliptraResult<()> {
    if resp.len() < 4 {
        return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
    }
    populate_checksum(resp);
    drivers.mbox.write_response(resp)
}

/// Finalise a variable-length response written via `MboxResponseWriter`, including
/// writing the VarSize header and populating the checksum.
#[inline(never)]
pub fn finalize_mbox_buffer(
    mbox: &mut crate::Mailbox,
    buffer: &mut MboxResponseWriter,
    mut header: MailboxRespHeaderVarSize,
) -> CaliptraResult<()> {
    let total_len = size_of::<MailboxRespHeaderVarSize>() + (header.data_len as usize);
    buffer
        .write_at(0, header.as_mut_bytes())
        .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
    let checksum = response_buffer_checksum(buffer, size_of::<u32>()..total_len)
        .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
    buffer
        .write_at(0, &checksum.to_le_bytes())
        .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;

    mbox.flush_sram_to_datain(total_len)
}

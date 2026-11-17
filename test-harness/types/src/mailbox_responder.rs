// Licensed under the Apache-2.0 license

//! The commands understood by the `mailbox_responder` test ROM
//! (`hw-model/test-fw/mailbox_responder.rs`) and the data it replies with.
//!
//! The ROM and the host side tests in `caliptra-hw-model` both use these
//! definitions so that the protocol is defined in exactly one place.

/// Echo: the ROM consumes the request (at most [`ECHO_MAX_LEN`] bytes) and
/// responds with the command id, as a little-endian word, followed by the
/// request.
pub const MBOX_CMD_ECHO: u32 = 0x1000_0000;

/// The ROM ignores the request and responds with [`FIXED_RESPONSE_LEN`] bytes of
/// data: the little-endian bytes of [`FIXED_RESPONSE_WORDS`].
pub const MBOX_CMD_FIXED_RESPONSE: u32 = 0x1000_1000;

/// The ROM ignores the request and responds with data ready and a data length
/// of zero.
pub const MBOX_CMD_EMPTY_RESPONSE: u32 = 0x1000_2000;

/// The ROM ignores the request and completes successfully without response
/// data.
pub const MBOX_CMD_NODATA: u32 = 0x2000_0000;

/// The ROM stores the request as the response that [`MBOX_CMD_GET_RESPONSE`]
/// returns and completes successfully without response data.
pub const MBOX_CMD_SET_RESPONSE: u32 = 0x3000_0000;

/// The ROM prints the request on the UART as `|<request bytes in hex>|` and
/// responds with the data stored by the last [`MBOX_CMD_SET_RESPONSE`].
pub const MBOX_CMD_GET_RESPONSE: u32 = 0x3000_0001;

/// The ROM fails every command it does not know. This is the one the tests use
/// to get a failure response.
pub const MBOX_CMD_FAIL: u32 = 0x4000_0000;

/// The ROM unlocks the SHA512 accelerator (by writing 1 to its lock register)
/// and completes successfully without response data.
pub const MBOX_CMD_UNLOCK_SHA512_ACC: u32 = 0x5000_0000;

/// The largest request in bytes that [`MBOX_CMD_ECHO`] can handle. The ROM
/// buffers it in `[u32; ECHO_MAX_LEN / 4]` and a larger request overflows it.
pub const ECHO_MAX_LEN: usize = 32;

/// The data words [`MBOX_CMD_FIXED_RESPONSE`] responds with. Only the first
/// [`FIXED_RESPONSE_LEN`] bytes of their little-endian representation are part
/// of the response.
pub const FIXED_RESPONSE_WORDS: [u32; 2] = [0x6745_2301, 0xefcd_ab89];

/// The length in bytes of the [`MBOX_CMD_FIXED_RESPONSE`] response.
pub const FIXED_RESPONSE_LEN: u32 = 7;

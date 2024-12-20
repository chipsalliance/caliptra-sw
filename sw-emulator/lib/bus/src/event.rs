// Licensed under the Apache-2.0 license.

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub src: Device,
    pub dest: Device,
    pub event: EventData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Device {
    CaliptraCore,
    MCU,
    BMC,
    External(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
pub enum EventData {
    WireRequest {
        name: &'static str,
    },
    WireValue {
        name: &'static str,
        value: u32,
    },
    RegisterRequest {
        name: &'static str,
    },
    RegisterValue {
        name: &'static str,
        value: u32,
    },
    MemoryRead {
        start_addr: u32,
        len: usize,
    },
    MemoryWrite {
        start_addr: u32,
        data: Vec<u8>,
    },
    MailboxCommand {
        command: u32,
        data: Vec<u8>,
    },
    MailboxResponse {
        response: u32,
        data: Vec<u8>,
    },
    I3CBusCommand {
        source_addr: u8,
        dest_addr: u8,
        descriptor: u64,
        data: Vec<u8>,
    },
    I3cBusResponse {
        source_addr: u8,
        dest_addr: u8,
        ibi: Option<u8>,
        descriptor: u64,
        data: Vec<u8>,
    },
}

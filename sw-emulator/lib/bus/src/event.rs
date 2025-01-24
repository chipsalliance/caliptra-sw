// Licensed under the Apache-2.0 license.

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub src: Device,
    pub dest: Device,
    pub event: EventData,
}

impl Event {
    pub fn new(src: Device, dest: Device, event: EventData) -> Self {
        Self { src, dest, event }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    MemoryRead {
        start_addr: u32,
        len: u32,
    },
    MemoryReadResponse {
        start_addr: u32,
        data: Vec<u8>,
    },
    MemoryWrite {
        start_addr: u32,
        data: Vec<u8>,
    },
    RecoveryBlockWrite {
        source_addr: u8,
        target_addr: u8,
        command_code: RecoveryCommandCode,
        payload: Vec<u8>,
    },
    RecoveryBlockReadRequest {
        source_addr: u8,
        target_addr: u8,
        command_code: RecoveryCommandCode,
    },
    RecoveryBlockReadResponse {
        source_addr: u8,
        target_addr: u8,
        command_code: RecoveryCommandCode,
        payload: Vec<u8>,
    },
    RecoveryImageAvailable {
        image_id: u8,
        image: Vec<u8>,
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RecoveryCommandCode {
    ProtCap,
    DeviceId,
    DeviceStatus,
    DeviceReset,
    RecoveryCtrl,
    RecoveryStatus,
    HwStatus,
    IndirectCtrl,
    IndirectStatus,
    IndirectData,
    Vendor,
    IndirectFifoCtrl,
    IndirectFifoStatus,
    IndirectFifoData,
}

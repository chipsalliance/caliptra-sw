// Licensed under the Apache-2.0 license

//! This is a driver for the Xilinx AXI I3C controller that is used in Xilinx
//! FPGAs for testing.
//!
//! Documentation for the underlying hardware is available at
//! https://docs.amd.com/r/en-US/pg439-axi-i3c/.

mod controller;

use std::sync::atomic::AtomicU32;

pub use controller::{Ccc, Command, Config, Controller, XI3c};
pub static STEP_STATUS: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XI3cError {
    /// Device is already started
    DeviceStarted,
    /// There was no data available
    NoData,
    /// Generic receive error
    RecvError,
    /// Generic transmit error
    SendError,
    /// Timeout error
    Timeout,
}

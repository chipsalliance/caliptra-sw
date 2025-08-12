// Licensed under the Apache-2.0 license

//! This is a driver for the Xilinx AXI I3C controller that is used in Xilinx
//! FPGAs for testing.
//!
//! Documentation for the underlying hardware is available at
//! https://docs.amd.com/r/en-US/pg439-axi-i3c/.

mod controller;

#[allow(unused)]
pub use controller::{Ccc, Command, Config, Controller, XI3c};

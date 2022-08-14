/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains exports for code useful for testing Bus traits.

--*/
mod fake_bus;
mod log;

pub use fake_bus::FakeBus;
pub use log::Log;

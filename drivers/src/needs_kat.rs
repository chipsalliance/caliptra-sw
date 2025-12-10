/*++

Licensed under the Apache-2.0 license.

File Name:

    needs_kat.rs

Abstract:

    File contains a driver wrapper that checks if a KAT has
    been run before returning the driver.

--*/

use crate::{report_fw_error_fatal, CaliptraError};

/// A wrapper around a driver that enforces KAT (Known Answer Test) execution
/// before allowing access to the underlying driver.
///
/// This wrapper ensures that cryptographic operations cannot be performed
/// without first running a KAT to verify the correctness of the hardware.
pub struct NeedsKat<T> {
    driver: T,
    kat_run: bool,
}

impl<T> NeedsKat<T> {
    /// Creates a new wrapper around a driver with KAT not yet run.
    ///
    /// # Arguments
    ///
    /// * `driver` - The driver instance to wrap
    pub const fn new(driver: T) -> Self {
        Self {
            driver,
            kat_run: false,
        }
    }

    /// Unwraps the driver if KAT has been run, otherwise triggers a fatal error.
    ///
    /// # Panics
    ///
    /// This function will call `report_fw_error_fatal` if KAT has not been run.
    ///
    /// # Returns
    ///
    /// A reference to the underlying driver if KAT has been successfully run.
    pub fn unwrap(&self) -> &T {
        if !self.kat_run {
            report_fw_error_fatal(CaliptraError::DRIVER_KAT_NOT_RUN.into());
        }
        &self.driver
    }

    /// Unwraps the driver mutably if KAT has been run, otherwise triggers a fatal error.
    ///
    /// # Panics
    ///
    /// This function will call `report_fw_error_fatal` if KAT has not been run.
    ///
    /// # Returns
    ///
    /// A mutable reference to the underlying driver if KAT has been successfully run.
    pub fn unwrap_mut(&mut self) -> &mut T {
        if !self.kat_run {
            report_fw_error_fatal(CaliptraError::DRIVER_KAT_NOT_RUN.into());
        }
        &mut self.driver
    }

    /// Provides unsafe access to the driver for running KAT tests.
    ///
    /// This method allows access to the driver before KAT has been run,
    /// specifically for the purpose of executing the KAT. The closure
    /// should return `Ok(())` if the KAT passes, which will mark the
    /// driver as ready for use.
    ///
    /// # Safety
    ///
    /// This method is marked unsafe because it bypasses the KAT check.
    /// The caller must ensure that the provided closure actually performs
    /// a proper KAT and verifies the results.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that takes a mutable reference to the driver
    ///         and returns a Result indicating KAT success or failure
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the KAT passes, marking the driver as ready.
    /// Returns the error from the closure if the KAT fails.
    pub unsafe fn run_kat<E, F>(&mut self, f: F) -> Result<(), E>
    where
        F: FnOnce(&mut T) -> Result<(), E>,
    {
        let result = f(&mut self.driver);
        if result.is_ok() {
            self.kat_run = true;
        }
        result
    }

    /// Returns whether the KAT has been run successfully.
    pub fn is_kat_run(&self) -> bool {
        self.kat_run
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDriver {
        value: u32,
    }

    impl DummyDriver {
        fn new() -> Self {
            Self { value: 0 }
        }

        fn set_value(&mut self, val: u32) {
            self.value = val;
        }

        fn get_value(&self) -> u32 {
            self.value
        }
    }

    #[test]
    fn test_kat_not_run() {
        let wrapper = NeedsKat::new(DummyDriver::new());
        assert!(!wrapper.is_kat_run());
    }

    #[test]
    fn test_kat_run_success() {
        let mut wrapper = NeedsKat::new(DummyDriver::new());

        unsafe {
            let result = wrapper.run_kat(|driver| {
                // Simulate KAT
                driver.set_value(42);
                if driver.get_value() == 42 {
                    Ok(())
                } else {
                    Err("KAT failed")
                }
            });

            assert!(result.is_ok());
        }

        assert!(wrapper.is_kat_run());
        assert_eq!(wrapper.unwrap().get_value(), 42);
    }

    #[test]
    fn test_kat_run_failure() {
        let mut wrapper = NeedsKat::new(DummyDriver::new());

        unsafe {
            let result: Result<(), &str> = wrapper.run_kat(|_driver| {
                // Simulate KAT failure
                Err("KAT verification failed")
            });

            assert!(result.is_err());
        }

        // KAT should not be marked as run on failure
        assert!(!wrapper.is_kat_run());
    }
}

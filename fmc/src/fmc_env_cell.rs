/*++

Licensed under the Apache-2.0 license.

File Name:

    env_cell.rs

Abstract:

    A mutable memory location that enforces Rust borrow rules.
    Tailored for single threaded environments.

--*/

use core::cell::UnsafeCell;

/// Environment Cell.
///
/// This cell is used to enforce rust borrowing rules while still allowing
/// mutable borrows that allows Rust to perform borrow checking.
#[derive(Debug)]
pub struct FmcEnvCell<T> {
    val: UnsafeCell<T>,
}

impl<T> FmcEnvCell<T> {
    /// Create a new `RentalCell` with `value`
    pub fn new(value: T) -> Self {
        Self {
            val: UnsafeCell::new(value),
        }
    }

    /// Helper function to use the Cell
    pub fn map<F, R>(&self, closure: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        closure(unsafe { &mut *self.val.get() })
    }
}

impl<T: Default> Default for FmcEnvCell<T> {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self::new(T::default())
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    emu_ctrl_regs.rs

Abstract:

    File contains helper type to hold register references

Note:

    This file has been copied from Tock OS repository
    https://github.com/tock/tock/blob/master/kernel/src/utilities/static_ref.rs

    Tock OS is licensed is dual licensed under MIT and Apache 2.0
    https://github.com/tock/tock

--*/

//! Wrapper type for safe pointers to static memory.

use core::ops::Deref;

/// A pointer to statically allocated mutable data such as memory mapped I/O
/// registers.
///
/// This is a simple wrapper around a raw pointer that encapsulates an unsafe
/// dereference in a safe manner. It serve the role of creating a `&'static T`
/// given a raw address and acts similarly to `extern` definitions, except
/// `StaticRef` is subject to module and crate boundaries, while `extern`
/// definitions can be imported anywhere.
#[derive(Debug)]
pub struct StaticRef<T> {
    ptr: *const T,
}

impl<T> StaticRef<T> {
    /// Create a new `StaticRef` from a raw pointer
    ///
    /// ## Safety
    ///
    /// Callers must pass in a reference to statically allocated memory which
    /// does not overlap with other values.
    pub const unsafe fn new(ptr: *const T) -> StaticRef<T> {
        StaticRef { ptr }
    }
}

impl<T> Clone for StaticRef<T> {
    fn clone(&self) -> Self {
        StaticRef { ptr: self.ptr }
    }
}

impl<T> Copy for StaticRef<T> {}

impl<T> Deref for StaticRef<T> {
    type Target = T;
    fn deref(&self) -> &'static T {
        unsafe { &*self.ptr }
    }
}

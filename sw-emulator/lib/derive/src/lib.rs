/*++

Licensed under the Apache-2.0 license.

File Name:

    token_iter.rs

Abstract:

    Contains derive procedural macros used in caliptra-emulator.

--*/
mod bus;
mod util;

#[cfg(not(test))]
use proc_macro::TokenStream;
#[cfg(test)]
use proc_macro2::TokenStream;

#[proc_macro_derive(Bus, attributes(peripheral, register))]
pub fn derive_bus(input: TokenStream) -> TokenStream {
    crate::bus::derive_bus(input)
}

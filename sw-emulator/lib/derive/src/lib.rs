/*++

Licensed under the Apache-2.0 license.

File Name:

    token_iter.rs

Abstract:

    Contains derive procedural macros used in caliptra-emulator.

--*/
mod bus;
mod util;

use proc_macro::TokenStream;

#[proc_macro_derive(
    Bus,
    attributes(
        peripheral,
        poll_fn,
        warm_reset_fn,
        update_reset_fn,
        register,
        register_array
    )
)]
pub fn derive_bus(input: TokenStream) -> TokenStream {
    crate::bus::derive_bus(input.into()).into()
}
